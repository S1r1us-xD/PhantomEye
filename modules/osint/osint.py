import socket
import subprocess
import re
import json
import urllib.request
from core.utils import OutputFormatter
from config.settings import Settings
from config.wordlists import Wordlists


class OSINTScanner:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []

    def _fetch(self, url, headers=None, timeout=8):
        try:
            req = urllib.request.Request(
                url,
                headers={**(headers or {}), "User-Agent": Settings.USER_AGENTS[0]},
            )
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", "ignore")
        except Exception:
            return None

    def whois(self):
        self.logger.section("WHOIS Lookup")
        try:
            r = subprocess.run(
                ["whois", self.target],
                capture_output=True, text=True, timeout=20,
            )
            out = r.stdout[:3000]
            fields = {}
            for key in [
                "Registrar", "Creation Date", "Expiry Date",
                "Updated Date", "Name Server", "Status",
                "Country", "Org", "Registrant",
            ]:
                m = re.search(rf"{key}[:\s]+(.+)", out, re.IGNORECASE)
                if m:
                    val = m.group(1).strip()
                    fields[key] = val
                    self.logger.stat(key, val[:80])

            self.findings.append(OutputFormatter.finding(
                "osint", "INFO", "WHOIS Data",
                f"WHOIS information for {self.target}",
                evidence=str(fields)[:400],
            ))
            return fields
        except FileNotFoundError:
            self.logger.warning("whois not installed")
        except Exception as e:
            self.logger.debug(f"WHOIS: {e}")
        return {}

    def geolocation(self):
        self.logger.section("IP Geolocation")
        try:
            ip   = socket.gethostbyname(self.target)
            data = self._fetch(
                f"http://ip-api.com/json/{ip}"
                f"?fields=status,country,regionName,city,isp,org,as,timezone,proxy,hosting"
            )
            if data:
                d = json.loads(data)
                if d.get("status") == "success":
                    for k in ["country", "regionName", "city", "isp", "org", "as", "timezone"]:
                        if d.get(k):
                            self.logger.stat(k, str(d[k]))
                    if d.get("proxy"):
                        self.logger.finding("medium", "Target IP is behind a proxy or VPN")
                    if d.get("hosting"):
                        self.logger.finding("info", "Target is a hosting/cloud IP")
                    self.findings.append(OutputFormatter.finding(
                        "osint", "INFO", "IP Geolocation",
                        f"Geolocation data for {ip}",
                        evidence=str(d)[:300],
                    ))
                    return d
        except Exception as e:
            self.logger.debug(f"Geolocation: {e}")
        return {}

    def shodan_internetdb(self):
        self.logger.section("Shodan InternetDB Lookup")
        try:
            ip   = socket.gethostbyname(self.target)
            data = self._fetch(f"https://internetdb.shodan.io/{ip}")
            if data:
                d         = json.loads(data)
                ports     = d.get("ports", [])
                vulns     = d.get("vulns", [])
                hostnames = d.get("hostnames", [])
                cpes      = d.get("cpes", [])

                if ports:
                    self.logger.stat("Open ports",  ", ".join(str(p) for p in ports))
                if hostnames:
                    self.logger.stat("Hostnames",   ", ".join(hostnames[:5]))
                if cpes:
                    self.logger.stat("CPEs",        ", ".join(cpes[:5]))

                for cve in vulns:
                    self.logger.finding("high", f"Shodan CVE: {cve}")
                    self.findings.append(OutputFormatter.finding(
                        "osint", "HIGH",
                        f"Shodan CVE: {cve}",
                        f"CVE {cve} is associated with this IP per Shodan InternetDB.",
                        recommendation="Patch the identified vulnerability.",
                    ))

                self.findings.append(OutputFormatter.finding(
                    "osint", "INFO", "Shodan InternetDB",
                    f"Shodan data for {ip}",
                    evidence=data[:400],
                ))
                return d
        except Exception as e:
            self.logger.debug(f"Shodan InternetDB: {e}")
        return {}

    def certificate_transparency(self):
        self.logger.section("Certificate Transparency Logs (crt.sh)")
        subs = set()
        try:
            data = self._fetch(f"https://crt.sh/?q=%25.{self.target}&output=json")
            if data:
                entries = json.loads(data)
                for e in entries:
                    for cn in [e.get("common_name", "")] + e.get("name_value", "").split("\n"):
                        cn = cn.strip().lstrip("*.")
                        if cn.endswith(self.target) and cn != self.target:
                            subs.add(cn)

                for sub in sorted(subs)[:30]:
                    self.logger.success(f"CT subdomain: {sub}")

                if subs:
                    self.findings.append(OutputFormatter.finding(
                        "osint", "INFO", "Subdomains via CT Logs",
                        f"{len(subs)} subdomain(s) discovered via certificate transparency logs",
                        evidence="\n".join(sorted(subs)[:30]),
                    ))
        except Exception as e:
            self.logger.debug(f"CT logs: {e}")
        return list(subs)

    def email_harvest(self):
        self.logger.section("Passive Email Harvesting")
        emails = set()
        try:
            data = self._fetch(f"https://crt.sh/?q=%25@{self.target}&output=json")
            if data:
                for e in json.loads(data)[:20]:
                    cn = e.get("common_name", "")
                    if "@" in cn:
                        emails.add(cn)
        except Exception:
            pass

        for em in list(emails)[:20]:
            self.logger.success(f"Email found: {em}")

        if emails:
            self.findings.append(OutputFormatter.finding(
                "osint", "MEDIUM",
                "Email Addresses Discovered",
                f"{len(emails)} email address(es) associated with {self.target}",
                evidence="\n".join(list(emails)[:20]),
                recommendation="Monitor exposed emails for credential stuffing exposure.",
            ))
        else:
            self.logger.info("No email addresses found via passive sources")
        return list(emails)

    def dns_history(self):
        self.logger.section("DNS History & Past Records")
        data = self._fetch(f"https://api.hackertarget.com/hostsearch/?q={self.target}")
        if data and "," in data:
            self.logger.info("Historical host records:")
            for line in data.splitlines()[:20]:
                self.logger.success(f"  {line.strip()}")
            self.findings.append(OutputFormatter.finding(
                "osint", "INFO", "Historical DNS Records",
                f"Past DNS records for {self.target}",
                evidence=data[:500],
            ))

    def run(self):
        self.logger.section("OSINT Collection")
        self.geolocation()
        self.whois()
        self.shodan_internetdb()
        self.certificate_transparency()
        self.email_harvest()
        self.dns_history()
