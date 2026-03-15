import socket
import subprocess
from core.utils import OutputFormatter
from config.wordlists import Wordlists


class DNSScanner:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []

    def _dig(self, rtype):
        try:
            r = subprocess.run(
                ["dig", "+noall", "+answer", self.target, rtype],
                capture_output=True, text=True, timeout=10,
            )
            return r.stdout.strip()
        except FileNotFoundError:
            try:
                r = subprocess.run(
                    ["nslookup", f"-type={rtype}", self.target],
                    capture_output=True, text=True, timeout=10,
                )
                return r.stdout.strip()
            except Exception:
                return ""
        except Exception:
            return ""

    def enumerate_records(self):
        self.logger.section("DNS Record Enumeration")
        records = {}
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]:
            out = self._dig(rtype)
            if out:
                records[rtype] = out
                self.logger.success(f"{rtype:<8} {out[:120]}")
        self.findings.append(OutputFormatter.finding(
            "network/dns", "INFO", "DNS Records",
            f"DNS enumeration for {self.target}",
            evidence=str(records)[:500],
        ))
        return records

    def zone_transfer(self):
        self.logger.section("DNS Zone Transfer (AXFR)")
        try:
            ns_out = subprocess.run(
                ["dig", "+short", "NS", self.target],
                capture_output=True, text=True, timeout=10,
            ).stdout.strip()
            ns_list = [n.strip().rstrip(".") for n in ns_out.splitlines() if n.strip()]
            for ns in ns_list:
                r = subprocess.run(
                    ["dig", "AXFR", self.target, f"@{ns}"],
                    capture_output=True, text=True, timeout=15,
                )
                if "Transfer failed" not in r.stdout and len(r.stdout) > 100:
                    self.logger.finding(
                        "critical",
                        f"Zone transfer succeeded via {ns} — full zone data obtained!",
                    )
                    self.findings.append(OutputFormatter.finding(
                        "network/dns", "CRITICAL", "DNS Zone Transfer Allowed",
                        f"Full zone data obtained from nameserver {ns}.",
                        evidence=r.stdout[:500],
                        recommendation="Restrict AXFR to authorised secondary nameservers only.",
                    ))
                    return r.stdout[:500]
        except Exception:
            pass
        self.logger.info("Zone transfer not permitted (expected behaviour)")
        return None

    def subdomain_bruteforce(self):
        self.logger.section("Subdomain Brute-force")
        found = []
        for sub in Wordlists.SUBDOMAINS:
            fqdn = f"{sub}.{self.target}"
            try:
                ip = socket.gethostbyname(fqdn)
                self.logger.success(f"Subdomain: {fqdn}  →  {ip}")
                found.append({"subdomain": fqdn, "ip": ip})
            except Exception:
                pass
        if found:
            self.findings.append(OutputFormatter.finding(
                "network/dns", "INFO", "Subdomains Discovered",
                f"{len(found)} subdomain(s) resolved",
                evidence="\n".join(f"{x['subdomain']} → {x['ip']}" for x in found[:30]),
            ))
        return found

    def run(self):
        self.enumerate_records()
        self.zone_transfer()
        self.subdomain_bruteforce()
