import socket
import urllib.request
from core.utils import OutputFormatter
from config.settings import Settings


class PassiveScanner:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []

    def _fetch(self, url, timeout=8):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": Settings.USER_AGENTS[0]}
            )
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", "ignore")
        except Exception:
            return None

    def passive_dns(self):
        self.logger.section("Passive DNS Resolution")
        try:
            ip  = socket.gethostbyname(self.target)
            self.logger.stat("A record", ip)
            try:
                ptr = socket.gethostbyaddr(ip)
                self.logger.stat("PTR record", ptr[0])
                self.findings.append(OutputFormatter.finding(
                    "passive", "INFO", "DNS Resolution",
                    f"{self.target} → {ip} → {ptr[0]}",
                ))
            except Exception:
                self.findings.append(OutputFormatter.finding(
                    "passive", "INFO", "DNS Resolution",
                    f"{self.target} → {ip} (no PTR record)",
                ))
        except Exception as e:
            self.logger.debug(f"Passive DNS: {e}")

    def banner_grab(self):
        self.logger.section("Passive Banner Grab (HTTP/HTTPS)")
        for port in [80, 443, 8080, 8443]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(Settings.CONNECT_TIMEOUT)
                if s.connect_ex((self.target, port)) != 0:
                    s.close()
                    continue
                s.send(b"HEAD / HTTP/1.0\r\nHost: " + self.target.encode() + b"\r\n\r\n")
                banner = s.recv(512).decode("utf-8", "ignore")
                s.close()
                if not banner:
                    continue
                server = ""
                for line in banner.splitlines():
                    if line.lower().startswith("server:"):
                        server = line.split(":", 1)[1].strip()
                if server:
                    self.logger.success(f"Port {port} — Server: {server}")
                    for sig, cve in Settings.CVE_SIGNATURES.items():
                        if sig.lower() in server.lower():
                            self.logger.finding("high", f"Vulnerable banner on port {port}: {cve}")
                            self.findings.append(OutputFormatter.finding(
                                "passive", "HIGH",
                                f"Vulnerable Banner on Port {port}",
                                cve, evidence=server,
                                recommendation="Update the identified software.",
                            ))
            except Exception:
                pass

    def run(self):
        self.logger.section("Passive Scan")
        self.passive_dns()
        self.banner_grab()
