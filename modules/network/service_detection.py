import socket
from config.settings import Settings
from config.signatures import Signatures
from core.utils import OutputFormatter


class ServiceDetection:
    def __init__(self, target, logger):
        self.target     = target
        self.logger     = logger
        self.findings   = []
        self.open_ports = []

    def _probe(self, port):
        probes = {
            21:   b"\r\n",
            22:   b"\r\n",
            25:   b"EHLO pe\r\n",
            80:   b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\nConnection: close\r\n\r\n",
            110:  b"USER test\r\n",
            143:  b"a1 CAPABILITY\r\n",
            443:  b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\nConnection: close\r\n\r\n",
            3306: b"\r\n",
            6379: b"INFO server\r\n",
            27017:b"\x3f\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00",
        }
        return probes.get(port, b"\r\n")

    def detect_port(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(Settings.DEFAULT_TIMEOUT)
            s.connect((self.target, port))
            s.send(self._probe(port))
            banner = s.recv(512).decode("utf-8", "ignore").strip()
            s.close()
            return port, banner
        except Exception:
            return port, ""

    def run(self):
        self.logger.section("Service Version Detection")
        if not self.open_ports:
            self.logger.info("No open ports registered — skipping service detection")
            return

        results = []
        for port in self.open_ports:
            _, banner = self.detect_port(port)
            if banner:
                svc = self._identify(port, banner)
                results.append((port, svc, banner[:80]))
                self._check_cves(port, svc, banner)

        if results:
            self.logger.table(
                ["Port", "Service", "Banner"],
                [(p, s, b) for p, s, b in results],
            )

    def _identify(self, port, banner):
        bl = banner.lower()
        for kw, svc in [
            ("ssh", "SSH"), ("ftp", "FTP"), ("smtp", "SMTP"),
            ("http", "HTTP"), ("imap", "IMAP"), ("pop3", "POP3"),
            ("mysql", "MySQL"), ("redis", "Redis"), ("mongodb", "MongoDB"),
            ("postgresql", "PostgreSQL"), ("apache", "Apache"),
            ("nginx", "nginx"), ("microsoft-iis", "IIS"),
        ]:
            if kw in bl:
                return svc
        smap = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            80: "HTTP", 443: "HTTPS", 3306: "MySQL",
            5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
        }
        return smap.get(port, "unknown")

    def _check_cves(self, port, svc, banner):
        for sig, cve in Settings.CVE_SIGNATURES.items():
            if sig.lower() in banner.lower():
                self.logger.finding("high", f"[port {port}] Vulnerable version: {cve}")
                self.findings.append(OutputFormatter.finding(
                    "network/service", "HIGH",
                    f"Vulnerable Version on port {port}",
                    cve, evidence=banner[:100],
                    recommendation="Update to a patched version immediately.",
                ))
