from core.utils import OutputFormatter
from config.settings import Settings


class PCIScanner:
    def __init__(self, target, logger, prior=None):
        self.target   = target
        self.logger   = logger
        self.prior    = prior or []
        self.findings = []

    def _has(self, keyword):
        keyword = keyword.lower()
        for f in self.prior:
            if keyword in (f.get("title","") + f.get("description","")).lower():
                return True
        return False

    def requirement_1(self):
        self.logger.section("PCI Req 1 — Network Security Controls")
        checks = [
            ("firewall",        "Firewall issue detected — network segmentation may be insufficient"),
            ("unnecessary port","Unnecessary service port exposed"),
            ("smb",             "SMB exposed — high-risk lateral movement vector"),
        ]
        for kw, msg in checks:
            if self._has(kw):
                self.logger.finding("high", f"[PCI Req 1] {msg}")
                self.findings.append(OutputFormatter.finding(
                    "compliance/pci", "HIGH", "PCI Req 1 — Network Control", msg,
                    recommendation="Review and tighten network segmentation rules.",
                ))

    def requirement_2(self):
        self.logger.section("PCI Req 2 — Secure Configurations")
        checks = [
            ("default credentials", "Default credentials in use — violates Req 2.1"),
            ("nopasswd",            "NOPASSWD sudo — violates Req 2.2"),
            ("suid",                "Dangerous SUID binary — violates Req 2.2"),
        ]
        for kw, msg in checks:
            if self._has(kw):
                self.logger.finding("high", f"[PCI Req 2] {msg}")
                self.findings.append(OutputFormatter.finding(
                    "compliance/pci", "HIGH", "PCI Req 2 — Secure Configuration", msg,
                    recommendation="Apply CIS hardening benchmarks.",
                ))

    def requirement_4(self):
        self.logger.section("PCI Req 4 — Cryptography in Transit")
        checks = [
            ("weak protocol",     "Weak TLS protocol — Req 4.2.1"),
            ("weak cipher",       "Weak cipher suite — Req 4.2.1"),
            ("certificate expired","Expired certificate — Req 4.2.1"),
            ("self-signed",       "Self-signed certificate — Req 4.2.1"),
            ("ssl disabled",      "SSL disabled on database — Req 4.2.1"),
        ]
        for kw, msg in checks:
            if self._has(kw):
                self.logger.finding("high", f"[PCI Req 4] {msg}")
                self.findings.append(OutputFormatter.finding(
                    "compliance/pci", "HIGH", "PCI Req 4 — Cryptography", msg,
                    recommendation="Configure TLSv1.2/1.3 with strong cipher suites.",
                ))

    def requirement_6(self):
        self.logger.section("PCI Req 6 — Secure Software Development")
        checks = [
            ("sql injection",     "SQL Injection — Req 6.2.4"),
            ("xss",               "XSS — Req 6.2.4"),
            ("lfi",               "LFI — Req 6.2.4"),
            ("csrf",              "CSRF missing — Req 6.2.4"),
            ("outdated",          "Outdated component — Req 6.3.3"),
        ]
        for kw, msg in checks:
            if self._has(kw):
                self.logger.finding("high", f"[PCI Req 6] {msg}")
                self.findings.append(OutputFormatter.finding(
                    "compliance/pci", "HIGH", "PCI Req 6 — Secure Development", msg,
                    recommendation="Apply secure coding practices and patch all components.",
                ))

    def run(self):
        self.logger.section("PCI DSS Detailed Scan")
        self.requirement_1()
        self.requirement_2()
        self.requirement_4()
        self.requirement_6()
        total = len(self.findings)
        if total == 0:
            self.logger.success("No PCI DSS violations detected")
        else:
            self.logger.warning(f"{total} PCI DSS finding(s) require remediation")
