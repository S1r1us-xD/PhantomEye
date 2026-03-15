from core.utils import OutputFormatter
from config.settings import Settings


class ComplianceScanner:
    def __init__(self, target, logger, prior=None):
        self.target   = target
        self.logger   = logger
        self.prior    = prior or []
        self.findings = []

    def _has(self, keyword):
        keyword = keyword.lower()
        for f in self.prior:
            text = (f.get("title", "") + " " + f.get("description", "")).lower()
            if keyword in text:
                return True
        return False

    def pci_dss(self):
        self.logger.section("PCI DSS Compliance Mapping")
        checks = [
            ("weak protocol",         "PCI 4.1",  "Weak TLS protocol — cardholder data transmission not secured"),
            ("weak cipher",           "PCI 4.1",  "Weak cipher suite — violates PCI cryptographic requirements"),
            ("default credentials",   "PCI 2.1",  "Default credentials in use — violates PCI hardening requirements"),
            ("self-signed",           "PCI 4.1",  "Self-signed certificate — not from trusted CA"),
            ("certificate expired",   "PCI 4.1",  "Expired SSL certificate"),
            ("csrf",                  "PCI 6.5.9","CSRF protection missing"),
            ("sql injection",         "PCI 6.5.1","SQL injection vulnerability"),
            ("xss",                   "PCI 6.5.7","XSS vulnerability"),
            ("directory listing",     "PCI 6.5",  "Directory listing enabled"),
            ("open redirect",         "PCI 6.5.8","Unvalidated redirect"),
        ]
        failed = 0
        for keyword, req, msg in checks:
            if self._has(keyword):
                self.logger.finding("high", f"[{req}] {msg}")
                self.findings.append(OutputFormatter.finding(
                    "compliance/pci", "HIGH",
                    f"PCI DSS Violation: {req}",
                    msg,
                    recommendation=f"Remediate to satisfy PCI DSS {req}.",
                ))
                failed += 1
        if failed == 0:
            self.logger.success("No PCI DSS violations identified from current findings")
        else:
            self.logger.warning(f"{failed} PCI DSS control(s) potentially violated")

    def owasp_top10(self):
        self.logger.section("OWASP Top 10 Mapping")
        mappings = {
            "A01": [("broken access", "Broken Access Control detected")],
            "A02": [("weak cipher", "Weak cryptography"), ("expired cert", "Expired certificate"),
                    ("self-signed", "Self-signed certificate")],
            "A03": [("sql injection", "SQL Injection"), ("xss", "Cross-Site Scripting"),
                    ("lfi", "Local File Inclusion"), ("rfi", "Remote File Inclusion"),
                    ("command injection", "Command Injection")],
            "A05": [("missing header", "Security header missing"),
                    ("default credentials", "Default credentials in use"),
                    ("directory listing", "Directory listing enabled")],
            "A06": [("cve", "Vulnerable/outdated component"), ("eol", "End-of-life software")],
            "A07": [("csrf", "CSRF token missing"), ("no rate limiting", "No rate limiting")],
            "A10": [("ssrf", "SSRF vulnerability")],
        }
        for owasp_id, checks in mappings.items():
            desc = Settings.OWASP_TOP10.get(owasp_id, "")
            for keyword, label in checks:
                if self._has(keyword):
                    self.logger.finding("medium", f"[OWASP {owasp_id} — {desc}] {label}")
                    self.findings.append(OutputFormatter.finding(
                        "compliance/owasp", "MEDIUM",
                        f"OWASP {owasp_id}: {label}",
                        f"Finding maps to OWASP Top 10 — {desc}",
                        recommendation=f"Remediate per OWASP guidance for {desc}.",
                    ))

    def run(self):
        self.logger.section("Compliance Scan")
        self.pci_dss()
        self.owasp_top10()
