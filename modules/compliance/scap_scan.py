import subprocess
from core.utils import OutputFormatter


class SCAPScanner:
    def __init__(self, target, logger, prior=None):
        self.target   = target
        self.logger   = logger
        self.prior    = prior or []
        self.findings = []

    def _cmd(self, cmd, timeout=30):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout.strip()
        except Exception:
            return ""

    def openscap_check(self):
        self.logger.section("OpenSCAP / oscap Availability")
        out = self._cmd(["oscap", "--version"])
        if out:
            self.logger.success(f"oscap available: {out.splitlines()[0]}")
            self.logger.info("Run: oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_pci-dss "
                             "/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml")
        else:
            self.logger.warning("oscap not installed — install openscap-scanner for full SCAP evaluation")
            self.findings.append(OutputFormatter.finding(
                "compliance/scap", "INFO",
                "OpenSCAP Not Installed",
                "Full SCAP evaluation requires the openscap-scanner package.",
                recommendation="Install: apt-get install openscap-scanner  or  yum install openscap-scanner",
            ))

    def aide_check(self):
        self.logger.section("AIDE File Integrity Check")
        out = self._cmd(["aide", "--check"])
        if out:
            if "changed" in out.lower() or "added" in out.lower() or "removed" in out.lower():
                self.logger.finding("medium", "AIDE detected filesystem changes")
                self.findings.append(OutputFormatter.finding(
                    "compliance/scap", "MEDIUM",
                    "AIDE Filesystem Changes Detected",
                    "File integrity monitoring detected modifications.",
                    evidence=out[:400],
                    recommendation="Investigate all reported changes for signs of compromise.",
                ))
            else:
                self.logger.success("AIDE check passed — no unexpected changes")
        else:
            self.logger.info("AIDE not installed or not initialised")

    def auditd_check(self):
        self.logger.section("Audit Daemon (auditd) Check")
        status = self._cmd(["systemctl", "is-active", "auditd"])
        if status == "active":
            self.logger.success("auditd is active")
        else:
            self.logger.finding("medium", "auditd is not running — audit logging disabled")
            self.findings.append(OutputFormatter.finding(
                "compliance/scap", "MEDIUM",
                "Audit Daemon Not Running",
                "auditd is not active — system events are not being logged.",
                recommendation="Enable and configure auditd: systemctl enable --now auditd",
            ))

    def run(self):
        self.logger.section("SCAP Compliance Check")
        self.openscap_check()
        self.aide_check()
        self.auditd_check()
