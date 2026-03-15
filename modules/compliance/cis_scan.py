import os
import subprocess
from core.utils import OutputFormatter


class CISScanner:
    def __init__(self, target, logger, prior=None):
        self.target   = target
        self.logger   = logger
        self.prior    = prior or []
        self.findings = []

    def _cmd(self, cmd, timeout=20):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout.strip()
        except Exception:
            return ""

    def _has(self, keyword):
        keyword = keyword.lower()
        for f in self.prior:
            if keyword in (f.get("title", "") + f.get("description", "")).lower():
                return True
        return False

    def section_1_filesystem(self):
        self.logger.section("CIS Section 1 — Filesystem Configuration")
        noexec_tmp = self._cmd(["findmnt", "--output", "OPTIONS", "/tmp"])
        if noexec_tmp and "noexec" not in noexec_tmp:
            self.logger.finding("medium", "CIS 1.1.3 — /tmp is mounted without noexec")
            self.findings.append(OutputFormatter.finding(
                "compliance/cis", "MEDIUM",
                "CIS 1.1.3 — /tmp noexec Missing",
                "/tmp is mounted without the noexec option.",
                recommendation="Add noexec to /tmp mount options in /etc/fstab.",
            ))

        sticky = self._cmd(["stat", "-c", "%a", "/tmp"])
        if sticky and not sticky.startswith("1"):
            self.logger.finding("medium", "CIS 1.1.6 — Sticky bit not set on /tmp")
            self.findings.append(OutputFormatter.finding(
                "compliance/cis", "MEDIUM",
                "CIS 1.1.6 — Sticky Bit Missing on /tmp",
                "/tmp does not have the sticky bit set.",
                recommendation="Run: chmod +t /tmp",
            ))

    def section_5_access(self):
        self.logger.section("CIS Section 5 — Access, Auth and Authorization")
        if self._has("nopasswd"):
            self.logger.finding("high", "CIS 5.3.6 — NOPASSWD sudo rule present")
            self.findings.append(OutputFormatter.finding(
                "compliance/cis", "HIGH",
                "CIS 5.3.6 — NOPASSWD Sudo Rule",
                "sudo configured with NOPASSWD — passwordless privilege escalation.",
                recommendation="Remove all NOPASSWD entries from /etc/sudoers.",
            ))

        if self._has("uid 0"):
            self.logger.finding("critical", "CIS 5.4.2 — Non-root account with UID 0")
            self.findings.append(OutputFormatter.finding(
                "compliance/cis", "CRITICAL",
                "CIS 5.4.2 — Rogue UID 0 Account",
                "Non-root user with UID 0 found — equivalent to root access.",
                recommendation="Remove or investigate this account immediately.",
            ))

        passwd_perms = self._cmd(["stat", "-c", "%a", "/etc/passwd"])
        if passwd_perms and passwd_perms not in ["644", "0644"]:
            self.logger.finding("medium", f"CIS 5.4.1 — /etc/passwd permissions: {passwd_perms}")
            self.findings.append(OutputFormatter.finding(
                "compliance/cis", "MEDIUM",
                "CIS 5.4.1 — /etc/passwd Permissions",
                f"/etc/passwd has permissions {passwd_perms} (expected 644).",
                recommendation="Run: chmod 644 /etc/passwd",
            ))

        shadow_perms = self._cmd(["stat", "-c", "%a", "/etc/shadow"])
        if shadow_perms and shadow_perms not in ["640", "000", "0640", "0000"]:
            self.logger.finding("medium", f"CIS 5.4.1 — /etc/shadow permissions: {shadow_perms}")
            self.findings.append(OutputFormatter.finding(
                "compliance/cis", "MEDIUM",
                "CIS 5.4.1 — /etc/shadow Permissions",
                f"/etc/shadow has permissions {shadow_perms} (expected 640 or stricter).",
                recommendation="Run: chmod 640 /etc/shadow",
            ))

    def section_6_logging(self):
        self.logger.section("CIS Section 6 — Logging and Auditing")
        rsyslog = self._cmd(["systemctl", "is-active", "rsyslog"])
        syslog  = self._cmd(["systemctl", "is-active", "syslog"])
        if rsyslog != "active" and syslog != "active":
            self.logger.finding("medium", "CIS 6.2 — rsyslog/syslog not running")
            self.findings.append(OutputFormatter.finding(
                "compliance/cis", "MEDIUM",
                "CIS 6.2 — Syslog Not Running",
                "No active syslog daemon detected.",
                recommendation="Enable rsyslog: systemctl enable --now rsyslog",
            ))

        auditd = self._cmd(["systemctl", "is-active", "auditd"])
        if auditd != "active":
            self.logger.finding("medium", "CIS 6.3 — auditd not running")
            self.findings.append(OutputFormatter.finding(
                "compliance/cis", "MEDIUM",
                "CIS 6.3 — Audit Daemon Not Running",
                "auditd is not active — kernel-level audit logging disabled.",
                recommendation="Enable: systemctl enable --now auditd",
            ))

    def section_9_network(self):
        self.logger.section("CIS Section 9 — Networking")
        if self._has("ssh misconfiguration"):
            self.logger.finding("high", "CIS 9.3 — SSH misconfiguration detected")
            self.findings.append(OutputFormatter.finding(
                "compliance/cis", "HIGH",
                "CIS 9.3 — SSH Hardening Required",
                "SSH configuration does not meet CIS hardening requirements.",
                recommendation="Apply CIS SSH hardening: disable root login, enforce key-based auth.",
            ))

        if self._has("firewall"):
            self.logger.finding("medium", "CIS 9.1 — Firewall issue detected")
            self.findings.append(OutputFormatter.finding(
                "compliance/cis", "MEDIUM",
                "CIS 9.1 — Firewall Configuration",
                "Firewall policy issue found.",
                recommendation="Set default DROP policy on all chains.",
            ))

    def run(self):
        self.logger.section("CIS Benchmark Compliance Check")
        self.section_1_filesystem()
        self.section_5_access()
        self.section_6_logging()
        self.section_9_network()
        total = len(self.findings)
        if total == 0:
            self.logger.success("No CIS benchmark violations detected")
        else:
            self.logger.warning(f"{total} CIS benchmark finding(s) require attention")
