import subprocess
from core.utils import OutputFormatter


class CredentialedAudit:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []
        self.user     = None
        self.password = None

    def _ssh_cmd(self, command, timeout=15):
        if not self.user:
            return ""
        try:
            cmd = [
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "BatchMode=yes",
                "-o", f"ConnectTimeout=5",
                f"{self.user}@{self.target}",
                command,
            ]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout.strip()
        except Exception:
            return ""

    def passwd_shadow_check(self):
        self.logger.section("Credentialed: /etc/shadow Check")
        out = self._ssh_cmd("sudo cat /etc/shadow 2>/dev/null | head -20")
        if out and ":" in out:
            self.logger.finding("info", "Read access to /etc/shadow confirmed")
            empty_pass = [
                line.split(":")[0]
                for line in out.splitlines()
                if line.count(":") >= 1 and line.split(":")[1] in ["", "!", "*"]
            ]
            if empty_pass:
                self.logger.finding("high", f"Accounts with no password: {', '.join(empty_pass)}")
                self.findings.append(OutputFormatter.finding(
                    "host/cred", "HIGH",
                    "Accounts With No Password",
                    f"Accounts without passwords: {', '.join(empty_pass)}",
                    recommendation="Set strong passwords for all accounts.",
                ))

    def sudo_permissions(self):
        self.logger.section("Credentialed: sudo Permissions")
        out = self._ssh_cmd("sudo -l 2>/dev/null")
        if out:
            self.logger.info(f"sudo permissions:\n{out[:400]}")
            if "NOPASSWD" in out:
                self.logger.finding("high", "NOPASSWD sudo rule found via credentialed check")
                self.findings.append(OutputFormatter.finding(
                    "host/cred", "HIGH",
                    "NOPASSWD Sudo Rule (Credentialed)",
                    "sudo allows passwordless privilege escalation.",
                    recommendation="Remove NOPASSWD entries. Restrict to specific commands.",
                ))

    def sensitive_files(self):
        self.logger.section("Credentialed: Sensitive File Access")
        paths = [
            "/etc/shadow", "/root/.ssh/id_rsa",
            "/root/.bash_history", "/var/log/auth.log",
        ]
        for path in paths:
            out = self._ssh_cmd(f"test -r {path} && echo READABLE || echo NO")
            if out == "READABLE":
                self.logger.finding("medium", f"Readable sensitive file: {path}")
                self.findings.append(OutputFormatter.finding(
                    "host/cred", "MEDIUM",
                    f"Sensitive File Readable: {path}",
                    f"Current user can read {path}.",
                    recommendation="Restrict file permissions to root only.",
                ))

    def run(self):
        self.logger.section("Credentialed Host Audit")
        if not self.user:
            self.logger.info("No credentials provided — skipping credentialed audit (use --user)")
            return
        self.passwd_shadow_check()
        self.sudo_permissions()
        self.sensitive_files()
