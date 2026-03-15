import os
import subprocess
from core.utils import OutputFormatter


class ConfigAudit:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []

    def _cmd(self, cmd, timeout=30):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout.strip()
        except Exception:
            return ""

    def suid_audit(self):
        self.logger.section("SUID / SGID Binary Audit")
        dangerous = [
            "nmap", "vim", "nano", "less", "more", "awk",
            "python", "python3", "perl", "ruby", "php",
            "wget", "curl", "bash", "dash", "sh", "env",
            "find", "tee", "cp", "mv", "tar", "zip",
            "socat", "nc", "netcat", "openssl", "gcc", "strace",
        ]
        out = self._cmd(["find", "/usr", "/bin", "/sbin",
                         "-perm", "/4000", "-type", "f"], timeout=30)
        for binary in out.splitlines():
            if not binary:
                continue
            base = os.path.basename(binary)
            if any(d in base.lower() for d in dangerous):
                self.logger.finding("high", f"Dangerous SUID binary: {binary}")
                self.findings.append(OutputFormatter.finding(
                    "host/config", "HIGH",
                    f"Dangerous SUID Binary: {binary}",
                    f"{binary} has SUID set and can be used for privilege escalation.",
                    recommendation=f"Remove SUID bit: chmod u-s {binary}",
                ))
            else:
                self.logger.info(f"SUID binary: {binary}")

    def world_writable_files(self):
        self.logger.section("World-Writable File Check")
        out = self._cmd([
            "find", "/etc", "/var", "/tmp",
            "-perm", "-o+w",
            "-not", "-path", "*/proc/*",
            "-type", "f",
        ], timeout=30)
        for path in out.splitlines()[:30]:
            if path:
                self.logger.finding("medium", f"World-writable file: {path}")
                self.findings.append(OutputFormatter.finding(
                    "host/config", "MEDIUM",
                    f"World-Writable File: {path}",
                    f"{path} is writable by any local user.",
                    recommendation="Review and restrict permissions with chmod.",
                ))

    def cron_audit(self):
        self.logger.section("Cron Job Audit")
        cron_paths = [
            "/etc/crontab", "/etc/cron.d",
            "/etc/cron.hourly", "/etc/cron.daily",
            "/etc/cron.weekly", "/var/spool/cron",
        ]
        suspicious = [
            "curl ", "wget ", "nc ", "bash -i", "python -c",
            "perl -e", "ruby -e", "/tmp/", "mkfifo",
        ]
        for cpath in cron_paths:
            if os.path.isfile(cpath):
                content = self._cmd(["cat", cpath])
                if content:
                    self.logger.info(f"{cpath}:\n{content[:200]}")
                    if any(s in content for s in suspicious):
                        self.logger.finding("high", f"Suspicious cron job in: {cpath}")
                        self.findings.append(OutputFormatter.finding(
                            "host/config", "HIGH",
                            f"Suspicious Cron Job: {cpath}",
                            "Cron entry contains network or shell execution commands.",
                            evidence=content[:300],
                            recommendation="Audit and remove unauthorised cron jobs.",
                        ))
            elif os.path.isdir(cpath):
                try:
                    for entry in os.listdir(cpath):
                        content = self._cmd(["cat", os.path.join(cpath, entry)])
                        if content and any(s in content for s in suspicious):
                            self.logger.finding("high", f"Suspicious cron: {cpath}/{entry}")
                except PermissionError:
                    pass

    def ssh_config_audit(self):
        self.logger.section("SSH Configuration Audit")
        cfg = self._cmd(["cat", "/etc/ssh/sshd_config"])
        if not cfg:
            return

        checks = {
            "PermitRootLogin yes":       ("high",     "Root SSH login is permitted"),
            "PasswordAuthentication yes": ("medium",  "Password authentication enabled — prefer key-based auth"),
            "PermitEmptyPasswords yes":   ("critical","Empty password SSH login permitted"),
            "X11Forwarding yes":          ("low",     "X11 forwarding enabled"),
            "Protocol 1":                ("critical", "SSHv1 protocol enabled — cryptographically broken"),
            "UsePAM no":                 ("medium",   "PAM disabled in SSH config"),
        }
        for pattern, (sev, msg) in checks.items():
            if pattern.lower() in cfg.lower():
                self.logger.finding(sev, f"SSH: {msg}")
                self.findings.append(OutputFormatter.finding(
                    "host/config", sev.upper(),
                    "SSH Misconfiguration",
                    msg,
                    recommendation="Update /etc/ssh/sshd_config and restart sshd.",
                ))

    def firewall_audit(self):
        self.logger.section("Firewall Status Check")
        iptables = self._cmd(["iptables", "-L", "-n", "-v"])
        if iptables:
            self.logger.info(f"iptables rules:\n{iptables[:400]}")
            if "policy ACCEPT" in iptables.upper():
                self.logger.finding("medium", "Default iptables ACCEPT policy — no default deny")
                self.findings.append(OutputFormatter.finding(
                    "host/config", "MEDIUM",
                    "Permissive Firewall Default Policy",
                    "Default iptables chain policy is ACCEPT.",
                    recommendation="Set default policies to DROP. Explicitly allow required traffic.",
                ))

        ufw = self._cmd(["ufw", "status", "verbose"])
        if ufw:
            self.logger.info(f"UFW status:\n{ufw[:300]}")

    def run(self):
        self.logger.section("Configuration Audit")
        self.suid_audit()
        self.world_writable_files()
        self.cron_audit()
        self.ssh_config_audit()
        self.firewall_audit()
