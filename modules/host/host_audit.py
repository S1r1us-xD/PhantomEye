import os
import socket
import subprocess
from core.utils import OutputFormatter
from config.settings import Settings


class HostAudit:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []
        self.is_local = self._detect_local()

    def _detect_local(self):
        try:
            ip = socket.gethostbyname(self.target)
            my_ip = ""
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                my_ip = s.getsockname()[0]
                s.close()
            except Exception:
                pass
            return ip in ["127.0.0.1", "::1"] or ip == my_ip or self.target in ["localhost", "127.0.0.1"]
        except Exception:
            return False

    def _cmd(self, cmd, timeout=15):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout.strip()
        except Exception:
            return ""

    def os_info(self):
        self.logger.section("OS Information")
        if not self.is_local:
            self.logger.info("Host audit runs on local targets only")
            return {}

        import platform
        info = {
            "platform": platform.system(),
            "release":  platform.release(),
            "version":  platform.version(),
            "machine":  platform.machine(),
            "hostname": socket.gethostname(),
        }
        for k, v in info.items():
            self.logger.stat(k.capitalize(), v)

        kernel = self._cmd(["uname", "-r"])
        if kernel:
            info["kernel"] = kernel
            self.logger.stat("Kernel", kernel)
            try:
                parts = kernel.split(".")
                major = int(parts[0])
                minor = int(parts[1].split("-")[0])
                if major < 5 or (major == 5 and minor < 10):
                    self.logger.finding("medium", f"Kernel {kernel} may have unpatched privilege escalation CVEs")
                    self.findings.append(OutputFormatter.finding(
                        "host/os", "MEDIUM",
                        f"Outdated Kernel: {kernel}",
                        "Kernel version predates several known privilege escalation CVEs.",
                        recommendation="Update kernel to latest stable version.",
                    ))
            except Exception:
                pass

        self.findings.append(OutputFormatter.finding(
            "host/os", "INFO", "OS Information",
            f"{info.get('platform')} {info.get('release')}",
            evidence=str(info)[:300],
        ))
        return info

    def running_services(self):
        self.logger.section("Running Services")
        if not self.is_local:
            return []

        risky = [
            "telnet", "rsh", "rlogin", "tftp", "finger",
            "rpcbind", "xinetd", "vsftpd", "tftpd",
        ]
        services = []
        out = self._cmd(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"])
        if out:
            for line in out.splitlines():
                if ".service" in line:
                    svc = line.split()[0].replace(".service", "")
                    services.append(svc)
                    if any(r in svc.lower() for r in risky):
                        self.logger.finding("high", f"Insecure service running: {svc}")
                        self.findings.append(OutputFormatter.finding(
                            "host/services", "HIGH",
                            f"Insecure Service Running: {svc}",
                            f"{svc} is active and may expose unencrypted or unauthenticated functionality.",
                            recommendation="Disable or replace with a secure alternative.",
                        ))

        listening = self._cmd(["ss", "-tlnp"])
        if listening:
            self.logger.info(f"Listening sockets:\n{listening[:600]}")
        return services

    def user_enumeration(self):
        self.logger.section("User & Account Enumeration")
        if not self.is_local:
            return []

        users = []
        try:
            with open("/etc/passwd", "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) < 7:
                        continue
                    uname, uid_s, shell = parts[0], parts[2], parts[6]
                    try:
                        uid = int(uid_s)
                    except ValueError:
                        uid = -1
                    can_login = shell not in ["/sbin/nologin", "/bin/false", "/usr/sbin/nologin"]
                    users.append({"name": uname, "uid": uid, "shell": shell, "login": can_login})
                    if uid == 0 and uname != "root":
                        self.logger.finding("critical", f"Non-root account with UID 0: {uname}")
                        self.findings.append(OutputFormatter.finding(
                            "host/users", "CRITICAL",
                            f"UID 0 Account: {uname}",
                            "Non-root user has UID 0 — equivalent to root access.",
                            recommendation="Investigate and remove. This is a critical misconfiguration.",
                        ))

            loginable = [u for u in users if u["login"]]
            self.logger.info(f"{len(users)} accounts — {len(loginable)} with login shell")
            if loginable:
                self.logger.table(
                    ["Username", "UID", "Shell"],
                    [(u["name"], u["uid"], u["shell"]) for u in loginable[:20]],
                )
        except PermissionError:
            self.logger.warning("/etc/passwd not readable")

        sudoers = self._cmd(["cat", "/etc/sudoers"])
        if sudoers and "NOPASSWD" in sudoers:
            self.logger.finding("high", "NOPASSWD sudo rule detected")
            self.findings.append(OutputFormatter.finding(
                "host/users", "HIGH", "NOPASSWD Sudo Rule",
                "sudoers allows passwordless privilege escalation.",
                recommendation="Remove NOPASSWD. Restrict sudo to specific commands only.",
            ))
        return users

    def run(self):
        self.logger.section("Host Audit")
        self.os_info()
        self.running_services()
        self.user_enumeration()
