import socket
import subprocess
from core.utils import OutputFormatter
from config.settings import Settings


class VulnNSE:
    def __init__(self, target, logger):
        self.target     = target
        self.logger     = logger
        self.findings   = []
        self.open_ports = []

    def check_ftp_anon(self):
        if 21 not in self.open_ports:
            return
        self.logger.section("FTP Anonymous Login Check")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(Settings.DEFAULT_TIMEOUT)
            s.connect((self.target, 21))
            s.recv(512)
            s.send(b"USER anonymous\r\n")
            r1 = s.recv(512).decode("utf-8", "ignore")
            if "331" in r1:
                s.send(b"PASS pe@scan.local\r\n")
                r2 = s.recv(512).decode("utf-8", "ignore")
                if "230" in r2:
                    self.logger.finding("high", "FTP anonymous login allowed")
                    self.findings.append(OutputFormatter.finding(
                        "network/ftp", "HIGH", "FTP Anonymous Login",
                        "FTP server permits anonymous authentication.",
                        recommendation="Disable anonymous FTP access.",
                    ))
            s.close()
        except Exception as e:
            self.logger.debug(f"FTP anon check: {e}")

    def check_ssh_algos(self):
        if 22 not in self.open_ports:
            return
        self.logger.section("SSH Algorithm Audit")
        try:
            r = subprocess.run(
                ["ssh", "-vn", "-o", "BatchMode=yes",
                 "-o", "StrictHostKeyChecking=no",
                 "-o", f"ConnectTimeout={Settings.CONNECT_TIMEOUT}",
                 self.target],
                capture_output=True, text=True, timeout=10,
            )
            for line in r.stderr.splitlines():
                ll = line.lower()
                for weak in ["diffie-hellman-group1", "ssh-dss", "arcfour", "3des-cbc"]:
                    if weak in ll:
                        self.logger.finding("medium", f"Weak SSH algorithm advertised: {weak}")
                        self.findings.append(OutputFormatter.finding(
                            "network/ssh", "MEDIUM",
                            f"Weak SSH Algorithm: {weak}",
                            f"SSH server advertises deprecated algorithm: {weak}",
                            recommendation="Remove weak algorithms from /etc/ssh/sshd_config.",
                        ))
        except FileNotFoundError:
            self.logger.debug("ssh binary not available")
        except Exception as e:
            self.logger.debug(f"SSH algo check: {e}")

    def check_smtp_relay(self):
        if 25 not in self.open_ports:
            return
        self.logger.section("SMTP Open Relay Check")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(Settings.DEFAULT_TIMEOUT)
            s.connect((self.target, 25))
            s.recv(512)
            for cmd in [
                b"EHLO pe.scan.local\r\n",
                b"MAIL FROM:<probe@pe.scan.local>\r\n",
                b"RCPT TO:<external@gmail.com>\r\n",
            ]:
                s.send(cmd)
                resp = s.recv(512).decode("utf-8", "ignore")
                if cmd.startswith(b"RCPT") and "250" in resp:
                    self.logger.finding("high", "SMTP open relay detected")
                    self.findings.append(OutputFormatter.finding(
                        "network/smtp", "HIGH", "SMTP Open Relay",
                        "SMTP server relays mail to arbitrary external addresses.",
                        recommendation="Restrict relay to authenticated sessions only.",
                    ))
            s.close()
        except Exception as e:
            self.logger.debug(f"SMTP relay check: {e}")

    def check_rdp(self):
        if 3389 not in self.open_ports:
            return
        self.logger.section("RDP Exposure Check")
        self.logger.finding("medium", "RDP (3389) is open — BlueKeep (CVE-2019-0708) patch status unverified")
        self.findings.append(OutputFormatter.finding(
            "network/rdp", "MEDIUM", "RDP Exposed",
            "RDP port 3389 is open. Verify CVE-2019-0708 (BlueKeep) patch status.",
            recommendation="Restrict RDP to VPN or jump-host access. Apply all MS RDP patches.",
        ))

    def check_telnet(self):
        if 23 not in self.open_ports:
            return
        self.logger.section("Telnet Check")
        self.logger.finding("high", "Telnet (23) is open — plaintext protocol")
        self.findings.append(OutputFormatter.finding(
            "network/telnet", "HIGH", "Telnet Enabled",
            "Telnet transmits all data including credentials in cleartext.",
            recommendation="Disable Telnet. Replace with SSH.",
        ))

    def run(self):
        self.logger.section("Script-Style Network Checks")
        self.check_ftp_anon()
        self.check_ssh_algos()
        self.check_smtp_relay()
        self.check_rdp()
        self.check_telnet()
