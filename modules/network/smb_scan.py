import socket
import subprocess
from core.utils import OutputFormatter
from config.settings import Settings


class SMBScanner:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []

    def _port_open(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(Settings.CONNECT_TIMEOUT)
            r = s.connect_ex((self.target, port))
            s.close()
            return r == 0
        except Exception:
            return False

    def null_session(self):
        self.logger.section("SMB Null Session Enumeration")
        if not (self._port_open(445) or self._port_open(139)):
            self.logger.info("SMB ports not open — skipping")
            return {}

        results = {}
        try:
            r = subprocess.run(
                ["smbclient", "-L", self.target, "-N"],
                capture_output=True, text=True, timeout=15,
            )
            out = r.stdout + r.stderr
            if "Sharename" in out or "WORKGROUP" in out:
                self.logger.finding("medium", "SMB null session — share enumeration succeeded")
                results["shares"] = out[:600]
                self.findings.append(OutputFormatter.finding(
                    "network/smb", "MEDIUM", "SMB Anonymous Access",
                    "SMB null session allowed — share names are visible without credentials.",
                    evidence=out[:300],
                    recommendation="Disable anonymous SMB sessions. Enforce authenticated access.",
                ))
            else:
                self.logger.success("SMB null session blocked (authenticated required)")
        except FileNotFoundError:
            self.logger.warning("smbclient not installed")
        return results

    def enum4linux(self):
        self.logger.section("SMB Enumeration (enum4linux)")
        try:
            r = subprocess.run(
                ["enum4linux", "-a", self.target],
                capture_output=True, text=True, timeout=90,
            )
            if r.stdout.strip():
                self.logger.info("enum4linux output captured")
                for line in r.stdout.splitlines():
                    if any(kw in line for kw in ["user:", "group:", "share:", "password policy"]):
                        self.logger.success(f"  {line.strip()[:120]}")
                return r.stdout[:2000]
        except FileNotFoundError:
            self.logger.debug("enum4linux not installed")
        return ""

    def check_eternalblue(self):
        self.logger.section("EternalBlue Indicator Check (MS17-010)")
        if not self._port_open(445):
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(Settings.DEFAULT_TIMEOUT)
            s.connect((self.target, 445))
            negotiate = (
                b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00"
                b"\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\xff\xff\xff\xfe\x00\x00\x00\x00\x00\x62\x00"
                b"\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50"
                b"\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c"
                b"\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e"
                b"\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b"
                b"\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02"
                b"\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41"
                b"\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c"
                b"\x4d\x20\x30\x2e\x31\x32\x00"
            )
            s.send(negotiate)
            resp = s.recv(1024)
            s.close()
            if len(resp) > 36 and resp[8] == 0x72:
                self.logger.finding(
                    "high",
                    "SMB responded to negotiate — manual MS17-010 (EternalBlue) verification recommended",
                )
                self.findings.append(OutputFormatter.finding(
                    "network/smb", "HIGH", "SMB Active — MS17-010 Verification Needed",
                    "SMB port 445 is open. Verify MS17-010 (EternalBlue) patch status.",
                    recommendation="Ensure KB4012212 (MS17-010) patch is applied. Disable SMBv1.",
                ))
        except Exception as e:
            self.logger.debug(f"EternalBlue check: {e}")

    def run(self):
        self.null_session()
        self.enum4linux()
        self.check_eternalblue()
