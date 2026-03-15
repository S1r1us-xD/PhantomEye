import subprocess
from core.utils import OutputFormatter


class MobileScanner:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []

    def _cmd(self, cmd, timeout=15):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout.strip(), r.returncode
        except FileNotFoundError:
            return "", 127
        except Exception:
            return "", -1

    def adb_devices(self):
        self.logger.section("ADB Device Detection")
        out, rc = self._cmd(["adb", "devices"])
        if rc == 127:
            self.logger.info("adb not installed — mobile checks unavailable")
            return []

        devices = []
        for line in out.splitlines()[1:]:
            line = line.strip()
            if line and "device" in line:
                device_id = line.split()[0]
                devices.append(device_id)
                self.logger.success(f"ADB device connected: {device_id}")
                self.findings.append(OutputFormatter.finding(
                    "mobile", "INFO",
                    f"ADB Device Connected: {device_id}",
                    "Android device accessible via ADB.",
                ))
        return devices

    def adb_security_checks(self, device_id):
        self.logger.section(f"ADB Security Checks — {device_id}")

        out, _ = self._cmd(["adb", "-s", device_id, "shell", "getprop", "ro.debuggable"])
        if out.strip() == "1":
            self.logger.finding("high", f"Android device {device_id} is in debug mode")
            self.findings.append(OutputFormatter.finding(
                "mobile", "HIGH",
                "Android Debug Mode Enabled",
                "ro.debuggable=1 — device is in debug mode, increasing attack surface.",
                recommendation="Disable debug mode on production devices.",
            ))

        out, _ = self._cmd(["adb", "-s", device_id, "shell", "id"])
        if "root" in out.lower():
            self.logger.finding("critical", f"ADB shell running as root on {device_id}")
            self.findings.append(OutputFormatter.finding(
                "mobile", "CRITICAL",
                "ADB Shell Running as Root",
                "ADB shell has root access — full device compromise possible.",
                recommendation="Disable root ADB access on production devices.",
            ))

        out, _ = self._cmd([
            "adb", "-s", device_id, "shell",
            "getprop", "ro.crypto.state",
        ])
        if out.strip() == "unencrypted":
            self.logger.finding("high", f"Device storage not encrypted: {device_id}")
            self.findings.append(OutputFormatter.finding(
                "mobile", "HIGH",
                "Device Storage Not Encrypted",
                "Android device storage is unencrypted — data at risk if device is lost.",
                recommendation="Enable full-disk or file-based encryption.",
            ))

    def tcpdump_check(self, device_id):
        self.logger.section("Network Interface Check via ADB")
        out, _ = self._cmd(["adb", "-s", device_id, "shell", "ip", "addr"])
        if out:
            self.logger.info(f"Network interfaces:\n{out[:400]}")

    def run(self):
        self.logger.section("Mobile / ADB Security Scan")
        devices = self.adb_devices()
        for dev in devices:
            self.adb_security_checks(dev)
            self.tcpdump_check(dev)
        if not devices:
            self.logger.info("No ADB devices found")
