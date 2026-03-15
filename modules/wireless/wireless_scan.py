import subprocess
from core.utils import OutputFormatter


class WirelessScanner:
    def __init__(self, logger):
        self.logger   = logger
        self.findings = []

    def _cmd(self, cmd, timeout=20):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout.strip(), r.returncode
        except FileNotFoundError:
            return "", 127
        except Exception:
            return "", -1

    def detect_interfaces(self):
        self.logger.section("Wireless Interface Detection")
        out, rc = self._cmd(["iwconfig"])
        if rc == 127:
            self.logger.warning("iwconfig not found — install wireless-tools")
            return []
        interfaces = []
        for line in out.splitlines():
            if line and not line.startswith(" ") and not line.startswith("\t"):
                parts = line.split()
                if parts and "no wireless" not in line.lower():
                    iface = parts[0]
                    interfaces.append(iface)
                    self.logger.success(f"Wireless interface found: {iface}")
        if not interfaces:
            self.logger.info("No wireless interfaces detected")
        return interfaces

    def scan_networks(self, interface="wlan0"):
        self.logger.section(f"Wireless Network Scan — {interface}")
        out, rc = self._cmd(["iwlist", interface, "scan"])
        if rc != 0:
            self.logger.warning(f"Scan failed on {interface} — may need root or monitor mode")
            return []

        networks = []
        current  = {}
        for line in out.splitlines():
            line = line.strip()
            if "Cell" in line and "Address" in line:
                if current:
                    networks.append(current)
                current = {"bssid": line.split("Address:")[-1].strip()}
            elif "ESSID:" in line:
                current["ssid"] = line.split("ESSID:")[-1].strip().strip('"')
            elif "Encryption key:" in line:
                current["encryption"] = line.split(":")[-1].strip()
            elif "IE: IEEE 802.11i/WPA2" in line:
                current["auth"] = "WPA2"
            elif "IE: WPA Version" in line and "auth" not in current:
                current["auth"] = "WPA"
            elif "Channel:" in line:
                current["channel"] = line.split(":")[-1].strip()
        if current:
            networks.append(current)

        for net in networks:
            enc  = net.get("encryption", "off")
            auth = net.get("auth", "OPEN")
            ssid = net.get("ssid", "<hidden>")
            self.logger.stat(ssid, f"BSSID={net.get('bssid','')}  Enc={enc}  Auth={auth}")

            if enc.lower() == "off":
                self.logger.finding("high", f"Open wireless network (no encryption): {ssid}")
                self.findings.append(OutputFormatter.finding(
                    "wireless", "HIGH",
                    f"Open Wireless Network: {ssid}",
                    "Network has no encryption — all traffic is visible to nearby devices.",
                    recommendation="Enable WPA2-AES or WPA3 encryption.",
                ))
            elif auth == "WPA" and "WPA2" not in auth:
                self.logger.finding("medium", f"Weak WPA-TKIP encryption: {ssid}")
                self.findings.append(OutputFormatter.finding(
                    "wireless", "MEDIUM",
                    f"Weak Wireless Encryption: {ssid}",
                    "WPA-TKIP is deprecated and vulnerable to KRACK and TKIP MIC attacks.",
                    recommendation="Upgrade to WPA2-AES or WPA3.",
                ))

        return networks

    def wps_check(self, interface="wlan0"):
        self.logger.section("WPS Detection")
        out, rc = self._cmd(["wash", "-i", interface, "--scan-time=10"])
        if rc == 127:
            self.logger.info("wash not installed — WPS check skipped (install reaver)")
            return []
        wps_networks = []
        for line in out.splitlines():
            if line and not line.startswith("BSSID"):
                self.logger.finding("medium", f"WPS-enabled network: {line[:80]}")
                wps_networks.append(line.strip())
                self.findings.append(OutputFormatter.finding(
                    "wireless", "MEDIUM",
                    "WPS Enabled Network Detected",
                    "WPS is enabled — vulnerable to Pixie Dust and brute-force attacks.",
                    evidence=line[:80],
                    recommendation="Disable WPS on the access point.",
                ))
        return wps_networks

    def run(self):
        self.logger.section("Wireless Scan")
        interfaces = self.detect_interfaces()
        if interfaces:
            networks = self.scan_networks(interfaces[0])
            self.wps_check(interfaces[0])
        else:
            self.logger.info("No wireless interfaces available — skipping network scan")
        self.logger.info("Passive capture: airodump-ng <iface>  |  Handshake: airodump-ng --bssid <BSSID> -c <CH> -w cap <iface>")
