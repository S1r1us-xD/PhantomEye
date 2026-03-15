import socket
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from core.utils import OutputFormatter
from config.settings import Settings


class HostDiscovery:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []

    def icmp_ping(self):
        self.logger.section("Host Discovery — ICMP Ping")
        try:
            r = subprocess.run(
                ["ping", "-c", "3", "-W", "2", self.target],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0:
                self.logger.success(f"Host {self.target} is up (ICMP)")
                return True
            self.logger.warning(f"Host {self.target} did not respond to ICMP ping")
            return False
        except Exception:
            return False

    def tcp_ping(self, ports=None):
        self.logger.section("Host Discovery — TCP Ping")
        ports = ports or [80, 443, 22, 21, 25, 8080]
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(Settings.CONNECT_TIMEOUT)
                if s.connect_ex((self.target, port)) == 0:
                    self.logger.success(f"Host up — TCP port {port} responded")
                    s.close()
                    return True
                s.close()
            except Exception:
                pass
        return False

    def arp_scan(self, cidr=None):
        self.logger.section("ARP Scan")
        target = cidr or self.target
        live   = []
        try:
            r = subprocess.run(
                ["arp-scan", "--localnet", target],
                capture_output=True, text=True, timeout=60,
            )
            for line in r.stdout.splitlines():
                if line and line[0].isdigit():
                    parts = line.split()
                    if len(parts) >= 2:
                        self.logger.success(f"Live host: {parts[0]}  MAC: {parts[1]}")
                        live.append({"ip": parts[0], "mac": parts[1]})
        except FileNotFoundError:
            self.logger.warning("arp-scan not found — using TCP sweep")
            live = self._tcp_sweep(target)
        self.findings.append(OutputFormatter.finding(
            "network/discovery", "INFO", "ARP Scan Results",
            f"{len(live)} live host(s) found",
            evidence=str(live[:20]),
        ))
        return live

    def _tcp_sweep(self, cidr):
        live = []
        try:
            hosts = [str(ip) for ip in ipaddress.ip_network(cidr, strict=False).hosts()]

            def check(ip):
                for p in [80, 22, 443]:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        if s.connect_ex((ip, p)) == 0:
                            s.close()
                            return ip
                        s.close()
                    except Exception:
                        pass
                return None

            with ThreadPoolExecutor(max_workers=200) as ex:
                for result in ex.map(check, hosts):
                    if result:
                        self.logger.success(f"Live host: {result}")
                        live.append({"ip": result, "mac": "N/A"})
        except Exception:
            pass
        return live

    def traceroute(self):
        self.logger.section("Traceroute")
        hops = []
        try:
            r = subprocess.run(
                ["traceroute", "-n", "-m", "20", self.target],
                capture_output=True, text=True, timeout=60,
            )
            for line in r.stdout.splitlines():
                if line.strip() and line[0].isdigit():
                    self.logger.info(line)
                    hops.append(line.strip())
        except FileNotFoundError:
            try:
                r = subprocess.run(
                    ["tracepath", "-n", self.target],
                    capture_output=True, text=True, timeout=60,
                )
                for line in r.stdout.splitlines():
                    self.logger.info(line)
                    hops.append(line)
            except Exception:
                self.logger.warning("traceroute/tracepath not available")
        self.findings.append(OutputFormatter.finding(
            "network/discovery", "INFO", "Traceroute",
            f"Route to {self.target} — {len(hops)} hop(s)",
            evidence="\n".join(hops[:20]),
        ))
        return hops

    def run(self, cidr=None):
        self.icmp_ping()
        self.tcp_ping()
        if cidr and "/" in str(cidr):
            self.arp_scan(cidr)
        self.traceroute()
