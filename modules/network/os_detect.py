import socket
from core.utils import OutputFormatter
from config.settings import Settings


class OSDetect:
    def __init__(self, target, logger):
        self.target     = target
        self.logger     = logger
        self.findings   = []
        self.open_ports = []

    def ttl_fingerprint(self):
        try:
            import struct
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.settimeout(Settings.DEFAULT_TIMEOUT)
            s.sendto(b"\x08\x00\xf7\xff\x00\x00\x00\x00", (self.target, 0))
            data, _ = s.recvfrom(1024)
            s.close()
            ttl = data[8]
            if ttl <= 64:
                return ttl, "Linux / Unix (TTL ~64)"
            if ttl <= 128:
                return ttl, "Windows (TTL ~128)"
            return ttl, "Cisco / Network device (TTL ~255)"
        except PermissionError:
            return None, None
        except Exception:
            return None, None

    def banner_fingerprint(self):
        for port in [22, 80, 443, 21, 25]:
            if port not in self.open_ports:
                continue
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(Settings.DEFAULT_TIMEOUT)
                s.connect((self.target, port))
                banner = s.recv(512).decode("utf-8", "ignore").lower()
                s.close()
                for kw, os_name in [
                    ("ubuntu",  "Linux/Ubuntu"),
                    ("debian",  "Linux/Debian"),
                    ("centos",  "Linux/CentOS"),
                    ("fedora",  "Linux/Fedora"),
                    ("red hat", "Linux/RHEL"),
                    ("windows", "Windows"),
                    ("microsoft", "Windows"),
                    ("freebsd", "FreeBSD"),
                    ("openbsd", "OpenBSD"),
                    ("darwin",  "macOS"),
                ]:
                    if kw in banner:
                        return os_name, banner[:80]
            except Exception:
                pass
        return None, None

    def server_header_fingerprint(self):
        for port in [80, 443, 8080, 8443]:
            if port not in self.open_ports:
                continue
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(Settings.DEFAULT_TIMEOUT)
                s.connect((self.target, port))
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                resp = s.recv(512).decode("utf-8", "ignore")
                s.close()
                for line in resp.splitlines():
                    if line.lower().startswith("server:"):
                        return line.split(":", 1)[1].strip()
            except Exception:
                pass
        return None

    def run(self):
        self.logger.section("OS Detection")
        ttl, ttl_os  = self.ttl_fingerprint()
        ban_os, _    = self.banner_fingerprint()
        server       = self.server_header_fingerprint()

        if ttl_os:
            self.logger.success(f"TTL fingerprint: {ttl_os}  (TTL={ttl})")
        if ban_os:
            self.logger.success(f"Banner fingerprint: {ban_os}")
        if server:
            self.logger.success(f"Server header: {server}")

        final = ban_os or ttl_os or "Unknown"
        self.logger.info(f"Estimated OS: {final}")
        self.findings.append(OutputFormatter.finding(
            "network/os", "INFO", "OS Fingerprint",
            f"Estimated OS: {final}",
            evidence=f"TTL={ttl}, banner_os={ban_os}, server={server}",
        ))
