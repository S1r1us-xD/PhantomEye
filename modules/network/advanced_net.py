import socket
import struct
import time
from core.utils import OutputFormatter
from config.settings import Settings


class AdvancedNet:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []

    def sctp_init_scan(self, ports=None):
        self.logger.section("SCTP INIT Scan")
        ports = ports or [2905, 3868, 7701, 9900, 36412]
        try:
            for port in ports:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 132)
                s.settimeout(1)
                chunk = b"\x01\x00\x00\x14" + b"\x00" * 8 + struct.pack("!HH", 1, 1)
                s.sendto(chunk, (self.target, port))
                try:
                    data, _ = s.recvfrom(1024)
                    if data:
                        self.logger.success(f"SCTP INIT response on port {port}")
                        self.findings.append(OutputFormatter.finding(
                            "network/sctp", "INFO",
                            f"SCTP Port Open: {port}",
                            "SCTP INIT received a response.",
                        ))
                except socket.timeout:
                    pass
                s.close()
        except PermissionError:
            self.logger.warning("SCTP scan requires root privileges")
        except Exception as e:
            self.logger.debug(f"SCTP scan: {e}")

    def ip_protocol_scan(self):
        self.logger.section("IP Protocol Scan")
        protocols = {
            1: "ICMP", 6: "TCP", 17: "UDP",
            47: "GRE", 50: "ESP", 51: "AH", 89: "OSPF",
        }
        found = []
        for proto, name in protocols.items():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
                s.settimeout(1)
                s.sendto(b"\x00" * 8, (self.target, 0))
                try:
                    s.recv(1024)
                    self.logger.success(f"IP protocol {proto} ({name}) — responded")
                    found.append({"proto": proto, "name": name})
                except socket.timeout:
                    pass
                s.close()
            except (socket.error, PermissionError):
                pass
        return found

    def run(self):
        self.sctp_init_scan()
        self.ip_protocol_scan()
