import socket
import struct
from core.utils import OutputFormatter
from config.settings import Settings


class ICSScanner:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []

    def _tcp_open(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(Settings.CONNECT_TIMEOUT)
            r = s.connect_ex((self.target, port))
            s.close()
            return r == 0
        except Exception:
            return False

    def port_sweep(self):
        self.logger.section("ICS / SCADA Port Detection")
        ics_services = {
            102:   "Siemens S7 (ISO-TSAP)",
            502:   "Modbus TCP",
            503:   "Modbus TCP (alt)",
            1911:  "Niagara Fox Protocol",
            2222:  "EtherNet/IP",
            4840:  "OPC-UA",
            9600:  "OMRON FINS",
            18245: "GE SRTP",
            20000: "DNP3",
            34980: "EtherNet/IP",
            44818: "EtherNet/IP",
            47808: "BACnet",
        }
        found = []
        for port, service in ics_services.items():
            if self._tcp_open(port):
                self.logger.finding("high", f"ICS protocol port open: {port} ({service})")
                found.append((port, service))
                self.findings.append(OutputFormatter.finding(
                    "ics", "HIGH",
                    f"ICS Service Exposed: {service} on port {port}",
                    f"Industrial control system protocol {service} is accessible from the network.",
                    recommendation="ICS/SCADA services should never be directly internet-facing. "
                                   "Segment with industrial DMZ and strict firewall rules.",
                ))
        if not found:
            self.logger.info("No ICS/SCADA ports detected")
        return found

    def modbus_probe(self):
        if not self._tcp_open(502):
            return
        self.logger.section("Modbus TCP Probe")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(Settings.DEFAULT_TIMEOUT)
            s.connect((self.target, 502))
            request = struct.pack(">HHHBBBB", 0x0001, 0x0000, 0x0006, 0xFF, 0x11, 0x00, 0x00)
            s.send(request)
            resp = s.recv(256)
            s.close()
            if resp and len(resp) >= 8:
                self.logger.finding("critical", "Modbus TCP responded — device information disclosed")
                self.findings.append(OutputFormatter.finding(
                    "ics", "CRITICAL",
                    "Modbus Device Information Disclosed",
                    "Modbus TCP device responded to read device identification request.",
                    evidence=resp.hex()[:100],
                    recommendation="Restrict Modbus TCP access to authorised engineering workstations only.",
                ))
        except Exception as e:
            self.logger.debug(f"Modbus probe: {e}")

    def s7_probe(self):
        if not self._tcp_open(102):
            return
        self.logger.section("Siemens S7 Probe (ISO-TSAP)")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(Settings.DEFAULT_TIMEOUT)
            s.connect((self.target, 102))
            cotp_connect = (
                b"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00"
                b"\xc0\x01\x0a\xc1\x02\x01\x02\xc2\x02\x01\x00"
            )
            s.send(cotp_connect)
            resp = s.recv(256)
            s.close()
            if resp and len(resp) > 4 and resp[4] == 0xd0:
                self.logger.finding("critical", "Siemens S7 PLC responded on port 102")
                self.findings.append(OutputFormatter.finding(
                    "ics", "CRITICAL",
                    "Siemens S7 PLC Accessible",
                    "Siemens S7 PLC responded to ISO-TSAP connection — direct PLC access possible.",
                    recommendation="Block port 102 from all non-authorised hosts. Use industrial firewall.",
                ))
        except Exception as e:
            self.logger.debug(f"S7 probe: {e}")

    def bacnet_probe(self):
        if not self._tcp_open(47808):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(Settings.DEFAULT_TIMEOUT)
                who_is = b"\x81\x0b\x00\x08\x01\x20\xff\xff\x00\xff\x10\x08"
                s.sendto(who_is, (self.target, 47808))
                resp, _ = s.recvfrom(512)
                s.close()
                if resp:
                    self.logger.finding("high", "BACnet device responded on UDP 47808")
                    self.findings.append(OutputFormatter.finding(
                        "ics", "HIGH",
                        "BACnet Device Accessible",
                        "BACnet building automation device responded to Who-Is broadcast.",
                        recommendation="Isolate BACnet devices on a dedicated VLAN with strict access control.",
                    ))
            except Exception:
                pass
            return
        self.logger.section("BACnet TCP Probe")
        self.logger.finding("high", "BACnet TCP port 47808 is open")
        self.findings.append(OutputFormatter.finding(
            "ics", "HIGH",
            "BACnet Port Open",
            "BACnet protocol port 47808 is accessible.",
            recommendation="Restrict BACnet to authorised building management systems only.",
        ))

    def run(self):
        self.logger.section("ICS / SCADA Security Scan")
        self.logger.warning("ICS scans are non-intrusive — passive probes only")
        self.port_sweep()
        self.modbus_probe()
        self.s7_probe()
        self.bacnet_probe()
