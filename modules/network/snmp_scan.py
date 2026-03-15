import socket
import struct
from core.utils import OutputFormatter
from config.settings import Settings


class SNMPScanner:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []

    def _build_get_request(self, community, oid=b"\x01\x01\x00"):
        comm  = community.encode() if isinstance(community, str) else community
        oid_t = b"\x06\x01" + oid
        varbind = b"\x30" + bytes([len(oid_t) + 2]) + oid_t + b"\x05\x00"
        pdu  = b"\xa0" + bytes([len(varbind) + 9]) + b"\x02\x01\x01\x02\x01\x00\x02\x01\x00" + varbind
        body = b"\x02\x01\x01\x04" + bytes([len(comm)]) + comm + pdu
        return b"\x30" + bytes([len(body)]) + body

    def community_sweep(self):
        self.logger.section("SNMP Community String Sweep")
        found = []
        for community in Settings.SNMP_COMMUNITIES:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2)
                pkt = self._build_get_request(community)
                s.sendto(pkt, (self.target, 161))
                resp, _ = s.recvfrom(1024)
                s.close()
                if resp and len(resp) > 10:
                    self.logger.finding("high", f"SNMP community string accepted: '{community}'")
                    found.append(community)
                    self.findings.append(OutputFormatter.finding(
                        "network/snmp", "HIGH",
                        f"SNMP Community String: '{community}'",
                        f"SNMP responding to community string '{community}'.",
                        recommendation="Use SNMPv3 with authentication and encryption. "
                                       "Change default community strings.",
                    ))
            except socket.timeout:
                pass
            except Exception:
                pass

        if not found:
            self.logger.info("No SNMP community strings accepted (or port closed)")
        return found

    def snmpwalk(self, community="public"):
        self.logger.section(f"SNMP Walk — community='{community}'")
        try:
            r_cmd = ["snmpwalk", "-v2c", "-c", community, self.target, "1.3.6.1.2.1.1"]
            import subprocess
            r = subprocess.run(r_cmd, capture_output=True, text=True, timeout=20)
            if r.stdout.strip():
                for line in r.stdout.splitlines()[:20]:
                    self.logger.success(f"  {line[:120]}")
                self.findings.append(OutputFormatter.finding(
                    "network/snmp", "MEDIUM", "SNMP System Info Disclosed",
                    f"SNMP walk returned system information with community '{community}'.",
                    evidence=r.stdout[:600],
                    recommendation="Restrict SNMP to management hosts only. Use SNMPv3.",
                ))
        except FileNotFoundError:
            self.logger.debug("snmpwalk not installed")
        except Exception as e:
            self.logger.debug(f"snmpwalk: {e}")

    def run(self):
        found = self.community_sweep()
        if found:
            self.snmpwalk(found[0])
