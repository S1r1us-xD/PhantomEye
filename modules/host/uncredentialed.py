import socket
import subprocess
from core.utils import OutputFormatter
from config.settings import Settings


class UncredentialedEnum:
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

    def banner_grab(self):
        self.logger.section("Unauthenticated Banner Grab")
        for port in [21, 22, 23, 25, 80, 110, 143, 443, 3306, 5432, 6379]:
            if not self._port_open(port):
                continue
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(Settings.DEFAULT_TIMEOUT)
                s.connect((self.target, port))
                s.send(b"\r\n")
                banner = s.recv(256).decode("utf-8", "ignore").strip()
                s.close()
                if banner:
                    self.logger.success(f"Port {port}: {banner[:100]}")
                    for sig, cve in Settings.CVE_SIGNATURES.items():
                        if sig.lower() in banner.lower():
                            self.logger.finding("high", f"Port {port} — vulnerable banner: {cve}")
                            self.findings.append(OutputFormatter.finding(
                                "host/uncred", "HIGH",
                                f"Vulnerable Banner on Port {port}",
                                cve, evidence=banner[:100],
                                recommendation="Update the identified software.",
                            ))
            except Exception:
                pass

    def null_auth_services(self):
        self.logger.section("Null / Anonymous Authentication Check")
        checks = []

        if self._port_open(6379):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(Settings.DEFAULT_TIMEOUT)
                s.connect((self.target, 6379))
                s.send(b"PING\r\n")
                resp = s.recv(64).decode("utf-8", "ignore")
                s.close()
                if "+PONG" in resp:
                    self.logger.finding("critical", "Redis accessible without authentication")
                    self.findings.append(OutputFormatter.finding(
                        "host/uncred", "CRITICAL",
                        "Redis Unauthenticated Access",
                        "Redis PING returned PONG without credentials.",
                        recommendation="Set requirepass in redis.conf. Bind to localhost.",
                    ))
            except Exception:
                pass

        if self._port_open(27017):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(Settings.DEFAULT_TIMEOUT)
                s.connect((self.target, 27017))
                s.send(b"\x3f\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00")
                resp = s.recv(256)
                s.close()
                if b"ismaster" in resp or b"ok" in resp:
                    self.logger.finding("critical", "MongoDB accessible without authentication")
                    self.findings.append(OutputFormatter.finding(
                        "host/uncred", "CRITICAL",
                        "MongoDB Unauthenticated Access",
                        "MongoDB responded without credentials.",
                        recommendation="Enable auth in mongod.conf: security.authorization: enabled",
                    ))
            except Exception:
                pass

    def run(self):
        self.logger.section("Unauthenticated Enumeration")
        self.banner_grab()
        self.null_auth_services()
