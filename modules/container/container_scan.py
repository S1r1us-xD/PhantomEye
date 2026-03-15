import socket
import urllib.request
from core.utils import OutputFormatter
from config.settings import Settings


class ContainerScanner:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []

    def _fetch(self, url, timeout=5):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": Settings.USER_AGENTS[0]}
            )
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", "ignore"), r.status
        except Exception:
            return None, None

    def docker_api(self):
        self.logger.section("Docker Remote API")
        for port in [2375, 2376, 4243]:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(Settings.CONNECT_TIMEOUT)
            if s.connect_ex((self.target, port)) == 0:
                s.close()
                body, code = self._fetch(f"http://{self.target}:{port}/version")
                if code == 200 and body:
                    self.logger.finding("critical", f"Docker API unauthenticated on port {port}")
                    self.findings.append(OutputFormatter.finding(
                        "container", "CRITICAL",
                        f"Docker API Unauthenticated: port {port}",
                        "Unauthenticated Docker API allows container creation, escape, and RCE.",
                        evidence=body[:300],
                        recommendation="Bind Docker to unix socket only. Add TLS mutual auth for TCP.",
                    ))
                    containers, _ = self._fetch(f"http://{self.target}:{port}/containers/json")
                    if containers:
                        self.logger.success("Container list obtained via unauthenticated API")
            else:
                s.close()

    def registry_exposure(self):
        self.logger.section("Container Registry Exposure")
        for port in [5000, 5001]:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(Settings.CONNECT_TIMEOUT)
            if s.connect_ex((self.target, port)) == 0:
                s.close()
                body, code = self._fetch(f"http://{self.target}:{port}/v2/_catalog")
                if code == 200 and body:
                    self.logger.finding("high", f"Container registry exposed on port {port}")
                    self.findings.append(OutputFormatter.finding(
                        "container", "HIGH",
                        f"Container Registry Unauthenticated: port {port}",
                        "Docker registry accessible without authentication.",
                        evidence=body[:300],
                        recommendation="Add authentication to registry. Restrict via firewall.",
                    ))
            else:
                s.close()

    def run(self):
        self.logger.section("Container Security Scan")
        self.docker_api()
        self.registry_exposure()
