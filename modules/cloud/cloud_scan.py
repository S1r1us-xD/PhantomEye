import socket
import urllib.request
import urllib.error
from core.utils import OutputFormatter
from config.settings import Settings


class CloudScanner:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []

    def _fetch(self, url, headers=None, timeout=5):
        try:
            req = urllib.request.Request(
                url,
                headers={**(headers or {}), "User-Agent": Settings.USER_AGENTS[0]},
            )
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", "ignore"), r.status
        except urllib.error.HTTPError as e:
            return "", e.code
        except Exception:
            return None, None

    def docker_api(self):
        self.logger.section("Docker Remote API Exposure")
        for port in [2375, 2376, 4243]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(Settings.CONNECT_TIMEOUT)
                if s.connect_ex((self.target, port)) == 0:
                    s.close()
                    body, code = self._fetch(f"http://{self.target}:{port}/version")
                    if code == 200 and body:
                        self.logger.finding("critical", f"Docker API unauthenticated on port {port}")
                        self.findings.append(OutputFormatter.finding(
                            "cloud", "CRITICAL",
                            f"Docker API Exposed: port {port}",
                            "Unauthenticated Docker API allows full container and host control.",
                            evidence=body[:300],
                            recommendation="Bind Docker to unix socket. Use TLS mutual auth for TCP.",
                        ))
                else:
                    s.close()
            except Exception:
                pass

    def kubernetes_api(self):
        self.logger.section("Kubernetes API Exposure")
        checks = [(6443, "https"), (8001, "http"), (8080, "http")]
        for port, scheme in checks:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(Settings.CONNECT_TIMEOUT)
                if s.connect_ex((self.target, port)) == 0:
                    s.close()
                    body, code = self._fetch(f"{scheme}://{self.target}:{port}/api/v1/namespaces")
                    if code == 200 and body:
                        self.logger.finding("critical", f"Kubernetes API unauthenticated on port {port}")
                        self.findings.append(OutputFormatter.finding(
                            "cloud", "CRITICAL",
                            f"Kubernetes API Exposed: port {port}",
                            "Unauthenticated Kubernetes API allows cluster enumeration and takeover.",
                            evidence=body[:200],
                            recommendation="Enable RBAC. Disable anonymous auth. Restrict API server network access.",
                        ))
                else:
                    s.close()
            except Exception:
                pass

    def run(self):
        self.logger.section("Cloud Security Scan")
        self.docker_api()
        self.kubernetes_api()
