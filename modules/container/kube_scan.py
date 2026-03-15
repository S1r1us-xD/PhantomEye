import socket
import urllib.request
from core.utils import OutputFormatter
from config.settings import Settings


class KubeScanner:
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

    def _port_open(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(Settings.CONNECT_TIMEOUT)
            r = s.connect_ex((self.target, port))
            s.close()
            return r == 0
        except Exception:
            return False

    def api_server(self):
        self.logger.section("Kubernetes API Server Check")
        checks = [(6443, "https"), (8001, "http"), (8080, "http")]
        for port, scheme in checks:
            if not self._port_open(port):
                continue
            body, code = self._fetch(f"{scheme}://{self.target}:{port}/api/v1/namespaces")
            if code == 200 and body:
                self.logger.finding("critical", f"Kubernetes API unauthenticated — port {port}")
                self.findings.append(OutputFormatter.finding(
                    "container/kube", "CRITICAL",
                    f"Kubernetes API Server Unauthenticated: port {port}",
                    "Unauthenticated k8s API server allows cluster enumeration and takeover.",
                    evidence=body[:200],
                    recommendation="Enable RBAC. Disable anonymous auth. Restrict API server access.",
                ))

            body2, code2 = self._fetch(f"{scheme}://{self.target}:{port}/version")
            if code2 == 200 and body2:
                self.logger.success(f"Kubernetes version info: {body2[:100]}")
                self.findings.append(OutputFormatter.finding(
                    "container/kube", "INFO",
                    "Kubernetes Version Disclosed",
                    "API server version endpoint is publicly accessible.",
                    evidence=body2[:200],
                ))

    def kubelet_api(self):
        self.logger.section("Kubelet API Check")
        for port in [10250, 10255]:
            if not self._port_open(port):
                continue
            body, code = self._fetch(f"https://{self.target}:{port}/pods")
            if code == 200 and body:
                self.logger.finding("critical", f"Kubelet API unauthenticated — port {port}")
                self.findings.append(OutputFormatter.finding(
                    "container/kube", "CRITICAL",
                    f"Kubelet API Unauthenticated: port {port}",
                    "Unauthenticated Kubelet API exposes pod list and enables exec access.",
                    evidence=body[:200],
                    recommendation="Enable Kubelet authentication. Set --anonymous-auth=false.",
                ))
            read_only_body, read_code = self._fetch(f"http://{self.target}:{port}/pods")
            if read_code == 200 and read_only_body:
                self.logger.finding("medium", f"Kubelet read-only port open: {port}")
                self.findings.append(OutputFormatter.finding(
                    "container/kube", "MEDIUM",
                    f"Kubelet Read-Only Port Open: {port}",
                    "Kubelet read-only port exposes pod and node metadata.",
                    recommendation="Disable read-only Kubelet port: --read-only-port=0",
                ))

    def etcd_exposure(self):
        self.logger.section("etcd Exposure Check")
        for port in [2379, 2380]:
            if not self._port_open(port):
                continue
            body, code = self._fetch(f"http://{self.target}:{port}/version")
            if code == 200 and body:
                self.logger.finding("critical", f"etcd unauthenticated on port {port}")
                self.findings.append(OutputFormatter.finding(
                    "container/kube", "CRITICAL",
                    f"etcd Unauthenticated: port {port}",
                    "Unauthenticated etcd exposes all Kubernetes cluster secrets.",
                    evidence=body[:200],
                    recommendation="Enable etcd client TLS authentication. Restrict network access.",
                ))

    def run(self):
        self.logger.section("Kubernetes Security Scan")
        self.api_server()
        self.kubelet_api()
        self.etcd_exposure()
