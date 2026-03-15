import os
import json
import subprocess
from core.utils import OutputFormatter


class DockerScanner:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []

    def _cmd(self, cmd, timeout=15):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout.strip(), r.returncode
        except FileNotFoundError:
            return "", 127
        except Exception:
            return "", -1

    def local_audit(self):
        self.logger.section("Local Docker Container Audit")
        out, rc = self._cmd(["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}"])
        if rc == 127:
            self.logger.info("Docker CLI not installed — skipping local audit")
            return
        if rc != 0 or not out.strip():
            self.logger.info("No running containers or Docker daemon not accessible")
            return

        self.logger.info(f"Running containers:\n{out[:400]}")
        for line in out.strip().splitlines():
            parts = line.split("\t")
            if len(parts) >= 1:
                self._inspect_container(parts[0])

    def _inspect_container(self, name):
        out, rc = self._cmd(["docker", "inspect", name])
        if rc != 0 or not out:
            return
        try:
            config = json.loads(out)
            if not config:
                return
            c  = config[0]
            hc = c.get("HostConfig", {})

            if hc.get("Privileged"):
                self.logger.finding("critical", f"Privileged container: {name}")
                self.findings.append(OutputFormatter.finding(
                    "container/docker", "CRITICAL",
                    f"Privileged Container: {name}",
                    "Privileged containers have unrestricted access to the host kernel.",
                    recommendation="Remove --privileged. Use specific capabilities instead.",
                ))

            for mount in c.get("Mounts", []):
                src = mount.get("Source", "")
                if src in ["/", "/etc", "/var/run/docker.sock", "/proc", "/sys", "/root"]:
                    self.logger.finding("critical", f"Dangerous volume mount in {name}: {src}")
                    self.findings.append(OutputFormatter.finding(
                        "container/docker", "CRITICAL",
                        f"Dangerous Volume Mount in {name}: {src}",
                        f"Container mounts sensitive host path {src}.",
                        recommendation="Never mount sensitive host paths into containers.",
                    ))

            net_mode = hc.get("NetworkMode", "")
            if net_mode == "host":
                self.logger.finding("high", f"Container {name} uses host network mode")
                self.findings.append(OutputFormatter.finding(
                    "container/docker", "HIGH",
                    f"Host Network Mode: {name}",
                    "Container shares host network namespace — no network isolation.",
                    recommendation="Use bridge networking unless host mode is explicitly required.",
                ))

        except (json.JSONDecodeError, KeyError, IndexError):
            pass

    def docker_sock(self):
        self.logger.section("Docker Socket Check")
        sock_path = "/var/run/docker.sock"
        if os.path.exists(sock_path):
            perms = oct(os.stat(sock_path).st_mode)
            self.logger.finding("high", f"Docker socket present: {sock_path}  perms={perms}")
            self.findings.append(OutputFormatter.finding(
                "container/docker", "HIGH",
                "Docker Socket Accessible",
                f"Docker socket exists at {sock_path} with permissions {perms}.",
                recommendation="Restrict socket permissions. Never mount docker.sock into containers.",
            ))

    def run(self):
        self.local_audit()
        self.docker_sock()
