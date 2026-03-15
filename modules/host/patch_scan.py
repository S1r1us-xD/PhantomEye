import subprocess
from core.utils import OutputFormatter


class PatchScan:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []

    def _cmd(self, cmd, timeout=30):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout.strip(), r.returncode
        except Exception:
            return "", -1

    def pending_updates(self):
        self.logger.section("Pending Package Updates")

        out, rc = self._cmd(["apt-get", "-s", "upgrade", "--just-print"])
        if out:
            count = out.count("Inst ")
            if count > 0:
                self.logger.finding("medium", f"{count} pending package update(s) via apt")
                self.findings.append(OutputFormatter.finding(
                    "host/patch", "MEDIUM",
                    f"{count} Pending Updates (apt)",
                    "System packages have available updates.",
                    recommendation="Run: apt-get update && apt-get upgrade",
                ))
            else:
                self.logger.success("System packages are up to date (apt)")
            return

        out, rc = self._cmd(["yum", "check-update"])
        if out:
            lines = [
                l for l in out.splitlines()
                if l and not l.startswith((" ", "\t", "Last", "Loading", "Loaded"))
            ]
            if lines:
                self.logger.finding("medium", f"{len(lines)} pending update(s) via yum/dnf")
                self.findings.append(OutputFormatter.finding(
                    "host/patch", "MEDIUM",
                    f"{len(lines)} Pending Updates (yum)",
                    "System packages have available updates.",
                    recommendation="Run: yum update",
                ))
            return

        self.logger.info("No supported package manager detected (apt/yum)")

    def kernel_cve_correlation(self):
        self.logger.section("Kernel CVE Correlation")
        out, _ = self._cmd(["uname", "-r"])
        if not out:
            return

        self.logger.stat("Kernel", out)

        kernel_cves = {
            "5.8":  ["CVE-2021-3490 — eBPF LPE", "CVE-2021-3492 — Shiftfs LPE"],
            "5.4":  ["CVE-2021-22555 — Netfilter heap OOB", "CVE-2021-3156 — sudo Baron Samedit"],
            "4.19": ["CVE-2020-14386 — AF_PACKET LPE", "CVE-2019-14287 — sudo bypass"],
            "4.15": ["CVE-2018-18955 — nested userns LPE"],
            "4.4":  ["CVE-2017-6074 — DCCP double-free LPE", "CVE-2016-5195 — Dirty COW"],
            "3.":   ["CVE-2016-5195 — Dirty COW", "CVE-2015-1701 — Win32k LPE"],
        }

        ver = ".".join(out.split(".")[:2])
        for kver, cves in kernel_cves.items():
            if out.startswith(kver):
                for cve in cves:
                    self.logger.finding("high", f"Kernel {out} — associated CVE: {cve}")
                    self.findings.append(OutputFormatter.finding(
                        "host/patch", "HIGH",
                        f"Kernel CVE: {cve}",
                        f"Kernel {out} is associated with a known privilege escalation vulnerability.",
                        recommendation="Update kernel immediately.",
                    ))

    def installed_packages_audit(self):
        self.logger.section("Installed Package Audit")
        risky_packages = [
            "netcat", "ncat", "nmap", "masscan", "hydra",
            "john", "hashcat", "metasploit", "aircrack-ng",
            "wireshark", "tcpdump",
        ]
        out, _ = self._cmd(["dpkg", "-l"])
        if not out:
            out, _ = self._cmd(["rpm", "-qa"])

        if out:
            for pkg in risky_packages:
                if pkg in out.lower():
                    self.logger.finding("low", f"Security tool installed: {pkg}")
                    self.findings.append(OutputFormatter.finding(
                        "host/patch", "LOW",
                        f"Security Tool Present: {pkg}",
                        f"Package '{pkg}' is installed — verify this is authorised.",
                        recommendation="Remove unauthorised offensive security tools.",
                    ))

    def run(self):
        self.pending_updates()
        self.kernel_cve_correlation()
        self.installed_packages_audit()
