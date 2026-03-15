import urllib.request
import urllib.error
from core.utils import OutputFormatter
from config.settings import Settings


class AzureScanner:
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

    def imds(self):
        self.logger.section("Azure IMDS Check")
        url  = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
        body, code = self._fetch(url, headers={"Metadata": "true"})
        if code == 200 and body:
            self.logger.finding("critical", "Azure IMDS endpoint accessible")
            self.findings.append(OutputFormatter.finding(
                "cloud/azure", "CRITICAL",
                "Azure IMDS Accessible",
                "Azure Instance Metadata Service exposed — may leak identity tokens.",
                evidence=body[:300],
                recommendation="Use managed identities. Block IMDS from untrusted network contexts.",
            ))
        else:
            self.logger.info("Azure IMDS not reachable from this context")

    def blob_storage(self):
        self.logger.section("Azure Blob Storage Enumeration")
        domain = self.target.replace("www.", "").split(".")[0]
        accounts = [
            domain, f"{domain}storage", f"{domain}backup",
            f"{domain}dev", f"{domain}prod",
        ]
        containers = ["public", "assets", "data", "files", "uploads", "backup"]
        for account in accounts:
            for container in containers:
                url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
                body, code = self._fetch(url)
                if code == 200 and body and "<EnumerationResults" in body:
                    self.logger.finding("critical", f"Azure blob container public: {account}/{container}")
                    self.findings.append(OutputFormatter.finding(
                        "cloud/azure", "CRITICAL",
                        f"Azure Blob Container Public: {account}/{container}",
                        "Azure blob container allows anonymous listing.",
                        recommendation="Set container access level to Private.",
                    ))

    def run(self):
        self.logger.section("Azure Security Scan")
        self.imds()
        self.blob_storage()
