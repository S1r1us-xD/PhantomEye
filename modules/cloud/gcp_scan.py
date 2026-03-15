import urllib.request
import urllib.error
from core.utils import OutputFormatter
from config.settings import Settings


class GCPScanner:
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

    def metadata_endpoint(self):
        self.logger.section("GCP Metadata Endpoint Check")
        url  = "http://metadata.google.internal/computeMetadata/v1/?recursive=true"
        body, code = self._fetch(url, headers={"Metadata-Flavor": "Google"})
        if code == 200 and body:
            self.logger.finding("critical", "GCP metadata endpoint accessible")
            self.findings.append(OutputFormatter.finding(
                "cloud/gcp", "CRITICAL",
                "GCP Metadata Endpoint Accessible",
                "GCP compute metadata exposed — service account tokens may be leaked.",
                evidence=body[:300],
                recommendation="Enforce metadata access controls. Use Workload Identity Federation.",
            ))
        else:
            self.logger.info("GCP metadata endpoint not reachable from this context")

    def gcs_bucket_enum(self):
        self.logger.section("GCS Bucket Enumeration")
        domain = self.target.replace("www.", "").split(".")[0]
        candidates = [
            domain, f"{domain}-backup", f"{domain}-assets",
            f"{domain}-data", f"{domain}-public",
        ]
        for bucket in candidates:
            url  = f"https://storage.googleapis.com/{bucket}"
            body, code = self._fetch(url)
            if code == 200 and body and ("<ListBucketResult" in body or "<Contents" in body):
                self.logger.finding("critical", f"GCS bucket publicly accessible: {bucket}")
                self.findings.append(OutputFormatter.finding(
                    "cloud/gcp", "CRITICAL",
                    f"GCS Bucket Public: {bucket}",
                    "Google Cloud Storage bucket allows public listing.",
                    recommendation="Set bucket IAM policy to remove allUsers access.",
                ))
            elif code == 403:
                self.logger.success(f"GCS bucket exists but is private: {bucket}")
                self.findings.append(OutputFormatter.finding(
                    "cloud/gcp", "INFO",
                    f"GCS Bucket Exists (Private): {bucket}",
                    "Bucket exists but public access is restricted.",
                ))

    def run(self):
        self.logger.section("GCP Security Scan")
        self.metadata_endpoint()
        self.gcs_bucket_enum()
