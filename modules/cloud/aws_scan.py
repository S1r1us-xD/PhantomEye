import urllib.request
import urllib.error
import json
from core.utils import OutputFormatter
from config.settings import Settings


class AWSScanner:
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

    def imds_v1(self):
        self.logger.section("AWS IMDSv1 Metadata Check")
        url  = "http://169.254.169.254/latest/meta-data/"
        body, code = self._fetch(url)
        if code == 200 and body:
            self.logger.finding("critical", "AWS IMDSv1 metadata endpoint accessible")
            for path in ["iam/security-credentials/", "hostname", "public-ipv4", "ami-id"]:
                d, c = self._fetch(f"http://169.254.169.254/latest/meta-data/{path}")
                if c == 200 and d:
                    self.logger.success(f"  meta-data/{path}: {d[:80]}")
            self.findings.append(OutputFormatter.finding(
                "cloud/aws", "CRITICAL",
                "AWS IMDSv1 Metadata Accessible",
                "SSRF or internal access to 169.254.169.254 can leak IAM credentials.",
                recommendation="Enforce IMDSv2 (require session tokens). Block metadata via host firewall.",
            ))
        else:
            self.logger.info("AWS IMDSv1 endpoint not reachable from this context")

    def s3_bucket_enum(self):
        self.logger.section("S3 Bucket Enumeration")
        domain = self.target.replace("www.", "").split(".")[0]
        candidates = [
            domain, f"{domain}-backup", f"{domain}-dev",
            f"{domain}-prod", f"{domain}-assets",
            f"{domain}-static", f"{domain}-data",
            f"{domain}-files", f"{domain}-uploads",
        ]
        for bucket in candidates:
            url  = f"https://{bucket}.s3.amazonaws.com/"
            body, code = self._fetch(url)
            if code == 200:
                self.logger.finding("critical", f"S3 bucket publicly readable: {bucket}")
                self.findings.append(OutputFormatter.finding(
                    "cloud/aws", "CRITICAL",
                    f"Open S3 Bucket: {bucket}",
                    "S3 bucket allows public listing or read access.",
                    recommendation="Set bucket ACL to private. Remove public bucket policies.",
                ))
            elif code == 403:
                self.logger.success(f"S3 bucket exists but is private: {bucket}")
                self.findings.append(OutputFormatter.finding(
                    "cloud/aws", "INFO",
                    f"S3 Bucket Exists (Private): {bucket}",
                    "Bucket exists but is not publicly accessible.",
                ))
            elif code == 301:
                self.logger.info(f"S3 bucket exists in a different region: {bucket}")

    def run(self):
        self.logger.section("AWS Security Scan")
        self.imds_v1()
        self.s3_bucket_enum()
