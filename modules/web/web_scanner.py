import re
import requests
import urllib3
from urllib.parse import urlparse, urljoin
from core.utils import OutputFormatter
from config.settings import Settings
from config.signatures import Signatures

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WebScanner:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []
        self.base_url = target if target.startswith("http") else f"http://{target}"
        self.session  = requests.Session()
        self.session.headers["User-Agent"] = Settings.USER_AGENTS[0]
        self.session.verify = False

    def _get(self, url, **kw):
        try:
            return self.session.get(url, timeout=Settings.READ_TIMEOUT, verify=False, **kw)
        except Exception:
            return None

    def header_analysis(self):
        self.logger.section("HTTP Security Header Analysis")
        resp = self._get(self.base_url)
        if not resp:
            self.logger.error(f"No response from {self.base_url}")
            return {}

        hdrs = dict(resp.headers)
        self.logger.stat("Status",       str(resp.status_code))
        self.logger.stat("Server",       hdrs.get("Server", "N/A"))
        self.logger.stat("Content-Type", hdrs.get("Content-Type", "N/A"))

        hdr_keys_lower = {k.lower() for k in hdrs}
        for hdr in Settings.SECURITY_HEADERS:
            if hdr.lower() not in hdr_keys_lower:
                self.logger.finding("medium", f"Missing security header: {hdr}")
                self.findings.append(OutputFormatter.finding(
                    "web/headers", "MEDIUM",
                    f"Missing Header: {hdr}",
                    f"HTTP response does not include {hdr}.",
                    recommendation=f"Add '{hdr}' to all responses.",
                ))
            else:
                self.logger.success(f"Header present: {hdr}")

        server = hdrs.get("Server", "")
        if server:
            for sig, cve in Settings.CVE_SIGNATURES.items():
                if sig.lower() in server.lower():
                    self.logger.finding("high", f"Vulnerable server: {server} — {cve}")
                    self.findings.append(OutputFormatter.finding(
                        "web/headers", "HIGH", "Vulnerable Server Version", cve,
                        evidence=server,
                        recommendation="Update server software immediately.",
                    ))

        xpb = hdrs.get("X-Powered-By", "")
        if xpb:
            self.logger.finding("low", f"Technology disclosure — X-Powered-By: {xpb}")
            self.findings.append(OutputFormatter.finding(
                "web/headers", "LOW", "Technology Disclosure via X-Powered-By",
                f"Header value: {xpb}",
                recommendation="Remove or obfuscate X-Powered-By.",
            ))

        for cookie in resp.cookies:
            issues = []
            if not cookie.secure:
                issues.append("Secure flag missing")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("HttpOnly flag missing")
            if not cookie.has_nonstandard_attr("SameSite"):
                issues.append("SameSite attribute missing")
            if issues:
                self.logger.finding("medium", f"Cookie '{cookie.name}': {', '.join(issues)}")
                self.findings.append(OutputFormatter.finding(
                    "web/headers", "MEDIUM",
                    f"Insecure Cookie: {cookie.name}",
                    f"Flags missing: {', '.join(issues)}",
                    recommendation="Set Secure, HttpOnly, and SameSite on all session cookies.",
                ))
        return hdrs

    def cms_detect(self):
        self.logger.section("CMS / Framework Detection")
        detected = []
        for cms, sigs in Signatures.CMS_FINGERPRINTS.items():
            for path in sigs.get("paths", []):
                r = self._get(f"{self.base_url}{path}", allow_redirects=True)
                if r and r.status_code in [200, 301, 302, 403]:
                    self.logger.finding("info", f"CMS detected: {cms} (via {path})")
                    detected.append(cms)
                    self.findings.append(OutputFormatter.finding(
                        "web/cms", "INFO", f"CMS Detected: {cms}",
                        f"Path {path} returned HTTP {r.status_code}.",
                        recommendation="Ensure CMS is updated and hardened.",
                    ))
                    break
        return list(set(detected))

    def http_methods(self):
        self.logger.section("HTTP Methods Enumeration")
        try:
            r = self.session.options(
                self.base_url, timeout=Settings.READ_TIMEOUT, verify=False
            )
            allow = r.headers.get("Allow", r.headers.get("Public", ""))
            if allow:
                self.logger.stat("Allow", allow)
                for method in ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]:
                    if method in allow:
                        self.logger.finding("medium", f"Potentially dangerous HTTP method allowed: {method}")
                        self.findings.append(OutputFormatter.finding(
                            "web/methods", "MEDIUM",
                            f"HTTP Method Allowed: {method}",
                            f"Server advertises {method} in Allow header.",
                            recommendation=f"Disable {method} unless explicitly required.",
                        ))
        except Exception:
            pass

    def robots_sitemap(self):
        self.logger.section("robots.txt / sitemap.xml")
        for path in ["/robots.txt", "/sitemap.xml", "/sitemap_index.xml"]:
            r = self._get(f"{self.base_url}{path}")
            if r and r.status_code == 200:
                self.logger.success(f"Found: {path}")
                disallowed = re.findall(r"Disallow:\s*(.+)", r.text)
                for d in disallowed[:10]:
                    self.logger.info(f"  Disallow: {d.strip()}")
                self.findings.append(OutputFormatter.finding(
                    "web/recon", "INFO", f"File Found: {path}",
                    "File exposes path/structure information.",
                    evidence=r.text[:300],
                ))

    def run(self):
        self.logger.section("Web Scanner")
        self.header_analysis()
        self.cms_detect()
        self.http_methods()
        self.robots_sitemap()
