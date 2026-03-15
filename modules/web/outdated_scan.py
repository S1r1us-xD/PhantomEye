import re
import requests
import urllib3
from core.utils import OutputFormatter
from config.settings import Settings
from config.signatures import Signatures

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class OutdatedScanner:
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

    def server_version_check(self):
        self.logger.section("Server Version Fingerprinting")
        resp = self._get(self.base_url)
        if not resp:
            return

        server = resp.headers.get("Server", "")
        xpb    = resp.headers.get("X-Powered-By", "")

        for header_val in [server, xpb]:
            if not header_val:
                continue
            self.logger.stat("Version header", header_val)
            for sig, cve in Settings.CVE_SIGNATURES.items():
                if sig.lower() in header_val.lower():
                    self.logger.finding("high", f"Outdated / vulnerable version: {header_val} — {cve}")
                    self.findings.append(OutputFormatter.finding(
                        "web/outdated", "HIGH",
                        f"Outdated Software: {header_val}",
                        cve,
                        evidence=f"Header value: {header_val}",
                        recommendation="Update to the latest patched release.",
                    ))

    def technology_fingerprint(self):
        self.logger.section("Technology Stack Fingerprint")
        resp = self._get(self.base_url)
        if not resp:
            return

        body  = resp.text
        hdrs  = dict(resp.headers)
        found = []

        for tech, indicators in Signatures.TECH_FINGERPRINTS.items():
            for indicator in indicators:
                if indicator in body or indicator in str(hdrs):
                    found.append(tech)
                    self.logger.success(f"Technology detected: {tech}")
                    break

        if found:
            self.findings.append(OutputFormatter.finding(
                "web/outdated", "INFO",
                "Technology Stack Identified",
                f"Detected: {', '.join(found)}",
                recommendation="Ensure all identified technologies are patched and up to date.",
            ))
        return found

    def wordpress_version(self):
        self.logger.section("WordPress Version Check")
        paths = ["/readme.html", "/wp-includes/version.php", "/?feed=rss2"]
        for path in paths:
            r = self._get(f"{self.base_url}{path}")
            if not r or r.status_code != 200:
                continue
            match = re.search(r'WordPress\s+([\d.]+)', r.text, re.IGNORECASE)
            if match:
                ver = match.group(1)
                self.logger.finding("medium", f"WordPress version disclosed: {ver}")
                self.findings.append(OutputFormatter.finding(
                    "web/outdated", "MEDIUM",
                    f"WordPress Version Disclosed: {ver}",
                    "WordPress version is publicly visible — aids targeted exploitation.",
                    recommendation="Hide WordPress version. Keep core, themes, and plugins updated.",
                ))
                break

    def php_version_disclosure(self):
        self.logger.section("PHP Version Disclosure")
        resp = self._get(self.base_url)
        if not resp:
            return
        xpb = resp.headers.get("X-Powered-By", "")
        match = re.search(r"PHP/([\d.]+)", xpb, re.IGNORECASE)
        if match:
            ver = match.group(1)
            self.logger.finding("medium", f"PHP version disclosed: {ver}")
            eol = any(ver.startswith(v) for v in ["5.", "7.0", "7.1", "7.2", "7.3"])
            sev = "high" if eol else "low"
            self.findings.append(OutputFormatter.finding(
                "web/outdated", sev.upper(),
                f"PHP Version Disclosed: {ver}",
                f"PHP {ver} is {'EOL and' if eol else ''} publicly visible.",
                recommendation="Remove X-Powered-By header. Update PHP to a supported version.",
            ))

    def run(self):
        self.server_version_check()
        self.technology_fingerprint()
        self.wordpress_version()
        self.php_version_disclosure()
