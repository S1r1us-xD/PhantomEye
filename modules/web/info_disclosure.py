import re
import requests
import urllib3
from core.utils import OutputFormatter
from config.settings import Settings
from config.signatures import Signatures

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class InfoDisclosure:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []
        self.base_url = target if target.startswith("http") else f"http://{target}"
        self.session  = requests.Session()
        self.session.headers["User-Agent"] = Settings.USER_AGENTS[0]
        self.session.verify = False

    def _get(self, url):
        try:
            return self.session.get(url, timeout=Settings.READ_TIMEOUT, verify=False)
        except Exception:
            return None

    def git_exposure(self):
        self.logger.section("VCS / Git Exposure")
        paths = [
            "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG",
            "/.svn/entries", "/.hg/hgrc", "/.bzr/branch-format",
        ]
        for path in paths:
            r = self._get(f"{self.base_url}{path}")
            if r and r.status_code == 200 and len(r.content) > 0:
                self.logger.finding("critical", f"VCS metadata exposed: {path}")
                self.findings.append(OutputFormatter.finding(
                    "web/info", "CRITICAL",
                    f"VCS Metadata Exposed: {path}",
                    "Source control metadata is publicly accessible — source code may be downloadable.",
                    evidence=r.text[:200],
                    recommendation="Block /.git, /.svn in web server config. Never deploy VCS metadata.",
                ))

    def env_exposure(self):
        self.logger.section("Environment / Config File Exposure")
        paths = [
            "/.env", "/.env.local", "/.env.production", "/.env.backup",
            "/config.php", "/config.yml", "/.aws/credentials", "/app.config",
            "/application.properties", "/database.yml",
        ]
        for path in paths:
            r = self._get(f"{self.base_url}{path}")
            if r and r.status_code == 200:
                keywords = ["PASSWORD", "SECRET", "KEY", "TOKEN", "DATABASE", "API_KEY", "PRIVATE"]
                if any(k in r.text.upper() for k in keywords):
                    self.logger.finding("critical", f"Sensitive config file accessible: {path}")
                    self.findings.append(OutputFormatter.finding(
                        "web/info", "CRITICAL",
                        f"Sensitive File Exposed: {path}",
                        "Configuration file is publicly accessible and may contain credentials.",
                        evidence=r.text[:200],
                        recommendation="Remove file from webroot. Restrict via web server config.",
                    ))

    def source_map_exposure(self):
        self.logger.section("JavaScript Source Map Exposure")
        js_paths = [
            "/static/app.js", "/assets/app.js", "/js/app.js",
            "/bundle.js", "/main.js", "/dist/app.js",
        ]
        for jspath in js_paths:
            r = self._get(f"{self.base_url}{jspath}")
            if r and "sourceMappingURL" in r.text:
                match = re.search(r"sourceMappingURL=(.+\.map)", r.text)
                if match:
                    map_url = f"{self.base_url}/{match.group(1).strip()}"
                    mr = self._get(map_url)
                    if mr and mr.status_code == 200:
                        self.logger.finding("medium", f"JS source map exposed: {map_url}")
                        self.findings.append(OutputFormatter.finding(
                            "web/info", "MEDIUM", "JavaScript Source Map Exposed",
                            "Source map allows reconstruction of original source code.",
                            recommendation="Remove .map files from production deployments.",
                        ))

    def error_page_leakage(self):
        self.logger.section("Error Page Information Leakage")
        probes = [
            f"{self.base_url}/pe_nonexistent_probe",
            f"{self.base_url}/'",
            f"{self.base_url}/%00",
        ]
        for url in probes:
            r = self._get(url)
            if r:
                for ptype, patterns in Signatures.DISCLOSURE_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, r.text, re.IGNORECASE):
                            self.logger.finding(
                                "medium",
                                f"Error page leaks {ptype} at {url}",
                            )
                            self.findings.append(OutputFormatter.finding(
                                "web/info", "MEDIUM",
                                f"Error Page Leakage: {ptype}",
                                "Detailed error messages expose stack traces or internal paths.",
                                evidence=r.text[:300],
                                recommendation="Disable verbose error messages in production.",
                            ))
                            break

    def backup_files(self):
        self.logger.section("Backup & Temporary File Detection")
        exts  = [".bak", ".old", ".backup", ".orig", ".copy", "~", ".tmp", ".swp"]
        pages = ["index", "login", "admin", "config", "database", "app", "main"]
        found = []
        for page in pages:
            for ext in exts:
                r = self._get(f"{self.base_url}/{page}{ext}")
                if r and r.status_code == 200 and len(r.content) > 0:
                    self.logger.finding("high", f"Backup file accessible: /{page}{ext}")
                    found.append(f"/{page}{ext}")
                    self.findings.append(OutputFormatter.finding(
                        "web/info", "HIGH",
                        f"Backup File Found: /{page}{ext}",
                        "Backup file may contain source code or sensitive configuration.",
                        recommendation="Remove all backup files from webroot.",
                    ))
        if not found:
            self.logger.info("No backup files found")

    def run(self):
        self.logger.section("Information Disclosure")
        self.git_exposure()
        self.env_exposure()
        self.source_map_exposure()
        self.error_page_leakage()
        self.backup_files()
