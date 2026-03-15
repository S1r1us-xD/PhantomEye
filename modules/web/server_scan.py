import re
import requests
import urllib3
from core.utils import OutputFormatter
from config.settings import Settings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ServerScanner:
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

    def apache_checks(self):
        self.logger.section("Apache-Specific Checks")
        checks = [
            ("/server-status", "Apache server-status page exposed"),
            ("/server-info",   "Apache server-info page exposed"),
        ]
        for path, msg in checks:
            r = self._get(f"{self.base_url}{path}")
            if r and r.status_code == 200 and ("Apache" in r.text or "Server" in r.text):
                self.logger.finding("high", msg)
                self.findings.append(OutputFormatter.finding(
                    "web/server", "HIGH", msg,
                    f"Path {path} reveals server configuration and process information.",
                    recommendation=f"Restrict access to {path} via Apache config or firewall.",
                ))

        r = self._get(f"{self.base_url}/.htaccess")
        if r and r.status_code == 200:
            self.logger.finding("high", ".htaccess file accessible")
            self.findings.append(OutputFormatter.finding(
                "web/server", "HIGH", ".htaccess File Accessible",
                "Apache .htaccess file is publicly readable.",
                recommendation="Deny access to .htaccess via server configuration.",
            ))

    def nginx_checks(self):
        self.logger.section("Nginx-Specific Checks")
        alias_paths = [
            "/static../etc/passwd",
            "/files../etc/passwd",
            "/images../etc/passwd",
        ]
        for path in alias_paths:
            r = self._get(f"{self.base_url}{path}")
            if r and "root:x:" in r.text:
                self.logger.finding("critical", f"Nginx alias traversal confirmed: {path}")
                self.findings.append(OutputFormatter.finding(
                    "web/server", "CRITICAL", "Nginx Alias Path Traversal",
                    "Misconfigured Nginx alias directive allows path traversal.",
                    evidence=f"Path: {path}",
                    recommendation="Ensure alias directives end with a trailing slash.",
                ))

    def iis_checks(self):
        self.logger.section("IIS-Specific Checks")
        r = self._get(self.base_url)
        if not r:
            return
        server = r.headers.get("Server", "")
        if "IIS" not in server:
            return

        self.logger.info(f"IIS detected: {server}")
        iis_paths = [
            "/trace.axd",
            "/elmah.axd",
            "/glimpse.axd",
            "/web.config",
            "/App_Data/",
        ]
        for path in iis_paths:
            rp = self._get(f"{self.base_url}{path}")
            if rp and rp.status_code not in [404, 403]:
                self.logger.finding("high", f"Sensitive IIS path accessible: {path}")
                self.findings.append(OutputFormatter.finding(
                    "web/server", "HIGH",
                    f"Sensitive IIS Path: {path}",
                    f"IIS-specific path {path} returned HTTP {rp.status_code}.",
                    recommendation=f"Restrict access to {path} in IIS configuration.",
                ))

    def directory_listing(self):
        self.logger.section("Directory Listing Check")
        test_paths = ["/images/", "/uploads/", "/static/", "/files/", "/css/", "/js/"]
        sigs = [
            "Index of /", "Directory listing for", "Parent Directory",
            "<title>Index of", "[DIR]",
        ]
        for path in test_paths:
            r = self._get(f"{self.base_url}{path}")
            if r and r.status_code == 200:
                for sig in sigs:
                    if sig in r.text:
                        self.logger.finding("medium", f"Directory listing enabled: {path}")
                        self.findings.append(OutputFormatter.finding(
                            "web/server", "MEDIUM",
                            f"Directory Listing Enabled: {path}",
                            "Web server returns a directory listing instead of an error.",
                            recommendation="Disable directory listing in web server configuration.",
                        ))
                        break

    def clickjacking_check(self):
        self.logger.section("Clickjacking Protection Check")
        r = self._get(self.base_url)
        if not r:
            return
        xfo = r.headers.get("X-Frame-Options", "")
        csp = r.headers.get("Content-Security-Policy", "")
        if not xfo and "frame-ancestors" not in csp.lower():
            self.logger.finding("medium", "No clickjacking protection (X-Frame-Options / CSP frame-ancestors)")
            self.findings.append(OutputFormatter.finding(
                "web/server", "MEDIUM", "Clickjacking Protection Missing",
                "No X-Frame-Options or CSP frame-ancestors directive found.",
                recommendation="Set X-Frame-Options: DENY or add frame-ancestors to CSP.",
            ))

    def run(self):
        self.logger.section("Server-Specific Checks")
        self.apache_checks()
        self.nginx_checks()
        self.iis_checks()
        self.directory_listing()
        self.clickjacking_check()
