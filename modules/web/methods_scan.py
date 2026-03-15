import requests
import urllib3
from core.utils import OutputFormatter
from config.settings import Settings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class MethodsScanner:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []
        self.base_url = target if target.startswith("http") else f"http://{target}"
        self.session  = requests.Session()
        self.session.headers["User-Agent"] = Settings.USER_AGENTS[0]
        self.session.verify = False

    def enumerate_methods(self):
        self.logger.section("HTTP Method Enumeration")
        methods = [
            "GET", "POST", "PUT", "DELETE", "PATCH",
            "OPTIONS", "HEAD", "TRACE", "CONNECT",
            "PROPFIND", "MKCOL", "COPY", "MOVE",
            "LOCK", "UNLOCK", "SEARCH",
        ]
        dangerous = {"PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND", "MKCOL"}
        results   = []
        for method in methods:
            try:
                r = self.session.request(
                    method, self.base_url,
                    timeout=Settings.READ_TIMEOUT,
                    verify=False,
                    allow_redirects=False,
                )
                if r.status_code not in [405, 501, 400]:
                    results.append({"method": method, "status": r.status_code})
                    self.logger.success(f"{method:<16} {r.status_code}")
                    if method in dangerous:
                        self.logger.finding("medium", f"Dangerous HTTP method accepted: {method}")
                        self.findings.append(OutputFormatter.finding(
                            "web/methods", "MEDIUM",
                            f"Dangerous HTTP Method Allowed: {method}",
                            f"Server accepts {method} requests.",
                            recommendation=f"Disable {method} unless explicitly required by the application.",
                        ))
            except Exception:
                pass

        if not results:
            self.logger.info("No unusual HTTP methods accepted")
        return results

    def trace_check(self):
        self.logger.section("HTTP TRACE / XST Check")
        try:
            r = self.session.request(
                "TRACE", self.base_url,
                timeout=Settings.READ_TIMEOUT,
                verify=False,
            )
            if r.status_code == 200 and "TRACE" in r.text.upper():
                self.logger.finding("medium", "HTTP TRACE enabled — XST risk")
                self.findings.append(OutputFormatter.finding(
                    "web/methods", "MEDIUM", "HTTP TRACE Enabled",
                    "TRACE method is enabled, enabling Cross-Site Tracing (XST).",
                    recommendation="Disable TRACE in web server configuration.",
                ))
        except Exception:
            pass

    def run(self):
        self.enumerate_methods()
        self.trace_check()
