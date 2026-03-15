import requests
import urllib3
from core.utils import OutputFormatter
from config.settings import Settings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class TraversalScanner:
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

    def path_traversal(self):
        self.logger.section("Path Traversal")
        sigs  = ["root:x:", "[boot loader]", "daemon:x:", "[operating systems]"]
        found = []
        for payload in Settings.PATH_TRAVERSAL:
            resp = self._get(self.base_url + payload)
            if resp:
                for sig in sigs:
                    if sig in resp.text:
                        self.logger.finding("critical", f"Path traversal confirmed — payload={payload}")
                        found.append(payload)
                        self.findings.append(OutputFormatter.finding(
                            "web/traversal", "CRITICAL", "Path Traversal",
                            "Server returned sensitive file content via path traversal.",
                            evidence=f"Payload: {payload}",
                            recommendation="Canonicalise paths server-side. Reject '..' sequences.",
                        ))
                        break
        if not found:
            self.logger.info("No path traversal vulnerabilities found")
        return found

    def param_traversal(self):
        self.logger.section("Parameter-Based Path Traversal")
        params = ["file", "path", "page", "dir", "doc", "include", "template", "view"]
        sigs   = ["root:x:", "[boot loader]", "daemon:x:"]
        found  = []
        for param in params:
            for payload in Settings.LFI_PAYLOADS:
                resp = self._get(f"{self.base_url}?{param}={payload}")
                if resp:
                    for sig in sigs:
                        if sig in resp.text:
                            self.logger.finding(
                                "critical",
                                f"Param traversal — param={param}  payload={payload}",
                            )
                            found.append({"param": param, "payload": payload})
                            self.findings.append(OutputFormatter.finding(
                                "web/traversal", "CRITICAL",
                                f"Path Traversal via Parameter: {param}",
                                "Sensitive file contents returned via parameter manipulation.",
                                evidence=f"Payload: {payload}",
                                recommendation="Whitelist allowed file paths. Never pass user input to file functions.",
                            ))
                            break
        if not found:
            self.logger.info("No parameter-based path traversal found")
        return found

    def run(self):
        self.path_traversal()
        self.param_traversal()
