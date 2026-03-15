import time
import random
import string
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.utils import OutputFormatter
from config.settings import Settings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Fuzzer:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []
        self.base_url = target if target.startswith("http") else f"http://{target}"
        self.threads  = Settings.MAX_THREADS
        self.session  = requests.Session()
        self.session.headers["User-Agent"] = Settings.USER_AGENTS[0]
        self.session.verify = False

    def _get(self, url, **kw):
        try:
            return self.session.get(url, timeout=Settings.READ_TIMEOUT, verify=False, **kw)
        except Exception:
            return None

    def _post(self, url, data=None, **kw):
        try:
            return self.session.post(url, data=data, timeout=Settings.READ_TIMEOUT, verify=False, **kw)
        except Exception:
            return None

    def param_discovery(self):
        self.logger.section("Parameter Discovery")
        params = [
            "id", "page", "search", "q", "user", "email", "file", "path",
            "url", "redirect", "type", "action", "cmd", "command", "exec",
            "debug", "admin", "lang", "ref", "source", "callback", "format",
            "sort", "order", "limit", "name", "value", "data", "input",
            "content", "body", "title", "code", "token", "key", "api_key",
            "uid", "session", "hash", "sig", "payload",
        ]
        found = []
        baseline = self._get(self.base_url)
        blen     = len(baseline.content) if baseline else 0

        for param in params:
            marker = "pe_" + "".join(random.choices(string.ascii_lowercase, k=6))
            resp   = self._get(f"{self.base_url}?{param}={marker}")
            if resp:
                diff = abs(len(resp.content) - blen)
                if diff > 50 or (baseline and resp.status_code != baseline.status_code):
                    found.append(param)
                    self.logger.success(f"Responsive parameter: {param}  diff={diff}b  status={resp.status_code}")
                    if marker in resp.text:
                        self.logger.finding("high", f"Input reflected — {param} is injection candidate")
                        self.findings.append(OutputFormatter.finding(
                            "fuzzer", "HIGH",
                            f"Reflected Parameter: {param}",
                            f"User input in '{param}' is reflected in the HTTP response.",
                            recommendation="Test for XSS and injection. Sanitise all reflected inputs.",
                        ))

        self.logger.info(f"Parameter discovery complete — {len(found)} responsive parameter(s)")
        return found

    def http_method_fuzz(self):
        self.logger.section("HTTP Method Enumeration")
        methods = [
            "GET", "POST", "PUT", "DELETE", "PATCH",
            "OPTIONS", "HEAD", "TRACE", "CONNECT",
            "PROPFIND", "MKCOL", "COPY", "MOVE",
            "LOCK", "UNLOCK", "FAKE_METHOD",
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
                if r.status_code not in [405, 501]:
                    results.append({"method": method, "status": r.status_code})
                    self.logger.success(f"{method:<18} {r.status_code}")
                    if method in dangerous:
                        self.logger.finding("medium", f"Dangerous HTTP method accepted: {method}")
                        self.findings.append(OutputFormatter.finding(
                            "fuzzer", "MEDIUM",
                            f"HTTP Method Allowed: {method}",
                            f"Server accepts {method} requests.",
                            recommendation=f"Disable {method} unless explicitly required.",
                        ))
            except Exception:
                pass
        return results

    def path_traversal_fuzz(self):
        self.logger.section("Path Traversal Fuzzing")
        sigs  = ["root:x:", "[boot loader]", "daemon:x:", "[operating systems]"]
        found = []
        for payload in Settings.PATH_TRAVERSAL:
            resp = self._get(self.base_url + payload)
            if resp:
                for sig in sigs:
                    if sig in resp.text:
                        self.logger.finding("critical", f"Path traversal confirmed — payload: {payload}")
                        found.append(payload)
                        self.findings.append(OutputFormatter.finding(
                            "fuzzer", "CRITICAL",
                            "Path Traversal Confirmed",
                            "Server returned sensitive file content via path traversal payload.",
                            evidence=f"Payload: {payload}",
                            recommendation="Canonicalise all paths server-side. Reject '..' sequences.",
                        ))
                        break
        if not found:
            self.logger.info("No path traversal vulnerabilities found")
        return found

    def command_injection_fuzz(self):
        self.logger.section("Command Injection Fuzzing")
        params = ["cmd", "exec", "command", "ping", "host", "ip", "query", "input", "run", "shell"]
        found  = []
        for param in params:
            for payload in Settings.CMD_PAYLOADS:
                start   = time.time()
                resp    = self._get(f"{self.base_url}?{param}={payload}")
                elapsed = time.time() - start
                if resp:
                    body = resp.text.lower()
                    if any(s in body for s in ["uid=", "root:", "daemon:", "www-data"]):
                        self.logger.finding("critical", f"Command injection — param={param}")
                        found.append({"param": param, "payload": payload})
                        self.findings.append(OutputFormatter.finding(
                            "fuzzer", "CRITICAL",
                            f"Command Injection: {param}",
                            "Server executed OS command and returned output in response.",
                            evidence=f"Payload: {payload}",
                            recommendation="Never pass user input to OS-level functions.",
                        ))
                    elif "sleep" in payload and elapsed >= 4.5:
                        self.logger.finding("high", f"Blind command injection (time-based) — param={param}  delay={elapsed:.1f}s")
                        found.append({"param": param, "payload": payload, "blind": True})
                        self.findings.append(OutputFormatter.finding(
                            "fuzzer", "HIGH",
                            f"Blind Command Injection: {param}",
                            f"Response delayed {elapsed:.1f}s after sleep payload.",
                            recommendation="Sanitise all inputs passed to OS-level functions.",
                        ))
        if not found:
            self.logger.info("No command injection found")
        return found

    def header_injection_fuzz(self):
        self.logger.section("Header Injection Fuzzing")
        payloads = [
            "\r\nX-Pe-Injected: pe",
            "\nX-Pe-Injected: pe",
            "%0d%0aX-Pe-Injected: pe",
            "%0aX-Pe-Injected: pe",
        ]
        headers_to_test = ["User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host"]
        found = []
        for hdr in headers_to_test:
            for payload in payloads:
                try:
                    resp = self.session.get(
                        self.base_url,
                        headers={hdr: payload},
                        timeout=Settings.READ_TIMEOUT,
                        verify=False,
                    )
                    if resp and "X-Pe-Injected" in resp.headers:
                        self.logger.finding("high", f"Header injection confirmed via {hdr}")
                        found.append({"header": hdr, "payload": payload})
                        self.findings.append(OutputFormatter.finding(
                            "fuzzer", "HIGH",
                            f"HTTP Header Injection: {hdr}",
                            "CRLF-injected header appears in the HTTP response.",
                            recommendation="Strip CRLF sequences from all header input values.",
                        ))
                except Exception:
                    pass
        if not found:
            self.logger.info("No header injection points detected")
        return found

    def ssti_fuzz(self):
        self.logger.section("Server-Side Template Injection (SSTI)")
        payloads = {
            "{{7*7}}":          "49",
            "${7*7}":           "49",
            "#{7*7}":           "49",
            "<%= 7*7 %>":       "49",
            "{{7*'7'}}":        "7777777",
            "${{7*7}}":         "49",
        }
        params = ["name", "template", "msg", "message", "input", "content", "q", "search"]
        found  = []
        for param in params:
            for payload, expected in payloads.items():
                resp = self._get(f"{self.base_url}?{param}={payload}")
                if resp and expected in resp.text:
                    self.logger.finding("critical", f"SSTI confirmed — param={param}  payload={payload}")
                    found.append({"param": param, "payload": payload})
                    self.findings.append(OutputFormatter.finding(
                        "fuzzer", "CRITICAL",
                        f"Server-Side Template Injection: {param}",
                        f"Template expression was evaluated server-side via '{param}'.",
                        evidence=f"Payload: {payload}  Expected: {expected}",
                        recommendation="Never render user input as a template. Use sandboxed rendering.",
                    ))
                    break
        if not found:
            self.logger.info("No SSTI vulnerabilities found")
        return found

    def run(self):
        self.logger.section("HTTP Fuzzer")
        self.param_discovery()
        self.http_method_fuzz()
        self.path_traversal_fuzz()
        self.command_injection_fuzz()
        self.header_injection_fuzz()
        self.ssti_fuzz()
