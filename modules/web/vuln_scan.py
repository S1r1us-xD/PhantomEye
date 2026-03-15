import re
import requests
import urllib3
from urllib.parse import urljoin
from core.utils import OutputFormatter
from config.settings import Settings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class VulnScanner:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []
        self.base_url = target if target.startswith("http") else f"http://{target}"
        self.session  = requests.Session()
        self.session.headers["User-Agent"] = Settings.USER_AGENTS[0]
        self.session.verify = False
        self._forms   = None

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

    def _get_forms(self):
        if self._forms is not None:
            return self._forms
        self._forms = []
        resp = self._get(self.base_url)
        if not resp:
            return self._forms
        for fm in re.finditer(r"<form([^>]*)>(.*?)</form>", resp.text, re.DOTALL | re.IGNORECASE):
            attrs = fm.group(1)
            body  = fm.group(2)
            action = re.search(r'action=["\']([^"\']*)["\']', attrs)
            method = re.search(r'method=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            inputs = []
            for inp in re.findall(r"<input([^>]*)>", body, re.IGNORECASE):
                nm = re.search(r'name=["\']([^"\']*)["\']', inp)
                tp = re.search(r'type=["\']([^"\']*)["\']', inp)
                inputs.append({
                    "name": nm.group(1) if nm else "",
                    "type": tp.group(1) if tp else "text",
                })
            act = action.group(1) if action else ""
            if act and not act.startswith("http"):
                act = urljoin(self.base_url, act)
            self._forms.append({
                "action": act or self.base_url,
                "method": method.group(1) if method else "get",
                "inputs": inputs,
            })
        return self._forms

    def sqli(self):
        self.logger.section("SQL Injection")
        SQL_ERRORS = [
            "sql syntax", "mysql_fetch", "ora-", "pg_query", "sqlite3",
            "sqlstate", "unclosed quotation", "microsoft ole db",
            "you have an error in your sql", "division by zero",
            "warning: mysql", "supplied argument is not",
            "invalid query", "odbc driver",
        ]
        found = []
        for form in self._get_forms()[:10]:
            for inp in form["inputs"]:
                if inp.get("type") in ["submit", "button", "hidden", "image"]:
                    continue
                for payload in Settings.SQLI_PAYLOADS:
                    data = {inp["name"]: payload}
                    if form["method"].lower() == "post":
                        resp = self._post(form["action"], data=data)
                    else:
                        resp = self._get(form["action"], params=data)
                    if resp:
                        body = resp.text.lower()
                        for err in SQL_ERRORS:
                            if err in body:
                                self.logger.finding(
                                    "critical",
                                    f"SQLi — {form['action']}  param={inp['name']}",
                                )
                                found.append({"url": form["action"], "param": inp["name"]})
                                self.findings.append(OutputFormatter.finding(
                                    "web/vuln", "CRITICAL", "SQL Injection",
                                    f"SQL error triggered via parameter '{inp['name']}'.",
                                    evidence=f"Payload: {payload}",
                                    recommendation="Use parameterised queries / prepared statements.",
                                ))
                                break
        if not found:
            self.logger.info("No SQL injection vulnerabilities found")
        return found

    def xss(self):
        self.logger.section("Cross-Site Scripting (XSS)")
        found = []
        for form in self._get_forms()[:10]:
            for inp in form["inputs"]:
                if inp.get("type") in ["submit", "button", "hidden", "image"]:
                    continue
                for payload in Settings.XSS_PAYLOADS:
                    data = {inp["name"]: payload}
                    if form["method"].lower() == "post":
                        resp = self._post(form["action"], data=data)
                    else:
                        resp = self._get(form["action"], params=data)
                    if resp and payload in resp.text:
                        self.logger.finding(
                            "high",
                            f"Reflected XSS — {form['action']}  param={inp['name']}",
                        )
                        found.append({"url": form["action"], "param": inp["name"]})
                        self.findings.append(OutputFormatter.finding(
                            "web/vuln", "HIGH", "Reflected XSS",
                            f"Payload reflected unescaped in response via '{inp['name']}'.",
                            evidence=f"Payload: {payload}",
                            recommendation="Encode all user-supplied input in the appropriate output context.",
                        ))
                        break
        if not found:
            self.logger.info("No reflected XSS vulnerabilities found")
        return found

    def lfi(self):
        self.logger.section("Local File Inclusion (LFI)")
        params = ["page", "file", "path", "include", "template", "dir", "doc", "view"]
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
                                f"LFI confirmed — param={param}",
                            )
                            found.append({"param": param, "payload": payload})
                            self.findings.append(OutputFormatter.finding(
                                "web/vuln", "CRITICAL", "Local File Inclusion",
                                f"Server returned sensitive file content via '{param}'.",
                                evidence=f"Payload: {payload}",
                                recommendation="Whitelist allowed file paths. Never pass user input directly to file functions.",
                            ))
                            break
        if not found:
            self.logger.info("No LFI vulnerabilities found")
        return found

    def open_redirect(self):
        self.logger.section("Open Redirect")
        params   = ["url", "redirect", "next", "return", "goto", "target", "dest"]
        payloads = ["https://evil.com", "//evil.com", "/\\evil.com"]
        found    = []
        for param in params:
            for payload in payloads:
                resp = self._get(
                    f"{self.base_url}?{param}={payload}",
                    allow_redirects=False,
                )
                if resp and resp.status_code in [301, 302, 303, 307, 308]:
                    loc = resp.headers.get("Location", "")
                    if "evil.com" in loc:
                        self.logger.finding("high", f"Open redirect — param={param}")
                        found.append({"param": param, "location": loc})
                        self.findings.append(OutputFormatter.finding(
                            "web/vuln", "HIGH", "Open Redirect",
                            f"Redirect to arbitrary external URL via '{param}'.",
                            evidence=f"Location: {loc}",
                            recommendation="Validate redirect destinations against a strict whitelist.",
                        ))
        if not found:
            self.logger.info("No open redirect vulnerabilities found")
        return found

    def ssrf(self):
        self.logger.section("Server-Side Request Forgery (SSRF)")
        params = [
            "url", "src", "dest", "redirect", "uri", "path",
            "file", "fetch", "proxy", "target", "resource",
        ]
        found = []
        for param in params:
            for tgt in Settings.SSRF_TARGETS:
                resp = self._get(f"{self.base_url}?{param}={tgt}")
                if resp:
                    indicators = ["ami-id", "instance-id", "169.254", "root:x:", "public-hostname"]
                    if any(s in resp.text for s in indicators):
                        self.logger.finding("critical", f"SSRF confirmed — param={param}")
                        found.append({"param": param, "target": tgt})
                        self.findings.append(OutputFormatter.finding(
                            "web/vuln", "CRITICAL", "Server-Side Request Forgery (SSRF)",
                            f"Server fetched an internal resource via '{param}'.",
                            evidence=f"Target: {tgt}",
                            recommendation="Whitelist allowed URL destinations. Block internal IP ranges.",
                        ))
        if not found:
            self.logger.info("No SSRF vulnerabilities found")
        return found

    def csrf(self):
        self.logger.section("CSRF Protection Check")
        csrf_tokens = ["csrf", "token", "_token", "authenticity_token", "csrfmiddlewaretoken"]
        found = []
        for form in self._get_forms():
            if form.get("method", "").lower() != "post":
                continue
            has_token = any(
                any(c in inp.get("name", "").lower() for c in csrf_tokens)
                for inp in form["inputs"]
            )
            if not has_token:
                self.logger.finding("high", f"CSRF token missing — {form['action']}")
                found.append(form["action"])
                self.findings.append(OutputFormatter.finding(
                    "web/vuln", "HIGH", "Missing CSRF Token",
                    f"POST form at {form['action']} has no CSRF token.",
                    recommendation="Add synchronised CSRF tokens to all state-changing forms.",
                ))
        if not found:
            self.logger.info("CSRF tokens present in all tested forms")
        return found

    def cors(self):
        self.logger.section("CORS Misconfiguration")
        origins = ["https://evil.com", "null"]
        found   = []
        for origin in origins:
            resp = self._get(self.base_url, headers={"Origin": origin})
            if resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if acao == "*":
                    self.logger.finding("medium", "CORS wildcard ACAO header")
                    found.append({"origin": origin, "acao": acao})
                    self.findings.append(OutputFormatter.finding(
                        "web/vuln", "MEDIUM", "CORS Wildcard Origin",
                        "Access-Control-Allow-Origin: * permits any origin.",
                        recommendation="Restrict CORS to trusted origins.",
                    ))
                elif origin in acao:
                    sev = "critical" if acac.lower() == "true" else "high"
                    self.logger.finding(sev, f"CORS reflects arbitrary origin — ACAC={acac}")
                    found.append({"origin": origin, "acao": acao, "acac": acac})
                    self.findings.append(OutputFormatter.finding(
                        "web/vuln", sev.upper(), "CORS Misconfiguration",
                        f"Server reflects arbitrary Origin header. ACAC={acac}",
                        evidence=f"ACAO: {acao}",
                        recommendation="Validate Origin against a strict allowlist.",
                    ))
        if not found:
            self.logger.info("No CORS misconfigurations found")
        return found

    def run(self):
        self.logger.section("Vulnerability Scan")
        self.sqli()
        self.xss()
        self.lfi()
        self.open_redirect()
        self.ssrf()
        self.csrf()
        self.cors()
