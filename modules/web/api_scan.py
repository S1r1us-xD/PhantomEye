import json
import requests
import urllib3
from core.utils import OutputFormatter
from config.settings import Settings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class APIScanner:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []
        self.base_url = target if target.startswith("http") else f"http://{target}"
        self.session  = requests.Session()
        self.session.headers.update({
            "User-Agent":   Settings.USER_AGENTS[0],
            "Content-Type": "application/json",
            "Accept":       "application/json",
        })
        self.session.verify = False

    def _get(self, url, **kw):
        try:
            return self.session.get(url, timeout=Settings.READ_TIMEOUT, verify=False, **kw)
        except Exception:
            return None

    def _post(self, url, data=None, **kw):
        try:
            return self.session.post(url, json=data, timeout=Settings.READ_TIMEOUT, verify=False, **kw)
        except Exception:
            return None

    def discover_endpoints(self):
        self.logger.section("API Endpoint Discovery")
        paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/v1", "/v2", "/v3", "/rest", "/graphql", "/gql",
            "/api/users", "/api/user", "/api/admin",
            "/api/login", "/api/auth", "/api/token",
            "/api/health", "/api/status", "/api/info",
            "/swagger.json", "/swagger-ui.html", "/openapi.json",
            "/api-docs", "/redoc",
            "/actuator", "/actuator/env", "/actuator/health",
            "/actuator/mappings", "/actuator/beans",
        ]
        found = []
        for path in paths:
            r = self._get(f"{self.base_url}{path}", allow_redirects=False)
            if r and r.status_code not in [404, 410]:
                self.logger.success(f"API endpoint: [{r.status_code}] {path}")
                found.append({"path": path, "status": r.status_code})
                if path in ["/actuator/env", "/actuator/beans", "/actuator/mappings"]:
                    self.logger.finding("high", f"Spring Actuator sensitive endpoint: {path}")
                    self.findings.append(OutputFormatter.finding(
                        "web/api", "HIGH",
                        f"Spring Actuator Exposed: {path}",
                        "Actuator endpoint may leak environment variables, beans, or mappings.",
                        recommendation="Disable or secure actuator endpoints in production.",
                    ))
                if path in ["/swagger.json", "/openapi.json", "/api-docs"]:
                    self.logger.finding("medium", f"API documentation exposed: {path}")
                    self.findings.append(OutputFormatter.finding(
                        "web/api", "MEDIUM", "API Documentation Exposed",
                        f"API schema at {path} reveals all endpoints and parameters.",
                        recommendation="Restrict API docs to authenticated/internal users.",
                    ))
        self.logger.info(f"Discovery complete — {len(found)} endpoint(s) found")
        return found

    def auth_bypass(self):
        self.logger.section("API Authentication Bypass")
        endpoints = ["/api/admin", "/api/users", "/api/v1/admin"]
        bypass_headers = [
            {"X-Original-URL":            "/admin"},
            {"X-Forwarded-For":           "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"Authorization":             "Bearer null"},
            {"Authorization":             "Bearer undefined"},
            {"Authorization":
             "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ."},
        ]
        for ep in endpoints:
            baseline = self._get(f"{self.base_url}{ep}")
            if not baseline:
                continue
            if baseline.status_code == 200:
                self.logger.finding("high", f"API endpoint accessible without auth: {ep}")
                self.findings.append(OutputFormatter.finding(
                    "web/api", "HIGH", "API Endpoint Unauthenticated",
                    f"{ep} returns HTTP 200 without any credentials.",
                    recommendation="Enforce authentication on all API endpoints.",
                ))
                continue
            for hdrs in bypass_headers:
                r = self._get(f"{self.base_url}{ep}", headers=hdrs)
                if r and r.status_code == 200 and baseline.status_code != 200:
                    hdr_name = list(hdrs.keys())[0]
                    self.logger.finding("critical", f"API auth bypass via {hdr_name} — {ep}")
                    self.findings.append(OutputFormatter.finding(
                        "web/api", "CRITICAL", "API Authentication Bypass",
                        f"Authentication bypassed via header '{hdr_name}'.",
                        evidence=f"Endpoint: {ep}",
                        recommendation="Fix server-side auth checks. Never trust client-supplied proxy headers.",
                    ))

    def idor_check(self):
        self.logger.section("IDOR Check")
        endpoints = [
            "/api/users/1", "/api/user/1", "/api/profile/1",
            "/api/orders/1", "/api/v1/users/1",
        ]
        for ep in endpoints:
            r1 = self._get(f"{self.base_url}{ep}")
            r2 = self._get(f"{self.base_url}{ep.rstrip('1')}2")
            if r1 and r2 and r1.status_code == 200 and r2.status_code == 200:
                if r1.text != r2.text:
                    self.logger.finding("high", f"Possible IDOR — {ep}")
                    self.findings.append(OutputFormatter.finding(
                        "web/api", "HIGH", "Possible IDOR",
                        f"Multiple object IDs accessible without authentication at {ep}.",
                        recommendation="Enforce object-level authorisation. Verify ownership server-side.",
                    ))

    def rate_limit_check(self):
        self.logger.section("Rate Limiting Check")
        endpoints = ["/api/login", "/api/auth", "/login", "/auth"]
        for ep in endpoints:
            codes = []
            for i in range(15):
                r = self._post(
                    f"{self.base_url}{ep}",
                    data={"username": "admin", "password": f"pe_probe_{i}"},
                )
                if r:
                    codes.append(r.status_code)
            if codes:
                if not any(c in codes for c in [429, 423, 403]):
                    self.logger.finding(
                        "medium",
                        f"No rate limiting on {ep} — {len(codes)} requests sent without throttle",
                    )
                    self.findings.append(OutputFormatter.finding(
                        "web/api", "MEDIUM", "No Rate Limiting on Login Endpoint",
                        f"Endpoint {ep} does not enforce rate limiting.",
                        recommendation="Implement rate limiting, account lockout, and CAPTCHA.",
                    ))
                else:
                    self.logger.success(f"Rate limiting active on {ep}")
                break

    def graphql_introspection(self):
        self.logger.section("GraphQL Introspection Check")
        gql_endpoints = ["/graphql", "/api/graphql", "/gql", "/query"]
        query = {"query": "{__schema{types{name}}}"}
        for ep in gql_endpoints:
            r = self._post(f"{self.base_url}{ep}", data=query)
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    if "data" in data and "__schema" in str(data):
                        self.logger.finding("medium", f"GraphQL introspection enabled: {ep}")
                        self.findings.append(OutputFormatter.finding(
                            "web/api", "MEDIUM", "GraphQL Introspection Enabled",
                            "Full schema disclosed via introspection query.",
                            recommendation="Disable introspection in production GraphQL endpoints.",
                        ))
                except Exception:
                    pass

    def run(self):
        self.logger.section("API Security Scan")
        self.discover_endpoints()
        self.auth_bypass()
        self.idor_check()
        self.rate_limit_check()
        self.graphql_introspection()
