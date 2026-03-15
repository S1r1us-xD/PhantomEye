import sys
import os
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.utils import Logger


def _mock_response(status=200, text="", headers=None, content=b""):
    resp = MagicMock()
    resp.status_code = status
    resp.text        = text
    resp.content     = content or text.encode()
    resp.headers     = headers or {}
    resp.cookies     = []
    resp.url         = "http://example.com/"
    return resp


class TestWebScannerLogic(unittest.TestCase):

    def setUp(self):
        from modules.web.web_scanner import WebScanner
        self.logger  = Logger(no_color=True)
        self.scanner = WebScanner("http://example.com", self.logger)

    def tearDown(self):
        self.logger.close()

    def test_base_url_set(self):
        self.assertEqual(self.scanner.base_url, "http://example.com")

    def test_base_url_prefixed(self):
        from modules.web.web_scanner import WebScanner
        s = WebScanner("example.com", self.logger)
        self.assertEqual(s.base_url, "http://example.com")

    def test_header_analysis_missing_security_headers(self):
        mock_resp = _mock_response(
            status=200,
            headers={"Server": "Apache/2.4.48", "Content-Type": "text/html"},
        )
        with patch.object(self.scanner, "_get", return_value=mock_resp):
            self.scanner.header_analysis()
        missing = [
            f for f in self.scanner.findings
            if "Missing Header" in f.get("title", "")
        ]
        self.assertGreater(len(missing), 0)

    def test_header_analysis_server_cve(self):
        mock_resp = _mock_response(
            status=200,
            headers={"Server": "Apache/2.4.49"},
        )
        with patch.object(self.scanner, "_get", return_value=mock_resp):
            self.scanner.header_analysis()
        cve_findings = [
            f for f in self.scanner.findings
            if "Vulnerable" in f.get("title", "")
        ]
        self.assertGreater(len(cve_findings), 0)

    def test_header_analysis_xpoweredby(self):
        mock_resp = _mock_response(
            status=200,
            headers={"X-Powered-By": "PHP/7.4.0"},
        )
        with patch.object(self.scanner, "_get", return_value=mock_resp):
            self.scanner.header_analysis()
        tech_findings = [
            f for f in self.scanner.findings
            if "X-Powered-By" in f.get("title", "")
        ]
        self.assertGreater(len(tech_findings), 0)


class TestVulnScannerForms(unittest.TestCase):

    def setUp(self):
        from modules.web.vuln_scan import VulnScanner
        self.logger  = Logger(no_color=True)
        self.scanner = VulnScanner("http://example.com", self.logger)

    def tearDown(self):
        self.logger.close()

    def test_get_forms_empty_response(self):
        with patch.object(self.scanner, "_get", return_value=None):
            forms = self.scanner._get_forms()
        self.assertEqual(forms, [])

    def test_get_forms_parses_form(self):
        html = """
        <html><body>
        <form action="/login" method="post">
          <input type="text" name="username">
          <input type="password" name="password">
          <input type="submit" value="Login">
        </form>
        </body></html>
        """
        mock_resp = _mock_response(status=200, text=html)
        with patch.object(self.scanner, "_get", return_value=mock_resp):
            forms = self.scanner._get_forms()
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["method"].lower(), "post")

    def test_sqli_no_response(self):
        with patch.object(self.scanner, "_get", return_value=None):
            result = self.scanner.sqli()
        self.assertEqual(result, [])

    def test_cors_wildcard(self):
        mock_resp = _mock_response(
            status=200,
            headers={"Access-Control-Allow-Origin": "*"},
        )
        with patch.object(self.scanner, "_get", return_value=mock_resp):
            result = self.scanner.cors()
        cors_findings = [
            f for f in self.scanner.findings
            if "CORS" in f.get("title", "")
        ]
        self.assertGreater(len(cors_findings), 0)


class TestDirScanner(unittest.TestCase):

    def setUp(self):
        from modules.web.dir_scan import DirScanner
        self.logger  = Logger(no_color=True)
        self.scanner = DirScanner("http://example.com", self.logger)

    def tearDown(self):
        self.logger.close()

    def test_no_findings_on_404(self):
        mock_resp = _mock_response(status=404)
        with patch.object(self.scanner, "_get", return_value=mock_resp):
            result = self.scanner.directory_bruteforce()
        self.assertEqual(result, [])

    def test_finding_on_200(self):
        mock_resp = _mock_response(status=200, content=b"page content here")

        def side_effect(url):
            if "admin" in url:
                return mock_resp
            return _mock_response(status=404)

        with patch.object(self.scanner, "_get", side_effect=side_effect):
            result = self.scanner.directory_bruteforce()
        self.assertGreater(len(result), 0)


if __name__ == "__main__":
    unittest.main()
