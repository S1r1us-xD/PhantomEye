import sys
import os
import json
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reports.json_report import JSONReport
from reports.xml_report  import XMLReport
from reports.html_report import HTMLReport
from reports.cli_report  import CLIReport
from core.utils import Logger


SAMPLE_FINDINGS = [
    {
        "module":         "web/vuln",
        "severity":       "CRITICAL",
        "title":          "SQL Injection",
        "description":    "SQL injection in login form",
        "evidence":       "payload: '",
        "recommendation": "Use parameterised queries",
        "timestamp":      "2024-01-01T00:00:00Z",
    },
    {
        "module":         "ssl",
        "severity":       "HIGH",
        "title":          "Weak TLS Protocol",
        "description":    "TLSv1.0 accepted",
        "evidence":       "",
        "recommendation": "Disable TLSv1.0",
        "timestamp":      "2024-01-01T00:00:01Z",
    },
    {
        "module":         "web/headers",
        "severity":       "MEDIUM",
        "title":          "Missing CSP Header",
        "description":    "Content-Security-Policy not set",
        "evidence":       "",
        "recommendation": "Add CSP header",
        "timestamp":      "2024-01-01T00:00:02Z",
    },
    {
        "module":         "network/port",
        "severity":       "LOW",
        "title":          "FTP Open",
        "description":    "FTP port 21 open",
        "evidence":       "",
        "recommendation": "Disable FTP",
        "timestamp":      "2024-01-01T00:00:03Z",
    },
    {
        "module":         "osint",
        "severity":       "INFO",
        "title":          "Target IP",
        "description":    "Resolved to 1.2.3.4",
        "evidence":       "",
        "recommendation": "",
        "timestamp":      "2024-01-01T00:00:04Z",
    },
]

SAMPLE_META = {
    "host":    "example.com",
    "ip":      "1.2.3.4",
    "profile": "default",
    "target":  "example.com",
}


class TestJSONReport(unittest.TestCase):

    def test_build_structure(self):
        r    = JSONReport(SAMPLE_FINDINGS, SAMPLE_META)
        data = r.build()
        self.assertEqual(data["tool"],    "PhantomEye")
        self.assertEqual(data["target"],  "example.com")
        self.assertIn("findings",  data)
        self.assertIn("summary",   data)
        self.assertEqual(len(data["findings"]), 5)

    def test_severity_counts(self):
        r      = JSONReport(SAMPLE_FINDINGS, SAMPLE_META)
        data   = r.build()
        counts = data["summary"]
        self.assertEqual(counts["CRITICAL"], 1)
        self.assertEqual(counts["HIGH"],     1)
        self.assertEqual(counts["MEDIUM"],   1)
        self.assertEqual(counts["LOW"],      1)
        self.assertEqual(counts["INFO"],     1)

    def test_save_and_load(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            JSONReport(SAMPLE_FINDINGS, SAMPLE_META).save(path)
            with open(path, "r") as f:
                data = json.load(f)
            self.assertEqual(data["tool"], "PhantomEye")
            self.assertEqual(len(data["findings"]), 5)
        finally:
            os.unlink(path)

    def test_empty_findings(self):
        r    = JSONReport([], SAMPLE_META)
        data = r.build()
        self.assertEqual(data["findings"], [])
        self.assertEqual(sum(data["summary"].values()), 0)


class TestXMLReport(unittest.TestCase):

    def test_save_valid_xml(self):
        import xml.etree.ElementTree as ET
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            path = f.name
        try:
            XMLReport(SAMPLE_FINDINGS, SAMPLE_META).save(path)
            tree = ET.parse(path)
            root = tree.getroot()
            self.assertEqual(root.tag, "phantomeye")
            findings = root.find("findings")
            self.assertIsNotNone(findings)
            self.assertEqual(len(list(findings)), 5)
        finally:
            os.unlink(path)

    def test_summary_counts_in_xml(self):
        import xml.etree.ElementTree as ET
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            path = f.name
        try:
            XMLReport(SAMPLE_FINDINGS, SAMPLE_META).save(path)
            tree    = ET.parse(path)
            root    = tree.getroot()
            summary = root.find("summary")
            self.assertIsNotNone(summary)
            critical = summary.find("critical")
            self.assertEqual(critical.text, "1")
        finally:
            os.unlink(path)


class TestHTMLReport(unittest.TestCase):

    def test_build_contains_target(self):
        r    = HTMLReport(SAMPLE_FINDINGS, SAMPLE_META)
        body = r.build()
        self.assertIn("example.com", body)

    def test_build_contains_severities(self):
        r    = HTMLReport(SAMPLE_FINDINGS, SAMPLE_META)
        body = r.build()
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            self.assertIn(sev, body)

    def test_build_contains_tool_name(self):
        r    = HTMLReport(SAMPLE_FINDINGS, SAMPLE_META)
        body = r.build()
        self.assertIn("PHANTOM", body)
        self.assertIn("EYE", body)

    def test_save_creates_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            path = f.name
        try:
            HTMLReport(SAMPLE_FINDINGS, SAMPLE_META).save(path)
            self.assertTrue(os.path.exists(path))
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("example.com",     content)
        finally:
            os.unlink(path)

    def test_empty_findings_no_crash(self):
        r = HTMLReport([], SAMPLE_META)
        try:
            body = r.build()
            self.assertIn("No findings", body)
        except Exception as e:
            self.fail(f"HTMLReport raised on empty findings: {e}")


class TestCLIReport(unittest.TestCase):

    def test_print_summary_no_crash(self):
        logger = Logger(no_color=True)
        report = CLIReport(SAMPLE_FINDINGS, logger)
        try:
            report.print_summary()
        except Exception as e:
            self.fail(f"CLIReport raised: {e}")
        finally:
            logger.close()

    def test_print_summary_empty(self):
        logger = Logger(no_color=True)
        report = CLIReport([], logger)
        try:
            report.print_summary()
        except Exception as e:
            self.fail(f"CLIReport raised on empty: {e}")
        finally:
            logger.close()


if __name__ == "__main__":
    unittest.main()
