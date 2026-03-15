import sys
import os
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.utils import Logger, Validator, OutputFormatter


class TestValidator(unittest.TestCase):

    def test_is_ip_valid(self):
        self.assertTrue(Validator.is_ip("192.168.1.1"))
        self.assertTrue(Validator.is_ip("10.0.0.1"))
        self.assertTrue(Validator.is_ip("255.255.255.255"))

    def test_is_ip_invalid(self):
        self.assertFalse(Validator.is_ip("999.999.999.999"))
        self.assertFalse(Validator.is_ip("example.com"))
        self.assertFalse(Validator.is_ip("not-an-ip"))

    def test_is_cidr(self):
        self.assertTrue(Validator.is_cidr("192.168.1.0/24"))
        self.assertTrue(Validator.is_cidr("10.0.0.0/8"))
        self.assertFalse(Validator.is_cidr("192.168.1.1"))
        self.assertFalse(Validator.is_cidr("not-a-cidr"))

    def test_is_url(self):
        self.assertTrue(Validator.is_url("http://example.com"))
        self.assertTrue(Validator.is_url("https://example.com/path"))
        self.assertFalse(Validator.is_url("example.com"))
        self.assertFalse(Validator.is_url("ftp://example.com"))

    def test_is_domain(self):
        self.assertTrue(Validator.is_domain("example.com"))
        self.assertTrue(Validator.is_domain("sub.example.com"))
        self.assertFalse(Validator.is_domain("192.168.1.1"))
        self.assertFalse(Validator.is_domain("not a domain"))

    def test_normalize_url(self):
        host, url = Validator.normalize("https://example.com/path")
        self.assertEqual(host, "example.com")
        self.assertIsNotNone(url)

    def test_normalize_ip(self):
        host, url = Validator.normalize("192.168.1.1")
        self.assertEqual(host, "192.168.1.1")
        self.assertIsNone(url)

    def test_normalize_domain(self):
        host, url = Validator.normalize("example.com")
        self.assertEqual(host, "example.com")
        self.assertIsNone(url)

    def test_expand_cidr(self):
        hosts = Validator.expand_cidr("192.168.1.0/30")
        self.assertEqual(len(hosts), 2)
        self.assertIn("192.168.1.1", hosts)
        self.assertIn("192.168.1.2", hosts)

    def test_expand_cidr_invalid(self):
        hosts = Validator.expand_cidr("not-a-cidr")
        self.assertEqual(hosts, [])


class TestOutputFormatter(unittest.TestCase):

    def test_finding_structure(self):
        f = OutputFormatter.finding(
            "test/module", "HIGH", "Test Title",
            "Test description", "evidence here", "fix it",
        )
        self.assertEqual(f["module"],         "test/module")
        self.assertEqual(f["severity"],       "HIGH")
        self.assertEqual(f["title"],          "Test Title")
        self.assertEqual(f["description"],    "Test description")
        self.assertEqual(f["evidence"],       "evidence here")
        self.assertEqual(f["recommendation"], "fix it")
        self.assertIn("timestamp",            f)

    def test_finding_severity_uppercase(self):
        f = OutputFormatter.finding("m", "critical", "t", "d")
        self.assertEqual(f["severity"], "CRITICAL")

    def test_port_entry(self):
        p = OutputFormatter.port_entry(80, "open", "HTTP", "Apache/2.4", "banner")
        self.assertEqual(p["port"],    80)
        self.assertEqual(p["state"],   "open")
        self.assertEqual(p["service"], "HTTP")

    def test_duration_seconds(self):
        import datetime
        start = datetime.datetime(2024, 1, 1, 0, 0, 0)
        end   = datetime.datetime(2024, 1, 1, 0, 0, 45)
        result = OutputFormatter.duration(start, end)
        self.assertIn("45s", result)

    def test_duration_minutes(self):
        import datetime
        start = datetime.datetime(2024, 1, 1, 0, 0, 0)
        end   = datetime.datetime(2024, 1, 1, 0, 2, 30)
        result = OutputFormatter.duration(start, end)
        self.assertIn("2m", result)
        self.assertIn("30s", result)


class TestLogger(unittest.TestCase):

    def test_logger_no_crash(self):
        logger = Logger(no_color=True)
        try:
            logger.info("info message")
            logger.success("success message")
            logger.warning("warning message")
            logger.error("error message")
            logger.finding("critical", "critical finding")
            logger.finding("high", "high finding")
            logger.finding("medium", "medium finding")
            logger.finding("low", "low finding")
            logger.finding("info", "info finding")
            logger.section("Test Section")
            logger.stat("Label", "Value")
            logger.table(["Col1", "Col2"], [["a", "b"], ["c", "d"]])
        except Exception as e:
            self.fail(f"Logger raised: {e}")
        finally:
            logger.close()

    def test_debug_verbose_off(self):
        import io
        from unittest.mock import patch
        logger = Logger(verbose=False, no_color=True)
        with patch("builtins.print") as mock_print:
            logger.debug("should not print")
            mock_print.assert_not_called()
        logger.close()

    def test_debug_verbose_on(self):
        import io
        from unittest.mock import patch
        logger = Logger(verbose=True, no_color=True)
        with patch("builtins.print") as mock_print:
            logger.debug("should print")
            mock_print.assert_called()
        logger.close()


if __name__ == "__main__":
    unittest.main()
