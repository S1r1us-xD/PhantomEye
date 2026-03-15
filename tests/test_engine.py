import sys
import os
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.context import ScanContext
from core.engine import Engine
from core.utils import Logger


def _make_ctx():
    args = MagicMock()
    args.no_color = True
    args.verbose  = False
    args.profile  = "default"
    args.scan_type = "tcp"
    args.output   = None
    logger = Logger(no_color=True)
    ctx    = ScanContext(args, logger)
    ctx.host = "example.com"
    ctx.ip   = "93.184.216.34"
    return ctx


class TestScanContext(unittest.TestCase):

    def test_add_finding(self):
        ctx = _make_ctx()
        ctx.add_finding({"severity": "HIGH", "title": "Test", "module": "test"})
        self.assertEqual(len(ctx.findings), 1)

    def test_add_findings_bulk(self):
        ctx = _make_ctx()
        ctx.add_findings([
            {"severity": "CRITICAL", "title": "A"},
            {"severity": "INFO",     "title": "B"},
        ])
        self.assertEqual(len(ctx.findings), 2)

    def test_severity_counts(self):
        ctx = _make_ctx()
        ctx.add_findings([
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
            {"severity": "INFO"},
        ])
        counts = ctx.severity_counts()
        self.assertEqual(counts["CRITICAL"], 1)
        self.assertEqual(counts["HIGH"],     2)
        self.assertEqual(counts["MEDIUM"],   1)
        self.assertEqual(counts["INFO"],     1)

    def test_open_ports_dedup(self):
        ctx = _make_ctx()
        ctx.add_open_port(80)
        ctx.add_open_port(80)
        ctx.add_open_port(443)
        self.assertEqual(len(ctx.open_ports), 2)

    def test_set_service(self):
        ctx = _make_ctx()
        ctx.set_service(80, "HTTP")
        self.assertEqual(ctx.services[80], "HTTP")


class TestEngine(unittest.TestCase):

    def test_engine_init(self):
        ctx    = _make_ctx()
        engine = Engine(ctx)
        self.assertIsNotNone(engine.profile)

    def test_print_banner_no_error(self):
        ctx    = _make_ctx()
        engine = Engine(ctx)
        try:
            engine.print_banner()
        except Exception as e:
            self.fail(f"print_banner raised: {e}")


if __name__ == "__main__":
    unittest.main()
