import json
import datetime
from config.settings import Settings


class JSONReport:
    def __init__(self, findings, meta=None):
        self.findings = findings
        self.meta     = meta or {}

    def _counts(self):
        c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            sev = f.get("severity", "INFO").upper()
            if sev in c:
                c[sev] += 1
        return c

    def build(self):
        return {
            "tool":      Settings.TOOL_NAME,
            "version":   Settings.VERSION,
            "author":    Settings.AUTHOR,
            "generated": datetime.datetime.utcnow().isoformat() + "Z",
            "target":    self.meta.get("host", ""),
            "ip":        self.meta.get("ip", ""),
            "profile":   self.meta.get("profile", "default"),
            "summary":   self._counts(),
            "findings":  self.findings,
        }

    def save(self, path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.build(), f, indent=2, default=str)
