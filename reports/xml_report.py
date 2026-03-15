import xml.etree.ElementTree as ET
import datetime
from config.settings import Settings


class XMLReport:
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

    def save(self, path):
        root = ET.Element(
            "phantomeye",
            version=Settings.VERSION,
            author=Settings.AUTHOR,
            generated=datetime.datetime.utcnow().isoformat() + "Z",
            target=self.meta.get("host", ""),
            ip=self.meta.get("ip", ""),
            profile=self.meta.get("profile", "default"),
        )

        counts = self._counts()
        sm = ET.SubElement(root, "summary")
        for k, v in counts.items():
            ET.SubElement(sm, k.lower()).text = str(v)

        fs = ET.SubElement(root, "findings")
        for f in self.findings:
            fe = ET.SubElement(fs, "finding")
            for key in ["module", "severity", "title", "description",
                        "evidence", "recommendation", "timestamp"]:
                ET.SubElement(fe, key).text = str(f.get(key, ""))

        tree = ET.ElementTree(root)
        ET.indent(tree, space="  ")
        tree.write(path, encoding="unicode", xml_declaration=True)
