import os
from config.settings import Settings


class ReportEngine:
    def __init__(self, findings, meta, path, fmt="json"):
        self.findings = findings
        self.meta     = meta
        self.path     = path
        self.fmt      = fmt.lower()

    def save(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)

        if self.fmt == "html":
            from reports.html_report import HTMLReport
            HTMLReport(self.findings, self.meta).save(self.path)
        elif self.fmt == "xml":
            from reports.xml_report import XMLReport
            XMLReport(self.findings, self.meta).save(self.path)
        else:
            from reports.json_report import JSONReport
            JSONReport(self.findings, self.meta).save(self.path)
