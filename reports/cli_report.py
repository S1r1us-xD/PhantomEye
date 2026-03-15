from core.utils import Colors


class CLIReport:
    SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    def __init__(self, findings, logger):
        self.findings = findings
        self.logger   = logger

    def print_summary(self):
        if not self.findings:
            return

        self.logger.section("Findings Summary")

        grouped = {s: [] for s in self.SEV_ORDER}
        for f in self.findings:
            sev = f.get("severity", "INFO").upper()
            if sev in grouped:
                grouped[sev].append(f)

        for sev in self.SEV_ORDER:
            items = grouped[sev]
            if not items:
                continue
            for f in items:
                module = f.get("module", "")
                title  = f.get("title", "")
                self.logger.finding(sev.lower(), f"[{module}]  {title}")

        print()
        counts = {s: len(grouped[s]) for s in self.SEV_ORDER}
        if counts["CRITICAL"] > 0:
            self.logger.error(
                f"{counts['CRITICAL']} critical finding(s) require immediate attention"
            )
        if counts["HIGH"] > 0:
            self.logger.warning(
                f"{counts['HIGH']} high-severity finding(s) require prompt remediation"
            )
