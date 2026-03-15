import datetime
import threading


class ScanContext:
    def __init__(self, args, logger):
        self.args      = args
        self.logger    = logger
        self.target    = getattr(args, "target", "")
        self.host      = ""
        self.ip        = ""
        self.url       = None
        self.is_url    = False
        self.is_cidr   = False
        self.findings  = []
        self.open_ports = []
        self.services  = {}
        self.meta      = {}
        self.start_time = datetime.datetime.utcnow()
        self._lock     = threading.Lock()

    def add_finding(self, finding):
        with self._lock:
            self.findings.append(finding)

    def add_findings(self, findings):
        with self._lock:
            self.findings.extend(findings)

    def add_open_port(self, port):
        with self._lock:
            if port not in self.open_ports:
                self.open_ports.append(port)

    def set_service(self, port, service):
        with self._lock:
            self.services[port] = service

    def severity_counts(self):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            sev = f.get("severity", "INFO").upper()
            if sev in counts:
                counts[sev] += 1
        return counts
