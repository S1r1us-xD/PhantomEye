import sys
import datetime

from core.utils import Validator
from core.context import ScanContext
from core.engine import Engine
from core.exceptions import TargetResolutionError


class Scanner:
    def __init__(self, args, logger):
        self.args   = args
        self.logger = logger
        self.ctx    = ScanContext(args, logger)
        self.engine = Engine(self.ctx)

    def _resolve(self):
        t = self.args.target
        host, url = Validator.normalize(t)
        if not host:
            raise TargetResolutionError(f"Cannot parse target: {t}")
        ip = Validator.resolve(host) if not Validator.is_cidr(t) else host
        if not ip and not Validator.is_cidr(t):
            raise TargetResolutionError(f"DNS resolution failed: {host}")
        self.ctx.host   = host
        self.ctx.ip     = ip or host
        self.ctx.url    = url
        self.ctx.is_url = Validator.is_url(t)
        self.ctx.is_cidr= Validator.is_cidr(t)

    def _flag(self, name):
        return getattr(self.args, name, False)

    def _full(self):
        return self._flag("full") or getattr(self.args, "profile", "") in ("full", "deep")

    def run(self):
        try:
            self._resolve()
        except TargetResolutionError as exc:
            self.logger.error(str(exc))
            sys.exit(1)

        start = datetime.datetime.utcnow()
        self.engine.print_banner()

        base_url = self.ctx.url or f"http://{self.ctx.host}"

        if self._flag("osint") or self._full():
            self._run("osint",       "modules.osint.osint",         "OSINTScanner",    self.ctx.host)

        if self._flag("passive") or self._full():
            self._run("passive",     "modules.passive.passive_scan", "PassiveScanner",  self.ctx.host)

        run_net = (
            self._flag("network") or self._full()
            or not any(self._flag(f) for f in [
                "web","host","database","ssl","cloud","container",
                "compliance","wireless","fuzz","osint","passive","api","mobile","ics",
            ])
        )
        if run_net:
            self._network()

        if self._flag("web") or self._full():
            self._web(base_url)

        if self._flag("api") or self._full():
            self._run("api_scan",   "modules.web.api_scan",        "APIScanner",      base_url)

        if self._flag("host") or self._full():
            self._host()

        if self._flag("database") or self._full():
            self._run("db_scan",    "modules.database.db_scan",    "DBScanner",       self.ctx.ip)

        if self._flag("ssl") or self._full():
            self._run("ssl_scan",   "modules.ssl.ssl_scan",        "SSLScanner",      self.ctx.host, 443)

        if self._flag("cloud") or self._full():
            self._cloud()

        if self._flag("container") or self._full():
            self._container()

        if self._flag("compliance") or self._full():
            self._run("compliance", "modules.compliance.compliance_scan",
                      "ComplianceScanner", self.ctx.host, prior=self.ctx.findings)

        if self._flag("wireless"):
            self._run("wireless",   "modules.wireless.wireless_scan","WirelessScanner")

        if self._flag("mobile"):
            self._run("mobile",     "modules.mobile.mobile_scan",  "MobileScanner",   self.ctx.host)

        if self._flag("ics"):
            self._run("ics",        "modules.ics.ics_scan",        "ICSScanner",      self.ctx.ip)

        if self._flag("fuzz") or self._full():
            self._run("fuzzer",     "modules.fuzzer.fuzzer",       "Fuzzer",          base_url)

        self._export()

        end = datetime.datetime.utcnow()
        from reports.cli_report import CLIReport
        CLIReport(self.ctx.findings, self.logger).print_summary()

        self.engine.print_footer(start, end)

    def _run(self, label, module_path, class_name, *pos_args, **kw_args):
        try:
            import importlib
            mod = importlib.import_module(module_path)
            cls = getattr(mod, class_name)
            prior = kw_args.pop("prior", None)
            if prior is not None:
                instance = cls(
                    *pos_args, self.logger, prior,
                    **kw_args,
                )
            else:
                instance = cls(*pos_args, self.logger, **kw_args)
            instance.run()
            self.ctx.add_findings(instance.findings)
        except Exception as exc:
            self.logger.debug(f"[{label}] {exc}")

    def _network(self):
        ip   = self.ctx.ip
        args = self.args
        self._run("port_scan",   "modules.network.port_scan",       "PortScanner",   ip)
        self._run("host_disc",   "modules.network.host_discovery",  "HostDiscovery", ip)
        self._run("svc_detect",  "modules.network.service_detection","ServiceDetection", ip)
        self._run("os_detect",   "modules.network.os_detect",       "OSDetect",      ip)
        if getattr(args, "advanced", False) or self._full():
            self._run("dns",     "modules.network.dns_scan",        "DNSScanner",    self.ctx.host)
            self._run("smb",     "modules.network.smb_scan",        "SMBScanner",    ip)
            self._run("snmp",    "modules.network.snmp_scan",       "SNMPScanner",   ip)
            self._run("adv_net", "modules.network.advanced_net",    "AdvancedNet",   ip)
            self._run("vuln_nse","modules.network.vuln_nse",        "VulnNSE",       ip)

    def _web(self, url):
        self._run("web_scan",    "modules.web.web_scanner",         "WebScanner",    url)
        self._run("dir_scan",    "modules.web.dir_scan",            "DirScanner",    url)
        self._run("vuln_scan",   "modules.web.vuln_scan",           "VulnScanner",   url)
        self._run("cgi_scan",    "modules.web.cgi_scan",            "CGIScanner",    url)
        self._run("info_disc",   "modules.web.info_disclosure",     "InfoDisclosure",url)
        self._run("traversal",   "modules.web.traversal_scan",      "TraversalScanner",url)
        self._run("methods",     "modules.web.methods_scan",        "MethodsScanner",url)
        self._run("outdated",    "modules.web.outdated_scan",       "OutdatedScanner",url)
        self._run("server",      "modules.web.server_scan",         "ServerScanner", url)

    def _host(self):
        host = self.ctx.host
        self._run("host_audit",  "modules.host.host_audit",         "HostAudit",     host)
        self._run("patch_scan",  "modules.host.patch_scan",         "PatchScan",     host)
        self._run("config_audit","modules.host.config_audit",       "ConfigAudit",   host)
        self._run("malware",     "modules.host.malware_scan",       "MalwareScan",   host)
        user = getattr(self.args, "user", None)
        if user:
            self._run("cred",    "modules.host.credentialed",       "CredentialedAudit", host)
        else:
            self._run("uncred",  "modules.host.uncredentialed",     "UncredentialedEnum",host)

    def _cloud(self):
        host = self.ctx.host
        self._run("cloud",       "modules.cloud.cloud_scan",        "CloudScanner",  host)
        self._run("aws",         "modules.cloud.aws_scan",          "AWSScanner",    host)
        self._run("azure",       "modules.cloud.azure_scan",        "AzureScanner",  host)
        self._run("gcp",         "modules.cloud.gcp_scan",          "GCPScanner",    host)

    def _container(self):
        ip = self.ctx.ip
        self._run("container",   "modules.container.container_scan","ContainerScanner",ip)
        self._run("docker",      "modules.container.docker_scan",   "DockerScanner", ip)
        self._run("kube",        "modules.container.kube_scan",     "KubeScanner",   ip)

    def _export(self):
        out = getattr(self.args, "output", None)
        if not out:
            return
        fmt = getattr(self.args, "format", "json").lower()
        try:
            from reports.report_engine import ReportEngine
            meta = {
                "host":    self.ctx.host,
                "ip":      self.ctx.ip,
                "target":  self.args.target,
                "profile": getattr(self.args, "profile", "default"),
            }
            ReportEngine(self.ctx.findings, meta, out, fmt).save()
            self.logger.success(f"Report saved → {out}")
        except Exception as exc:
            self.logger.error(f"Report export failed: {exc}")
