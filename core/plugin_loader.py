import importlib
import os


_REGISTRY = {}


def register(name, module_path, class_name):
    _REGISTRY[name] = (module_path, class_name)


def load(name):
    if name not in _REGISTRY:
        raise ImportError(f"Module '{name}' not registered in plugin registry")
    module_path, class_name = _REGISTRY[name]
    mod = importlib.import_module(module_path)
    return getattr(mod, class_name)


def registered():
    return list(_REGISTRY.keys())


register("port_scan",        "modules.network.port_scan",       "PortScanner")
register("host_discovery",   "modules.network.host_discovery",  "HostDiscovery")
register("service_detect",   "modules.network.service_detection","ServiceDetection")
register("os_detect",        "modules.network.os_detect",       "OSDetect")
register("vuln_nse",         "modules.network.vuln_nse",        "VulnNSE")
register("smb_scan",         "modules.network.smb_scan",        "SMBScanner")
register("dns_scan",         "modules.network.dns_scan",        "DNSScanner")
register("snmp_scan",        "modules.network.snmp_scan",       "SNMPScanner")
register("advanced_net",     "modules.network.advanced_net",    "AdvancedNet")
register("web_scanner",      "modules.web.web_scanner",         "WebScanner")
register("dir_scan",         "modules.web.dir_scan",            "DirScanner")
register("vuln_scan",        "modules.web.vuln_scan",           "VulnScanner")
register("api_scan",         "modules.web.api_scan",            "APIScanner")
register("cgi_scan",         "modules.web.cgi_scan",            "CGIScanner")
register("info_disclosure",  "modules.web.info_disclosure",     "InfoDisclosure")
register("traversal_scan",   "modules.web.traversal_scan",      "TraversalScanner")
register("methods_scan",     "modules.web.methods_scan",        "MethodsScanner")
register("outdated_scan",    "modules.web.outdated_scan",       "OutdatedScanner")
register("server_scan",      "modules.web.server_scan",         "ServerScanner")
register("host_audit",       "modules.host.host_audit",         "HostAudit")
register("patch_scan",       "modules.host.patch_scan",         "PatchScan")
register("config_audit",     "modules.host.config_audit",       "ConfigAudit")
register("malware_scan",     "modules.host.malware_scan",       "MalwareScan")
register("credentialed",     "modules.host.credentialed",       "CredentialedAudit")
register("uncredentialed",   "modules.host.uncredentialed",     "UncredentialedEnum")
register("db_scan",          "modules.database.db_scan",        "DBScanner")
register("ssl_scan",         "modules.ssl.ssl_scan",            "SSLScanner")
register("cloud_scan",       "modules.cloud.cloud_scan",        "CloudScanner")
register("aws_scan",         "modules.cloud.aws_scan",          "AWSScanner")
register("azure_scan",       "modules.cloud.azure_scan",        "AzureScanner")
register("gcp_scan",         "modules.cloud.gcp_scan",          "GCPScanner")
register("container_scan",   "modules.container.container_scan","ContainerScanner")
register("docker_scan",      "modules.container.docker_scan",   "DockerScanner")
register("kube_scan",        "modules.container.kube_scan",     "KubeScanner")
register("compliance_scan",  "modules.compliance.compliance_scan","ComplianceScanner")
register("pci_scan",         "modules.compliance.pci_scan",     "PCIScanner")
register("scap_scan",        "modules.compliance.scap_scan",    "SCAPScanner")
register("cis_scan",         "modules.compliance.cis_scan",     "CISScanner")
register("wireless_scan",    "modules.wireless.wireless_scan",  "WirelessScanner")
register("passive_scan",     "modules.passive.passive_scan",    "PassiveScanner")
register("mobile_scan",      "modules.mobile.mobile_scan",      "MobileScanner")
register("ics_scan",         "modules.ics.ics_scan",            "ICSScanner")
register("osint",            "modules.osint.osint",             "OSINTScanner")
register("fuzzer",           "modules.fuzzer.fuzzer",           "Fuzzer")
