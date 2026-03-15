class ScanProfile:
    PROFILES = {
        "quick": {
            "description": "Fast top-1024 port scan + basic web headers",
            "modules":     ["network.port_scan", "web.web_scanner"],
            "port_range":  (1, 1024),
            "threads":     150,
            "timeout":     2,
        },
        "default": {
            "description": "Balanced — top ports, services, web, SSL",
            "modules":     [
                "network.port_scan", "network.host_discovery",
                "network.os_detect", "web.web_scanner",
                "web.vuln_scan", "ssl.ssl_scan",
            ],
            "port_range":  "top",
            "threads":     100,
            "timeout":     5,
        },
        "deep": {
            "description": "All modules, all ports, extended payloads",
            "modules":     "all",
            "port_range":  (1, 65535),
            "threads":     100,
            "timeout":     5,
        },
        "stealth": {
            "description": "Low-noise — passive + FIN/NULL scan, minimal footprint",
            "modules":     ["network.port_scan", "passive.passive_scan", "osint.osint"],
            "scan_types":  ["fin", "null"],
            "port_range":  "top",
            "threads":     5,
            "timeout":     12,
            "delay":       2.0,
        },
        "aggressive": {
            "description": "Max threads, all ports, all payloads",
            "modules":     "all",
            "port_range":  (1, 65535),
            "threads":     200,
            "timeout":     3,
        },
        "web": {
            "description": "Full web application assessment",
            "modules":     [
                "web.web_scanner", "web.dir_scan", "web.vuln_scan",
                "web.api_scan", "web.cgi_scan", "web.info_disclosure",
                "web.traversal_scan", "web.methods_scan", "web.outdated_scan",
                "ssl.ssl_scan",
            ],
            "port_range":  "web",
            "threads":     50,
            "timeout":     10,
        },
        "network": {
            "description": "Full network assessment",
            "modules":     [
                "network.port_scan", "network.host_discovery",
                "network.os_detect", "network.service_detection",
                "network.dns_scan", "network.smb_scan",
                "network.snmp_scan", "network.advanced_net",
            ],
            "port_range":  (1, 65535),
            "threads":     200,
            "timeout":     3,
        },
        "api": {
            "description": "REST/GraphQL API security assessment",
            "modules":     ["web.api_scan", "web.vuln_scan", "ssl.ssl_scan"],
            "threads":     30,
            "timeout":     10,
        },
        "pci": {
            "description": "PCI DSS compliance scan",
            "modules":     [
                "network.port_scan", "ssl.ssl_scan", "web.web_scanner",
                "web.vuln_scan", "compliance.pci_scan", "database.db_scan",
            ],
            "profile_tag": "PCI-DSS",
            "threads":     50,
            "timeout":     5,
        },
        "scap": {
            "description": "SCAP/CIS benchmark audit",
            "modules":     [
                "host.host_audit", "host.config_audit",
                "host.patch_scan", "compliance.scap_scan", "compliance.cis_scan",
            ],
            "profile_tag": "SCAP",
            "threads":     10,
            "timeout":     5,
        },
        "cloud": {
            "description": "Cloud infrastructure security scan",
            "modules":     [
                "cloud.cloud_scan", "cloud.aws_scan",
                "cloud.azure_scan", "cloud.gcp_scan",
                "network.port_scan", "ssl.ssl_scan",
            ],
            "threads":     50,
            "timeout":     8,
        },
        "container": {
            "description": "Docker/Kubernetes security scan",
            "modules":     [
                "container.container_scan", "container.docker_scan",
                "container.kube_scan", "network.port_scan",
            ],
            "threads":     30,
            "timeout":     5,
        },
        "osint": {
            "description": "Passive OSINT only — no active probes",
            "modules":     ["osint.osint", "passive.passive_scan"],
            "threads":     10,
            "timeout":     10,
        },
        "internal": {
            "description": "Internal network credentialed scan",
            "modules":     [
                "network.port_scan", "host.host_audit", "host.patch_scan",
                "host.config_audit", "database.db_scan", "network.advanced_net",
                "host.credentialed",
            ],
            "port_range":  (1, 65535),
            "threads":     100,
            "timeout":     5,
        },
        "external": {
            "description": "External attack surface scan",
            "modules":     [
                "network.port_scan", "web.web_scanner", "web.vuln_scan",
                "ssl.ssl_scan", "osint.osint", "web.info_disclosure",
                "web.server_scan",
            ],
            "port_range":  "top",
            "threads":     80,
            "timeout":     8,
        },
    }

    @classmethod
    def get(cls, name):
        return cls.PROFILES.get(name, cls.PROFILES["default"])

    @classmethod
    def list_all(cls):
        return [(k, v["description"]) for k, v in cls.PROFILES.items()]
