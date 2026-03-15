class Signatures:

    SERVICE_BANNERS = {
        "ssh":           ["SSH-", "OpenSSH"],
        "ftp":           ["220", "FTP", "vsftpd", "ProFTPD", "FileZilla"],
        "smtp":          ["220", "ESMTP", "Postfix", "Exim", "sendmail"],
        "http":          ["HTTP/", "Server:", "Apache", "nginx", "IIS"],
        "mysql":         ["\x5b\x00\x00\x00", "mysql", "MariaDB"],
        "redis":         ["+PONG", "-NOAUTH", "redis_version"],
        "mongodb":       ["ismaster", "MongoDB"],
        "postgresql":    ["PostgreSQL", "FATAL:  password"],
        "elasticsearch": ["cluster_name", "elasticsearch"],
        "memcached":     ["VERSION", "STAT pid"],
        "vnc":           ["RFB "],
        "smb":           ["\xff\x53\x4d\x42"],
        "rdp":           ["\x03\x00"],
        "telnet":        ["\xff\xfd", "\xff\xfb"],
    }

    CMS_FINGERPRINTS = {
        "WordPress": {
            "paths":    ["/wp-login.php", "/wp-admin/", "/wp-content/"],
            "headers":  [],
            "body":     ["wp-content", "wp-includes", "WordPress"],
        },
        "Joomla": {
            "paths":    ["/administrator/", "/components/", "/modules/"],
            "headers":  [],
            "body":     ["Joomla", "/media/jui/"],
        },
        "Drupal": {
            "paths":    ["/sites/default/", "/?q=user/login"],
            "headers":  ["X-Generator: Drupal"],
            "body":     ["Drupal.settings", "/sites/all/"],
        },
        "Magento": {
            "paths":    ["/skin/frontend/", "/js/mage/"],
            "headers":  [],
            "body":     ["Mage.Cookies", "mage/"],
        },
        "Laravel": {
            "paths":    ["/_ignition/health-check"],
            "headers":  [],
            "body":     ["laravel_session", "XSRF-TOKEN"],
        },
        "Django": {
            "paths":    ["/admin/", "/static/admin/"],
            "headers":  [],
            "body":     ["csrfmiddlewaretoken", "djdt-", "__admin_media_prefix__"],
        },
        "Rails": {
            "paths":    ["/rails/info/properties"],
            "headers":  ["X-Powered-By: Phusion Passenger"],
            "body":     ["_rails_session"],
        },
        "Strapi": {
            "paths":    ["/admin/auth/login"],
            "headers":  [],
            "body":     ["strapi"],
        },
        "Ghost": {
            "paths":    ["/ghost/api/"],
            "headers":  [],
            "body":     ["ghost-editor"],
        },
        "Typo3": {
            "paths":    ["/typo3/"],
            "headers":  [],
            "body":     ["typo3", "TYPO3"],
        },
    }

    TECH_FINGERPRINTS = {
        "PHP":        ["X-Powered-By: PHP", ".php"],
        "ASP.NET":    ["X-Powered-By: ASP.NET", "X-AspNet-Version", ".aspx"],
        "JSP":        [".jsp", ".do", ".action"],
        "Node.js":    ["X-Powered-By: Express", "connect.sid"],
        "Python":     ["X-Powered-By: Django", "X-Powered-By: Flask", "Werkzeug"],
        "Ruby":       ["X-Powered-By: Phusion", "_session_id"],
        "Java":       ["JSESSIONID", "java.lang."],
        "WordPress":  ["wp-content", "wp-includes"],
        "jQuery":     ["jquery.min.js", "jquery-"],
        "Bootstrap":  ["bootstrap.min.css", "bootstrap.min.js"],
        "React":      ["react.min.js", "react-dom", "_react"],
        "Angular":    ["ng-app", "angular.min.js", "ng-version"],
        "Vue.js":     ["vue.min.js", "__vue__"],
    }

    DISCLOSURE_PATTERNS = {
        "stack_trace":    [
            r"at\s+\w+\([\w./]+:\d+\)",
            r"Traceback \(most recent call last\)",
            r"Stack trace:",
            r"Fatal error:",
            r"Warning:.*on line",
            r"in /.+\.php on line \d+",
        ],
        "sql_error":      [
            r"SQL syntax.*MySQL",
            r"Warning: mysql_",
            r"ORA-\d{5}",
            r"PG::SyntaxError",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Unclosed quotation mark",
            r"SQLite3::Exception",
        ],
        "path_disclosure": [
            r"/var/www/html/",
            r"C:\\inetpub\\wwwroot\\",
            r"C:\\xampp\\htdocs\\",
            r"/home/\w+/public_html/",
        ],
        "credentials": [
            r"password\s*=\s*['\"][^'\"]+['\"]",
            r"passwd\s*=\s*['\"][^'\"]+['\"]",
            r"secret\s*=\s*['\"][^'\"]+['\"]",
            r"api_key\s*=\s*['\"][^'\"]+['\"]",
            r"AWS_SECRET_ACCESS_KEY\s*=",
            r"PRIVATE KEY-----",
        ],
    }

    RISKY_PORTS = {
        21:    "FTP — credentials sent in plaintext",
        23:    "Telnet — fully unencrypted protocol",
        69:    "TFTP — no authentication",
        110:   "POP3 — plaintext credential exposure",
        137:   "NetBIOS Name Service — enumeration vector",
        139:   "NetBIOS Session — lateral movement risk",
        143:   "IMAP — plaintext credential exposure",
        161:   "SNMP — community string enumeration",
        389:   "LDAP — directory enumeration risk",
        445:   "SMB — lateral movement and ransomware vector",
        512:   "rexec — unauthenticated remote execution",
        513:   "rlogin — legacy plaintext remote login",
        514:   "rsh — unauthenticated remote shell",
        873:   "Rsync — unauthorized file access risk",
        1099:  "Java RMI — deserialization attack surface",
        2049:  "NFS — unauthorized filesystem access",
        4444:  "Common backdoor / Metasploit listener",
        5900:  "VNC — brute-force and auth bypass risk",
        6000:  "X11 — display interception risk",
        27017: "MongoDB — often unauthenticated",
        6379:  "Redis — often unauthenticated",
        9200:  "Elasticsearch — open access risk",
    }
