import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Wordlists:
    DATA_DIR      = os.path.join(BASE_DIR, "data", "wordlists")

    SYSTEM_PATHS = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    ]

    FALLBACK_DIRS = [
        "admin", "administrator", "login", "logout", "register", "signup",
        "dashboard", "panel", "control", "manage", "management",
        "api", "api/v1", "api/v2", "api/v3", "rest", "graphql",
        "backup", "backups", "bak", "old", "archive", "archives",
        "config", "configuration", "conf", "settings", "setup",
        "test", "tests", "dev", "develop", "development", "staging",
        "uploads", "upload", "files", "file", "media", "static",
        "assets", "js", "css", "img", "images", "fonts",
        "includes", "include", "src", "source", "lib", "libs",
        "tmp", "temp", "cache", "log", "logs", "debug",
        ".git", ".svn", ".hg", ".env", ".env.local",
        ".env.production", ".env.backup", ".env.dev",
        "robots.txt", "sitemap.xml", "sitemap_index.xml",
        "readme.txt", "README.md", "CHANGELOG.md",
        "info.php", "phpinfo.php", "test.php",
        "server-status", "server-info",
        "actuator", "actuator/health", "actuator/env",
        "actuator/mappings", "actuator/beans", "actuator/info",
        "swagger-ui.html", "swagger-ui/index.html",
        "swagger.json", "openapi.json", "api-docs",
        "v1", "v2", "v3", "version",
        ".htaccess", ".htpasswd", "web.config",
        "crossdomain.xml", "clientaccesspolicy.xml",
        ".DS_Store", "Thumbs.db",
        "composer.json", "composer.lock",
        "package.json", "package-lock.json",
        ".gitignore", ".gitmodules",
        "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
        "wp-admin", "wp-login.php", "wp-config.php",
        "wp-content", "wp-includes", "xmlrpc.php",
        "wp-content/uploads", "wp-json",
        "phpmyadmin", "pma", "mysql", "myadmin",
        "joomla", "administrator", "components",
        "magento", "skin/frontend",
        "django-admin", "admin/",
        "console", "manager", "jenkins",
        "solr", "kibana", "grafana", "prometheus",
        "nagios", "zabbix", "cacti",
        "cgi-bin", "cgi-bin/test.cgi",
    ]

    SUBDOMAINS = [
        "www", "mail", "remote", "blog", "webmail", "server",
        "ns1", "ns2", "smtp", "pop", "pop3", "imap", "ftp",
        "m", "mobile", "vpn", "mail2", "sip", "api",
        "dev", "staging", "test", "portal", "admin",
        "shop", "store", "app", "apps", "beta",
        "cdn", "media", "static", "assets",
        "intranet", "internal", "corp", "corporate",
        "secure", "login", "auth", "sso",
        "git", "svn", "jira", "wiki", "docs",
        "monitor", "status", "support", "help",
        "cloud", "aws", "azure", "gcp",
    ]

    @classmethod
    def load(cls, path=None):
        if path:
            try:
                with open(path, "r", errors="ignore") as f:
                    return [l.strip() for l in f if l.strip() and not l.startswith("#")]
            except Exception:
                pass
        for sp in cls.SYSTEM_PATHS:
            if os.path.isfile(sp):
                try:
                    with open(sp, "r", errors="ignore") as f:
                        return [l.strip() for l in f if l.strip() and not l.startswith("#")]
                except Exception:
                    continue
        return cls.FALLBACK_DIRS
