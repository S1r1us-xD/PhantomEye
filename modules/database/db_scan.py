import os
import socket
import subprocess
import urllib.request
from core.utils import OutputFormatter
from config.settings import Settings


class DBScanner:
    def __init__(self, target, logger):
        self.target   = target
        self.logger   = logger
        self.findings = []
        self.open_dbs = {}

    def _tcp(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(Settings.DEFAULT_TIMEOUT)
            r = s.connect_ex((self.target, port))
            s.close()
            return r == 0
        except Exception:
            return False

    def detect(self):
        self.logger.section("Database Port Detection")
        for db, port in Settings.DB_PORTS.items():
            if self._tcp(port):
                self.logger.success(f"  {db.upper():<16} port {port}")
                self.open_dbs[db] = port
                self.findings.append(OutputFormatter.finding(
                    "database", "INFO",
                    f"Database Service Exposed: {db.upper()}",
                    f"{db.upper()} is accessible on port {port}.",
                    recommendation="Restrict database access to application servers via firewall.",
                ))
        if not self.open_dbs:
            self.logger.info("No database ports detected")
        return self.open_dbs

    def mysql(self):
        if "mysql" not in self.open_dbs:
            return
        port = self.open_dbs["mysql"]
        self.logger.section("MySQL")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(Settings.DEFAULT_TIMEOUT)
            s.connect((self.target, port))
            banner = s.recv(256)
            s.close()
            if len(banner) > 5:
                null = banner.find(b"\x00", 5)
                ver  = banner[5:null].decode("utf-8", "ignore") if null != -1 else "unknown"
                self.logger.success(f"MySQL version: {ver}")
                if ver.startswith("5."):
                    self.logger.finding("medium", f"MySQL {ver} is end-of-life")
                    self.findings.append(OutputFormatter.finding(
                        "database", "MEDIUM",
                        f"MySQL EOL Version: {ver}",
                        "End-of-life MySQL version with unpatched CVEs.",
                        recommendation="Upgrade to MySQL 8.x or MariaDB latest stable.",
                    ))
        except Exception as e:
            self.logger.debug(f"MySQL banner: {e}")

        for user, pwd in Settings.DEFAULT_DB_CREDS["mysql"]:
            try:
                r = subprocess.run(
                    ["mysql", "-h", self.target, "-P", str(port),
                     f"-u{user}", f"-p{pwd}", "-e", "SELECT 1;", "--connect-timeout=3"],
                    capture_output=True, text=True, timeout=6,
                )
                if r.returncode == 0:
                    self.logger.finding("critical", f"MySQL default credentials: {user}:{pwd or '<empty>'}")
                    self.findings.append(OutputFormatter.finding(
                        "database", "CRITICAL",
                        "MySQL Default Credentials",
                        f"Authenticated with {user}:{pwd or '<empty>'}",
                        recommendation="Change default credentials immediately.",
                    ))
                    break
            except Exception:
                pass

    def postgresql(self):
        if "postgresql" not in self.open_dbs:
            return
        port = self.open_dbs["postgresql"]
        self.logger.section("PostgreSQL")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(Settings.DEFAULT_TIMEOUT)
            s.connect((self.target, port))
            s.send(b"\x00\x00\x00\x08\x04\xd2\x16/")
            resp = s.recv(1)
            s.close()
            ssl_on = resp == b"S"
            self.logger.stat("SSL", "enabled" if ssl_on else "DISABLED")
            if not ssl_on:
                self.logger.finding("medium", "PostgreSQL SSL is disabled")
                self.findings.append(OutputFormatter.finding(
                    "database", "MEDIUM",
                    "PostgreSQL SSL Disabled",
                    "Connections to PostgreSQL are unencrypted.",
                    recommendation="Set ssl=on in postgresql.conf.",
                ))
        except Exception as e:
            self.logger.debug(f"PostgreSQL: {e}")

        for user, pwd in Settings.DEFAULT_DB_CREDS["postgresql"]:
            try:
                env = {**os.environ, "PGPASSWORD": pwd}
                r = subprocess.run(
                    ["psql", "-h", self.target, "-p", str(port),
                     "-U", user, "-c", "SELECT 1;", "-t"],
                    capture_output=True, text=True, timeout=6, env=env,
                )
                if r.returncode == 0:
                    self.logger.finding("critical", f"PostgreSQL default credentials: {user}:{pwd or '<empty>'}")
                    self.findings.append(OutputFormatter.finding(
                        "database", "CRITICAL",
                        "PostgreSQL Default Credentials",
                        f"Authenticated with {user}:{pwd or '<empty>'}",
                        recommendation="Change default credentials immediately.",
                    ))
                    break
            except Exception:
                pass

    def mongodb(self):
        if "mongodb" not in self.open_dbs:
            return
        port = self.open_dbs["mongodb"]
        self.logger.section("MongoDB")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(Settings.DEFAULT_TIMEOUT)
            s.connect((self.target, port))
            s.send(
                b"\x3f\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00"
                b"\xd4\x07\x00\x00\x00\x00\x00\x00"
                b"\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00"
                b"\x00\x00\x00\x00\xff\xff\xff\xff"
                b"\x13\x00\x00\x00\x10\x69\x73\x4d\x61\x73\x74\x65\x72\x00"
                b"\x01\x00\x00\x00\x00"
            )
            resp = s.recv(256)
            s.close()
            if b"ismaster" in resp or b"ok" in resp:
                self.logger.finding("critical", "MongoDB accessible without authentication")
                self.findings.append(OutputFormatter.finding(
                    "database", "CRITICAL",
                    "MongoDB No Authentication",
                    "MongoDB instance is accessible without credentials.",
                    recommendation="Enable auth: security.authorization: enabled in mongod.conf",
                ))
        except Exception as e:
            self.logger.debug(f"MongoDB: {e}")

    def redis(self):
        if "redis" not in self.open_dbs:
            return
        port = self.open_dbs["redis"]
        self.logger.section("Redis")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(Settings.DEFAULT_TIMEOUT)
            s.connect((self.target, port))
            s.send(b"INFO server\r\n")
            resp = s.recv(4096).decode("utf-8", "ignore")
            s.close()
            if "redis_version" in resp:
                ver = next(
                    (l.split(":")[1].strip() for l in resp.splitlines() if l.startswith("redis_version")),
                    "unknown",
                )
                self.logger.finding("critical", f"Redis unauthenticated — version {ver}")
                self.findings.append(OutputFormatter.finding(
                    "database", "CRITICAL",
                    "Redis No Authentication",
                    f"Redis {ver} is accessible without credentials.",
                    recommendation="Set requirepass in redis.conf. Bind to 127.0.0.1.",
                ))
                s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s2.settimeout(Settings.DEFAULT_TIMEOUT)
                s2.connect((self.target, port))
                s2.send(b"CONFIG GET dir\r\n")
                cfg = s2.recv(512).decode("utf-8", "ignore")
                s2.close()
                if any(p in cfg for p in ["/root", "/etc", "/var/www"]):
                    self.logger.finding("critical", "Redis CONFIG reveals sensitive write path — RCE risk")
                    self.findings.append(OutputFormatter.finding(
                        "database", "CRITICAL",
                        "Redis Dangerous Write Path",
                        "Redis CONFIG GET dir reveals a sensitive filesystem path enabling potential RCE.",
                        evidence=cfg[:200],
                        recommendation="Disable CONFIG command: rename-command CONFIG ''",
                    ))
            elif "-NOAUTH" in resp:
                self.logger.success("Redis requires authentication")
        except Exception as e:
            self.logger.debug(f"Redis: {e}")

    def elasticsearch(self):
        if "elasticsearch" not in self.open_dbs:
            return
        port = self.open_dbs["elasticsearch"]
        self.logger.section("Elasticsearch")
        try:
            req = urllib.request.Request(
                f"http://{self.target}:{port}/",
                headers={"User-Agent": Settings.USER_AGENTS[0]},
            )
            with urllib.request.urlopen(req, timeout=Settings.DEFAULT_TIMEOUT) as r:
                body = r.read().decode("utf-8", "ignore")
            if "cluster_name" in body or "elasticsearch" in body.lower():
                self.logger.finding("critical", "Elasticsearch open — no authentication")
                self.findings.append(OutputFormatter.finding(
                    "database", "CRITICAL",
                    "Elasticsearch Open Access",
                    "Elasticsearch cluster accessible without authentication.",
                    evidence=body[:300],
                    recommendation="Enable X-Pack security: xpack.security.enabled: true",
                ))
        except Exception as e:
            self.logger.debug(f"Elasticsearch: {e}")

    def mssql(self):
        if "mssql" not in self.open_dbs:
            return
        port = self.open_dbs["mssql"]
        self.logger.section("MSSQL")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(Settings.DEFAULT_TIMEOUT)
            s.connect((self.target, port))
            s.send(
                b"\x12\x01\x00\x2f\x00\x00\x01\x00\x00\x00\x1a\x00\x06"
                b"\x01\x00\x20\x00\x01\x02\x00\x21\x00\x01\x03\x00\x22"
                b"\x00\x04\x04\x00\x26\x00\x01\xff\x0a\x32\x06\x40\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            )
            resp = s.recv(256)
            s.close()
            if resp:
                self.logger.success(f"MSSQL responded on port {port}")
                self.findings.append(OutputFormatter.finding(
                    "database", "INFO",
                    "MSSQL Accessible",
                    f"MSSQL server responded on port {port}.",
                    recommendation="Restrict access to application servers only.",
                ))
        except Exception as e:
            self.logger.debug(f"MSSQL: {e}")

    def run(self):
        self.detect()
        if self.open_dbs:
            self.mysql()
            self.postgresql()
            self.mongodb()
            self.redis()
            self.elasticsearch()
            self.mssql()
