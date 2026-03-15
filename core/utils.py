import sys
import os
import re
import datetime
import socket
import ipaddress
from urllib.parse import urlparse


class Colors:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GREY    = "\033[90m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


class Logger:
    def __init__(self, verbose=False, log_file=None, no_color=False):
        self.verbose  = verbose
        self.no_color = no_color
        self._fh      = None
        if log_file:
            os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
            self._fh = open(log_file, "a", encoding="utf-8")

    def _c(self, code):
        return "" if self.no_color else code

    def _strip(self, text):
        return re.sub(r"\033\[[0-9;]*m", "", text)

    def _emit(self, line):
        print(line)
        if self._fh:
            self._fh.write(self._strip(line) + "\n")
            self._fh.flush()

    def info(self, msg):
        self._emit(f"{self._c(Colors.CYAN)}[*]{self._c(Colors.RESET)} {msg}")

    def success(self, msg):
        self._emit(f"{self._c(Colors.GREEN)}[+]{self._c(Colors.RESET)} {msg}")

    def warning(self, msg):
        self._emit(f"{self._c(Colors.YELLOW)}[!]{self._c(Colors.RESET)} {msg}")

    def error(self, msg):
        self._emit(f"{self._c(Colors.RED)}[-]{self._c(Colors.RESET)} {msg}")

    def debug(self, msg):
        if self.verbose:
            self._emit(f"{self._c(Colors.GREY)}[~]{self._c(Colors.RESET)} {msg}")

    def finding(self, severity, msg):
        palette = {
            "critical": Colors.RED + Colors.BOLD,
            "high":     Colors.RED,
            "medium":   Colors.YELLOW,
            "low":      Colors.CYAN,
            "info":     Colors.WHITE,
        }
        sev   = severity.lower()
        color = palette.get(sev, Colors.WHITE)
        pad   = " " * max(0, 10 - len(sev) - 2)
        self._emit(f"{self._c(color)}[{sev}]{self._c(Colors.RESET)}{pad}{msg}")

    def section(self, title):
        bar = "─" * 64
        self._emit(f"\n{self._c(Colors.BLUE)}{bar}{self._c(Colors.RESET)}")
        self._emit(f"{self._c(Colors.BOLD)}  {title}{self._c(Colors.RESET)}")
        self._emit(f"{self._c(Colors.BLUE)}{bar}{self._c(Colors.RESET)}")

    def table(self, headers, rows):
        if not rows:
            return
        col_w = [len(str(h)) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(col_w):
                    col_w[i] = max(col_w[i], len(str(cell)))
        fmt = "  " + "  ".join(f"{{:<{w}}}" for w in col_w)
        sep = "  " + "  ".join("─" * w for w in col_w)
        self._emit(
            f"{self._c(Colors.BOLD)}"
            f"{fmt.format(*[str(h) for h in headers])}"
            f"{self._c(Colors.RESET)}"
        )
        self._emit(sep)
        for row in rows:
            padded = list(row) + [""] * (len(headers) - len(row))
            self._emit(fmt.format(*[str(c) for c in padded]))

    def stat(self, label, value):
        self._emit(
            f"  {self._c(Colors.GREY)}{label:<26}{self._c(Colors.RESET)}{value}"
        )

    def close(self):
        if self._fh:
            self._fh.close()


class Validator:
    @staticmethod
    def is_ip(t):
        try:
            ipaddress.ip_address(t)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_cidr(t):
        try:
            ipaddress.ip_network(t, strict=False)
            return "/" in t
        except ValueError:
            return False

    @staticmethod
    def is_url(t):
        p = urlparse(t)
        return p.scheme in ("http", "https") and bool(p.netloc)

    @staticmethod
    def is_domain(t):
        return bool(re.match(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$",
            t,
        ))

    @staticmethod
    def resolve(t):
        try:
            return socket.gethostbyname(t)
        except Exception:
            return None

    @staticmethod
    def normalize(t):
        if Validator.is_url(t):
            p = urlparse(t)
            return p.netloc.split(":")[0], t
        if Validator.is_ip(t) or Validator.is_domain(t):
            return t, None
        if Validator.is_cidr(t):
            return t, None
        return None, None

    @staticmethod
    def expand_cidr(cidr):
        try:
            return [str(ip) for ip in ipaddress.ip_network(cidr, strict=False).hosts()]
        except Exception:
            return []


class OutputFormatter:
    @staticmethod
    def finding(module, severity, title, description, evidence="", recommendation=""):
        return {
            "module":         module,
            "severity":       severity.upper(),
            "title":          title,
            "description":    description,
            "evidence":       evidence,
            "recommendation": recommendation,
            "timestamp":      datetime.datetime.utcnow().isoformat() + "Z",
        }

    @staticmethod
    def port_entry(port, state, service, version="", banner=""):
        return {
            "port":    port,
            "state":   state,
            "service": service,
            "version": version,
            "banner":  banner,
        }

    @staticmethod
    def ts():
        return datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    @staticmethod
    def duration(start, end):
        secs = int((end - start).total_seconds())
        m, s = divmod(secs, 60)
        h, m = divmod(m, 60)
        if h:
            return f"{h}h {m}m {s}s"
        if m:
            return f"{m}m {s}s"
        return f"{s}s"
