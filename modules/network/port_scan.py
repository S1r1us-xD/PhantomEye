import socket
import struct
import select
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.utils import OutputFormatter
from config.settings import Settings
from config.signatures import Signatures


class PortScanner:
    def __init__(self, target, logger):
        self.target     = target
        self.logger     = logger
        self.timeout    = getattr(logger, "_timeout", Settings.DEFAULT_TIMEOUT)
        self.threads    = Settings.MAX_THREADS
        self.findings   = []
        self.open_ports = []

    def _tcp_connect(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            r = s.connect_ex((self.target, port))
            if r == 0:
                banner = self._banner(s, port)
                s.close()
                return port, "open", banner
            s.close()
            return port, "closed", ""
        except Exception:
            return port, "filtered", ""

    def _syn_scan(self, port):
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            raw.settimeout(self.timeout)
            pkt = self._build_tcp_packet(port, 0x02)
            raw.sendto(pkt, (self.target, 0))
            start = time.time()
            while time.time() - start < self.timeout:
                if select.select([raw], [], [], 0.5)[0]:
                    data, addr = raw.recvfrom(1024)
                    if addr[0] == self.target and len(data) >= 34:
                        flags = data[33]
                        raw.close()
                        if flags == 0x12:
                            return port, "open", ""
                        if flags == 0x14:
                            return port, "closed", ""
            raw.close()
            return port, "filtered", ""
        except PermissionError:
            return self._tcp_connect(port)
        except Exception:
            return port, "filtered", ""

    def _udp_scan(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            s.sendto(b"\x00" * 8, (self.target, port))
            try:
                s.recvfrom(1024)
                s.close()
                return port, "open", ""
            except socket.timeout:
                s.close()
                return port, "open|filtered", ""
        except socket.error as e:
            import errno
            if e.errno == errno.ECONNREFUSED:
                return port, "closed", ""
            return port, "filtered", ""

    def _flag_scan(self, port, flags):
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            raw.settimeout(self.timeout)
            raw.sendto(self._build_tcp_packet(port, flags), (self.target, 0))
            start = time.time()
            while time.time() - start < self.timeout:
                if select.select([raw], [], [], 0.5)[0]:
                    data, addr = raw.recvfrom(1024)
                    if addr[0] == self.target and len(data) >= 34:
                        if data[33] & 0x04:
                            raw.close()
                            return port, "closed", ""
            raw.close()
            return port, "open|filtered", ""
        except PermissionError:
            return self._tcp_connect(port)
        except Exception:
            return port, "filtered", ""

    def _fin_scan(self, port):    return self._flag_scan(port, 0x01)
    def _null_scan(self, port):   return self._flag_scan(port, 0x00)
    def _xmas_scan(self, port):   return self._flag_scan(port, 0x29)
    def _ack_scan(self, port):    return self._flag_scan(port, 0x10)
    def _maimon_scan(self, port): return self._flag_scan(port, 0x09)

    def _window_scan(self, port):
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            raw.settimeout(self.timeout)
            raw.sendto(self._build_tcp_packet(port, 0x10), (self.target, 0))
            start = time.time()
            while time.time() - start < self.timeout:
                if select.select([raw], [], [], 0.5)[0]:
                    data, addr = raw.recvfrom(1024)
                    if addr[0] == self.target and len(data) >= 36:
                        window = struct.unpack("!H", data[34:36])[0]
                        raw.close()
                        return port, ("open" if window != 0 else "closed"), ""
            raw.close()
            return port, "filtered", ""
        except PermissionError:
            return self._tcp_connect(port)
        except Exception:
            return port, "filtered", ""

    def _idle_scan(self, port):
        zombie = getattr(self, "zombie_host", None)
        if not zombie:
            self.logger.warning("Idle scan requires --zombie <host>. Falling back to SYN.")
            return self._syn_scan(port)
        try:
            ip1 = self._get_ipid(zombie)
            self._send_spoofed_syn(zombie, port)
            time.sleep(0.15)
            ip2 = self._get_ipid(zombie)
            delta = ip2 - ip1
            if delta >= 2:   return port, "open",     ""
            if delta == 1:   return port, "closed",   ""
            return port, "filtered", ""
        except Exception:
            return port, "filtered", ""

    def _get_ipid(self, host):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.settimeout(2)
            s.sendto(self._build_tcp_packet(9999, 0x02), (host, 0))
            data, _ = s.recvfrom(1024)
            s.close()
            return struct.unpack("!H", data[4:6])[0]
        except Exception:
            return 0

    def _send_spoofed_syn(self, zombie, port):
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            pkt = self._build_tcp_packet(port, 0x02, src_ip=zombie)
            raw.sendto(pkt, (self.target, 0))
            raw.close()
        except Exception:
            pass

    def _build_tcp_packet(self, dst_port, flags, src_ip=None):
        try:
            src_ip   = src_ip or socket.gethostbyname(socket.gethostname())
            src_port = random.randint(1024, 65534)
            ip_hdr   = struct.pack(
                "!BBHHHBBH4s4s",
                (4 << 4) | 5, 0, 40,
                random.randint(1, 65535), 0,
                64, socket.IPPROTO_TCP, 0,
                socket.inet_aton(src_ip),
                socket.inet_aton(self.target),
            )
            tcp_hdr = struct.pack(
                "!HHLLBBHHH",
                src_port, dst_port,
                random.randint(0, 0xFFFFFF), 0,
                (5 << 4) | 0, flags,
                socket.htons(5840), 0, 0,
            )
            return ip_hdr + tcp_hdr
        except Exception:
            return b"\x00" * 40

    def _banner(self, sock, port):
        try:
            probes = {
                80:  b"HEAD / HTTP/1.0\r\n\r\n",
                443: b"HEAD / HTTP/1.0\r\n\r\n",
                21:  b"\r\n",
                22:  b"\r\n",
                25:  b"EHLO pe\r\n",
                6379:b"INFO\r\n",
            }
            sock.settimeout(2)
            sock.send(probes.get(port, b"\r\n"))
            return sock.recv(512).decode("utf-8", "ignore").strip()[:200]
        except Exception:
            return ""

    def _identify_service(self, port, banner=""):
        smap = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC",
            139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            465: "SMTPS", 587: "SMTP", 993: "IMAPS", 995: "POP3S",
            1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
            3306: "MySQL", 3389: "RDP", 4444: "Backdoor?",
            5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB",
            6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
            9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
        }
        bl = banner.lower()
        for kw, svc in [
            ("ssh", "SSH"), ("ftp", "FTP"), ("smtp", "SMTP"),
            ("http", "HTTP"), ("mysql", "MySQL"), ("redis", "Redis"),
            ("mongodb", "MongoDB"), ("postgresql", "PostgreSQL"),
        ]:
            if kw in bl:
                return svc
        return smap.get(port, "unknown")

    def _get_scan_func(self, scan_type):
        return {
            "tcp":    self._tcp_connect,
            "syn":    self._syn_scan,
            "udp":    self._udp_scan,
            "fin":    self._fin_scan,
            "null":   self._null_scan,
            "xmas":   self._xmas_scan,
            "ack":    self._ack_scan,
            "window": self._window_scan,
            "maimon": self._maimon_scan,
            "idle":   self._idle_scan,
        }.get(scan_type, self._tcp_connect)

    def _run_scan(self, ports, scan_func, label):
        self.logger.section(f"Port Scan — {label}  [{len(ports)} ports]")
        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(scan_func, p): p for p in ports}
            for f in as_completed(futures):
                try:
                    port, state, banner = f.result()
                    if "open" in state:
                        svc = self._identify_service(port, banner)
                        results.append((port, state, svc, banner))
                        self.open_ports.append(port)
                except Exception:
                    pass

        results.sort(key=lambda x: x[0])
        if results:
            self.logger.table(
                ["Port", "State", "Service", "Banner"],
                [(p, s, svc, ban[:60]) for p, s, svc, ban in results],
            )
            for port, state, svc, banner in results:
                self.findings.append(
                    OutputFormatter.port_entry(port, state, svc, banner=banner)
                )
                self._check_risky(port, svc, banner)
        else:
            self.logger.info("No open ports found in scanned range")

    def _check_risky(self, port, svc, banner):
        if port in Signatures.RISKY_PORTS:
            msg = Signatures.RISKY_PORTS[port]
            self.logger.finding("high", f"Risky service on {port}/tcp ({svc}): {msg}")
            self.findings.append(OutputFormatter.finding(
                "network/port", "HIGH",
                f"Risky Service: {svc} on port {port}", msg,
                recommendation="Disable or replace with an encrypted/authenticated alternative.",
            ))
        for sig, cve in Settings.CVE_SIGNATURES.items():
            if sig.lower() in banner.lower():
                self.logger.finding("high", f"Vulnerable version: {cve}")
                self.findings.append(OutputFormatter.finding(
                    "network/port", "HIGH", "Vulnerable Version Detected", cve,
                    evidence=banner[:100],
                    recommendation="Update to a patched release immediately.",
                ))

    def run(self):
        args = self.logger  # logger carries args ref via context
        scan_type = "tcp"
        ports = sorted(set(list(range(1, 1025)) + Settings.TOP_PORTS))
        self._run_scan(ports, self._get_scan_func(scan_type), f"TCP Default")
