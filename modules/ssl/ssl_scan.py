import ssl
import socket
import datetime
from core.utils import OutputFormatter
from config.settings import Settings


class SSLScanner:
    def __init__(self, host, port=443, logger=None):
        self.host     = host
        self.port     = port
        self.logger   = logger
        self.findings = []

    def certificate_analysis(self):
        self.logger.section("SSL/TLS Certificate Analysis")
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=self.host) as ss:
                ss.settimeout(Settings.DEFAULT_TIMEOUT)
                ss.connect((self.host, self.port))
                cert     = ss.getpeercert()
                cipher   = ss.cipher()
                protocol = ss.version()

            self.logger.stat("Protocol", protocol or "N/A")
            self.logger.stat("Cipher",   cipher[0] if cipher else "N/A")
            self.logger.stat("Key bits", str(cipher[2]) if cipher else "N/A")

            if protocol in Settings.SSL_WEAK_PROTOCOLS:
                self.logger.finding("high", f"Weak TLS protocol negotiated: {protocol}")
                self.findings.append(OutputFormatter.finding(
                    "ssl", "HIGH",
                    f"Weak Protocol: {protocol}",
                    f"{protocol} is deprecated and cryptographically weak.",
                    recommendation="Disable TLSv1/1.1. Configure TLSv1.2 and TLSv1.3 only.",
                ))

            if cipher:
                for weak in Settings.SSL_WEAK_CIPHERS:
                    if weak in cipher[0].upper():
                        self.logger.finding("high", f"Weak cipher suite: {cipher[0]}")
                        self.findings.append(OutputFormatter.finding(
                            "ssl", "HIGH",
                            f"Weak Cipher Suite: {cipher[0]}",
                            f"Cipher {cipher[0]} is considered cryptographically weak.",
                            recommendation="Configure strong cipher suites: AES-GCM, CHACHA20-POLY1305.",
                        ))

            if cert:
                not_after = cert.get("notAfter", "")
                if not_after:
                    try:
                        exp  = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days = (exp - datetime.datetime.utcnow()).days
                        if days < 0:
                            self.logger.finding("critical", f"SSL certificate EXPIRED {abs(days)} days ago")
                            self.findings.append(OutputFormatter.finding(
                                "ssl", "CRITICAL",
                                "SSL Certificate Expired",
                                f"Certificate expired {abs(days)} days ago ({not_after}).",
                                recommendation="Renew certificate immediately.",
                            ))
                        elif days < 30:
                            self.logger.finding("high", f"SSL certificate expires in {days} days")
                            self.findings.append(OutputFormatter.finding(
                                "ssl", "HIGH",
                                f"Certificate Expiring Soon: {days} days",
                                f"Expires {not_after}.",
                                recommendation="Renew certificate before expiry.",
                            ))
                        else:
                            self.logger.success(f"Certificate valid — {days} days remaining (expires {not_after})")
                    except ValueError:
                        pass

                subj   = dict(x[0] for x in cert.get("subject",   []))
                issuer = dict(x[0] for x in cert.get("issuer",    []))
                self.logger.stat("Subject", subj.get("commonName", "N/A"))
                self.logger.stat("Issuer",  issuer.get("organizationName", "N/A"))

                if issuer.get("commonName") == subj.get("commonName"):
                    self.logger.finding("medium", "Self-signed certificate detected")
                    self.findings.append(OutputFormatter.finding(
                        "ssl", "MEDIUM",
                        "Self-Signed Certificate",
                        "Certificate is self-signed and will trigger browser warnings.",
                        recommendation="Replace with a certificate from a trusted CA.",
                    ))

                san = [v for _, v in cert.get("subjectAltName", [])]
                if san:
                    self.logger.stat("SANs", ", ".join(san[:8]))

            return {"protocol": protocol, "cipher": cipher, "cert": cert}

        except ConnectionRefusedError:
            self.logger.warning(f"SSL port {self.port} closed on {self.host}")
            return {}
        except Exception as e:
            self.logger.debug(f"SSL cert analysis: {e}")
            return {}

    def heartbleed_check(self):
        self.logger.section("Heartbleed Check (CVE-2014-0160)")
        try:
            client_hello = (
                b"\x16\x03\x02\x00\xdc\x01\x00\x00\xd8\x03\x02"
                b"\x53\x43\x5b\x90\x9d\x9b\x72\x0b\xbc\x0c\xbc\x2b"
                b"\x92\xa8\x48\x97\xcf\xbd\x39\x04\xcc\x16\x0a\x85"
                b"\x03\x90\x9f\x77\x04\x33\xd4\xde\x00\x00\x66"
                b"\xc0\x14\xc0\x0a\xc0\x22\xc0\x21\x00\x39\x00\x38"
                b"\xc0\x0f\xc0\x05\x00\x35\x00\x84\xc0\x12\xc0\x08"
                b"\x00\x16\x00\x13\xc0\x0d\xc0\x03\x00\x0a\xc0\x13"
                b"\xc0\x09\x00\x33\x00\x32\xc0\x0e\xc0\x04\x00\x2f"
                b"\x00\x96\x00\x41\xc0\x11\xc0\x07\xc0\x0c\xc0\x02"
                b"\x00\x05\x00\x04\x00\xff\x01\x00\x00\x49"
                b"\x00\x0b\x00\x04\x03\x00\x01\x02"
                b"\x00\x0a\x00\x34\x00\x32\x00\x0e\x00\x0d\x00\x19"
                b"\x00\x0b\x00\x0c\x00\x18\x00\x09\x00\x0a\x00\x16"
                b"\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15"
                b"\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02"
                b"\x00\x03\x00\x0f\x00\x10\x00\x11\x00\x23\x00\x00"
                b"\x00\x0f\x00\x01\x01"
            )
            heartbeat = b"\x18\x03\x02\x00\x03\x01\x40\x00"
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(Settings.DEFAULT_TIMEOUT)
            s.connect((self.host, self.port))
            s.send(client_hello)
            while True:
                rt = s.recv(1)
                if not rt:
                    break
                s.recv(2)
                ln = s.recv(2)
                if not ln:
                    break
                s.recv(int.from_bytes(ln, "big"))
                if rt == b"\x16":
                    try:
                        payload = s.recv(64)
                        if payload and payload[0] == 14:
                            break
                    except Exception:
                        break
            s.send(heartbeat)
            resp = s.recv(4096)
            s.close()
            if resp and resp[0:1] == b"\x18":
                self.logger.finding("critical", "Heartbleed (CVE-2014-0160) CONFIRMED")
                self.findings.append(OutputFormatter.finding(
                    "ssl", "CRITICAL",
                    "Heartbleed — CVE-2014-0160",
                    "Host responded to malformed heartbeat — memory disclosure is possible.",
                    recommendation="Upgrade OpenSSL to 1.0.1g+. Revoke and reissue all certificates.",
                ))
                return True
            self.logger.success("Not vulnerable to Heartbleed")
            return False
        except Exception as e:
            self.logger.debug(f"Heartbleed check: {e}")
            return False

    def poodle_check(self):
        self.logger.section("POODLE Check (CVE-2014-3566 — SSLv3)")
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.set_ciphers("ALL:@SECLEVEL=0")
            if hasattr(ssl.TLSVersion, "SSLv3"):
                ctx.minimum_version = ssl.TLSVersion.SSLv3
            with ctx.wrap_socket(socket.socket(), server_hostname=self.host) as ss:
                ss.settimeout(2)
                ss.connect((self.host, self.port))
                ver = ss.version()
                if ver and "SSL" in ver:
                    self.logger.finding("high", f"SSLv3 accepted — POODLE risk")
                    self.findings.append(OutputFormatter.finding(
                        "ssl", "HIGH",
                        "POODLE — CVE-2014-3566",
                        "Server accepts SSLv3 connections.",
                        recommendation="Disable SSLv3 completely in server TLS configuration.",
                    ))
                    return True
        except Exception:
            pass
        self.logger.success("SSLv3 not accepted — POODLE not applicable")
        return False

    def tls_version_support(self):
        self.logger.section("TLS Protocol Version Support")
        version_map = {
            "TLSv1":   ssl.TLSVersion.TLSv1   if hasattr(ssl.TLSVersion, "TLSv1")   else None,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None,
            "TLSv1.2": ssl.TLSVersion.TLSv1_2 if hasattr(ssl.TLSVersion, "TLSv1_2") else None,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, "TLSv1_3") else None,
        }
        for ver_name, ver_const in version_map.items():
            if ver_const is None:
                continue
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname  = False
                ctx.verify_mode     = ssl.CERT_NONE
                ctx.minimum_version = ver_const
                ctx.maximum_version = ver_const
                with ctx.wrap_socket(socket.socket(), server_hostname=self.host) as ss:
                    ss.settimeout(3)
                    ss.connect((self.host, self.port))
                    negotiated = ss.version()
                if ver_name in Settings.SSL_WEAK_PROTOCOLS:
                    self.logger.finding("high", f"Deprecated TLS version accepted: {ver_name}")
                else:
                    self.logger.success(f"TLS version accepted: {ver_name}")
            except Exception:
                pass

    def run(self):
        self.certificate_analysis()
        self.heartbleed_check()
        self.poodle_check()
        self.tls_version_support()
