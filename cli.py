import argparse
import sys
from config.settings import Settings


BANNER = r"""
  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗███████╗██╗   ██╗███████╗
  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║██╔════╝╚██╗ ██╔╝██╔════╝
  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║█████╗   ╚████╔╝ █████╗
  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║██╔══╝    ╚██╔╝  ██╔══╝
  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║███████╗   ██║   ███████╗
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚══════╝
"""

EPILOG = """
scan profiles:
  quick         Top-1024 ports + basic web headers
  default       Balanced — ports, services, web, SSL
  deep          All ports, all modules, extended payloads
  stealth       Slow, low-noise — FIN/NULL, passive only
  aggressive    Max threads, all ports, full payload sets
  web           Full web application assessment
  network       Full network assessment
  api           REST/GraphQL API security assessment
  pci           PCI DSS compliance scan
  scap          SCAP/CIS benchmark audit
  cloud         Cloud infrastructure scan
  container     Docker/Kubernetes security scan
  osint         Passive OSINT only — no active probes
  internal      Internal network credentialed scan
  external      External attack surface scan

scan types (--scan-type):
  tcp           TCP Connect (default)
  syn           SYN stealth (root required)
  udp           UDP scan
  fin           FIN scan
  null          NULL scan
  xmas          Xmas scan (FIN+PSH+URG)
  ack           ACK scan (firewall mapping)
  window        Window scan
  maimon        Maimon scan (FIN+ACK)
  idle          Idle/Zombie scan (--zombie required)

examples:
  pe -t 192.168.1.1
  pe -t 192.168.1.1 --scan-type syn
  pe -t example.com --profile deep -o report.html --format html
  pe -t example.com --web --fuzz -v
  pe -t 10.0.0.0/24 --network --quick
  pe -t example.com --profile pci -o pci.json
  pe -t example.com --profile osint
  pe -t 192.168.1.1 --scan-type idle --zombie 192.168.1.5
  phantomeye -t example.com --profile web --ssl --api
"""


def build_parser():
    parser = argparse.ArgumentParser(
        prog="pe",
        description=f"PhantomEye v{Settings.VERSION} — Hybrid Vulnerability Assessment Framework",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=EPILOG,
    )

    parser.add_argument(
        "--version", action="version",
        version=f"PhantomEye {Settings.VERSION} by {Settings.AUTHOR}",
    )

    tg = parser.add_argument_group("target")
    tg.add_argument(
        "-t", "--target", required=True, metavar="TARGET",
        help="IP address, hostname, URL, or CIDR range",
    )

    pg = parser.add_argument_group("scan profile")
    pg.add_argument(
        "--profile", metavar="PROFILE", default="default",
        help="scan profile (default: default)",
    )

    mg = parser.add_argument_group("modules")
    mg.add_argument("--network",    action="store_true", help="run network scan modules")
    mg.add_argument("--web",        action="store_true", help="run web application modules")
    mg.add_argument("--host",       action="store_true", help="run host audit modules")
    mg.add_argument("--database",   action="store_true", help="run database scan modules")
    mg.add_argument("--ssl",        action="store_true", help="run SSL/TLS scan")
    mg.add_argument("--cloud",      action="store_true", help="run cloud security scan")
    mg.add_argument("--container",  action="store_true", help="run container security scan")
    mg.add_argument("--compliance", action="store_true", help="run compliance checks")
    mg.add_argument("--wireless",   action="store_true", help="run wireless scan")
    mg.add_argument("--passive",    action="store_true", help="run passive scan only")
    mg.add_argument("--osint",      action="store_true", help="run OSINT collection")
    mg.add_argument("--fuzz",       action="store_true", help="run HTTP fuzzer")
    mg.add_argument("--api",        action="store_true", help="run API security scan")
    mg.add_argument("--mobile",     action="store_true", help="run mobile/ADB checks")
    mg.add_argument("--ics",        action="store_true", help="run ICS/SCADA checks")
    mg.add_argument("--full",       action="store_true", help="enable all modules")

    sg = parser.add_argument_group("scan options")
    sg.add_argument(
        "--scan-type", dest="scan_type", default="tcp", metavar="TYPE",
        help="port scan type: tcp|syn|udp|fin|null|xmas|ack|window|maimon|idle",
    )
    sg.add_argument("--quick",     action="store_true", help="top 1024 ports only")
    sg.add_argument("--all-ports", action="store_true", dest="all_ports",
                    help="scan all 65535 ports")
    sg.add_argument("--zombie",    metavar="HOST", help="zombie host for idle scan")
    sg.add_argument("--advanced",  action="store_true",
                    help="advanced network checks (SMB, DNS, SNMP, SCTP)")
    sg.add_argument("--threads",   type=int, default=Settings.MAX_THREADS,
                    metavar="N", help=f"thread count (default: {Settings.MAX_THREADS})")
    sg.add_argument("--timeout",   type=float, default=Settings.DEFAULT_TIMEOUT,
                    metavar="SEC", help=f"socket timeout in seconds (default: {Settings.DEFAULT_TIMEOUT})")
    sg.add_argument("--rate",      type=int, default=Settings.DEFAULT_RATE,
                    metavar="N", help=f"max requests/sec (default: {Settings.DEFAULT_RATE})")
    sg.add_argument("--wordlist",  metavar="FILE",
                    help="custom wordlist for directory brute-force")
    sg.add_argument("--user",      metavar="USER", help="username for credentialed scans")
    sg.add_argument("--password",  metavar="PASS", help="password for credentialed scans")
    sg.add_argument("--cookies",   metavar="STR",
                    help="cookies for authenticated web scan (name=val; name2=val2)")

    og = parser.add_argument_group("output")
    og.add_argument("-o", "--output", metavar="FILE", help="save report to file")
    og.add_argument(
        "--format", choices=["json", "html", "xml"], default="json",
        metavar="FMT", help="report format: json|html|xml (default: json)",
    )
    og.add_argument("-v", "--verbose", action="store_true", help="verbose/debug output")
    og.add_argument("--no-color",  action="store_true", dest="no_color",
                    help="disable ANSI color output")
    og.add_argument("--log",       metavar="FILE", help="write output to log file")

    return parser


def parse_args(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.zombie:
        args.scan_type = "idle"

    if args.profile == "stealth":
        args.threads = min(args.threads, 5)
        args.timeout = max(args.timeout, 10)
    elif args.profile in ("aggressive", "deep"):
        args.threads = max(args.threads, 200)
        args.timeout = min(args.timeout, 3)

    return args
