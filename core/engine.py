import datetime
from config.settings import Settings
from config.profiles import ScanProfile
from core.utils import Colors, OutputFormatter


class Engine:
    def __init__(self, ctx):
        self.ctx     = ctx
        self.profile = ScanProfile.get(getattr(ctx.args, "profile", "default"))

    def print_banner(self):
        args = self.ctx.args
        nc   = args.no_color
        c    = lambda code: "" if nc else code

        print(
            f"{c(Colors.RED)}{c(Colors.BOLD)}\n"
            "  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗███████╗██╗   ██╗███████╗\n"
            "  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║██╔════╝╚██╗ ██╔╝██╔════╝\n"
            "  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║█████╗   ╚████╔╝ █████╗  \n"
            "  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║██╔══╝    ╚██╔╝  ██╔══╝  \n"
            "  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║███████╗   ██║   ███████╗\n"
            "  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚══════╝\n"
            f"{c(Colors.RESET)}"
        )
        print(
            f"{c(Colors.BLUE)}  "
            f"Hybrid Vulnerability Assessment Framework  "
            f"v{Settings.VERSION} "
            f"{c(Colors.RESET)}\n"
        )

        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        logger = self.ctx.logger
        logger.stat("Target",   self.ctx.host)
        logger.stat("IP",       self.ctx.ip)
        logger.stat("Profile",  getattr(args, "profile", "default"))
        logger.stat("Scan type",getattr(args, "scan_type", "tcp").upper())
        logger.stat("Started",  now)
        print()

    def print_footer(self, start, end):
        elapsed = OutputFormatter.duration(start, end)
        counts  = self.ctx.severity_counts()
        args    = self.ctx.args
        nc      = args.no_color
        col     = lambda code: "" if nc else code
        logger  = self.ctx.logger

        logger.section("Scan Complete")
        logger.stat("Duration",  elapsed)
        logger.stat("Total",     str(sum(counts.values())))
        logger.stat("Critical",
            f"{col(Colors.RED)}{col(Colors.BOLD)}{counts['CRITICAL']}{col(Colors.RESET)}")
        logger.stat("High",
            f"{col(Colors.RED)}{counts['HIGH']}{col(Colors.RESET)}")
        logger.stat("Medium",
            f"{col(Colors.YELLOW)}{counts['MEDIUM']}{col(Colors.RESET)}")
        logger.stat("Low",
            f"{col(Colors.CYAN)}{counts['LOW']}{col(Colors.RESET)}")
        logger.stat("Info",      str(counts["INFO"]))

        out = getattr(args, "output", None)
        if out:
            logger.stat("Report", out)

        print(f"\n{col(Colors.GREY)}[pe] Done.{col(Colors.RESET)}\n")
