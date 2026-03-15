#!/usr/bin/env python3
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cli import parse_args
from core.utils import Logger


def main():
    args = parse_args()
    logger = Logger(
        verbose=getattr(args, "verbose", False),
        log_file=getattr(args, "log", None),
        no_color=getattr(args, "no_color", False),
    )
    try:
        from core.scanner import Scanner
        Scanner(args, logger).run()
    except KeyboardInterrupt:
        c = lambda code: "" if args.no_color else code
        from core.utils import Colors
        print(f"\n\n{c(Colors.YELLOW)}[!]{c(Colors.RESET)} Scan aborted by user.")
        sys.exit(0)
    except Exception as exc:
        logger.error(f"Fatal: {exc}")
        if getattr(args, "verbose", False):
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        logger.close()


if __name__ == "__main__":
    main()
