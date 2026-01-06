#!/usr/bin/env python3
"""CodeScanner - Multi-tool vulnerability scanner with AI analysis."""

import argparse
import asyncio
import sys
from pathlib import Path

from src.scanner import Scanner
from src.scanner.report import ReportGenerator


def run_cli(args: argparse.Namespace) -> int:
    target = Path(args.target).resolve()

    if not target.exists():
        print(f"Error: Target path does not exist: {target}")
        return 1

    if not target.is_dir():
        print(f"Error: Target path is not a directory: {target}")
        return 1

    def on_progress(msg: str) -> None:
        print(msg)

    scanner = Scanner(
        on_progress=on_progress,
        gemini_api_key=args.api_key,
        enable_bandit=not args.no_bandit,
        enable_semgrep=not args.no_semgrep,
        enable_safety=not args.no_safety,
        enable_gemini=bool(args.api_key) and not args.no_gemini,
    )

    print(f"\nScanning: {target}\n")
    result = asyncio.run(scanner.scan(target))

    report = ReportGenerator(result)

    if args.output:
        output_path = Path(args.output)
        if output_path.suffix == ".json":
            output_path.write_text(report.generate_json(), encoding="utf-8")
        elif output_path.suffix == ".html":
            output_path.write_text(report.generate_html(), encoding="utf-8")
        else:
            output_path.write_text(report.generate_markdown(), encoding="utf-8")
        print(f"\nReport saved to: {output_path}")
    else:
        print("\n" + report.generate_markdown())

    return 0 if result.critical_count == 0 and result.high_count == 0 else 1


def run_gui() -> None:
    from src.gui.app import main
    main()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CodeScanner - Security vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan ./myproject                    # Scan with all engines
  %(prog)s scan ./myproject -o report.md       # Save markdown report
  %(prog)s scan ./myproject --api-key KEY      # Enable Gemini AI scanning
  %(prog)s gui                                 # Launch graphical interface
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    scan_parser = subparsers.add_parser("scan", help="Run vulnerability scan")
    scan_parser.add_argument("target", help="Directory to scan")
    scan_parser.add_argument("-o", "--output", help="Output file path (.md, .html, .json)")
    scan_parser.add_argument("--api-key", help="Gemini API key for AI scanning")
    scan_parser.add_argument("--no-bandit", action="store_true", help="Disable Bandit")
    scan_parser.add_argument("--no-semgrep", action="store_true", help="Disable Semgrep")
    scan_parser.add_argument("--no-safety", action="store_true", help="Disable Safety")
    scan_parser.add_argument("--no-gemini", action="store_true", help="Disable Gemini AI")

    subparsers.add_parser("gui", help="Launch graphical interface")

    args = parser.parse_args()

    if args.command == "scan":
        return run_cli(args)
    elif args.command == "gui":
        run_gui()
        return 0
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
