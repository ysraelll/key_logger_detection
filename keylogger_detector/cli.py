import argparse
import platform
import sys
from .utils import is_admin
from .config import COMMON_KEYLOG_PATHS
from .core.scanner import check_processes, check_network, check_filesystem, check_behavioral_indicators
from .core.risk_engine import calculate_risk
from .core.reports import generate_text_report, generate_json_report
from .core.logger import logger

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect potential keylogger indicators")
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output report format",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=5000,
        help="Maximum files to scan before stopping",
    )
    parser.add_argument(
        "--paths",
        nargs="*",
        help="Optional paths to scan instead of OS defaults",
    )
    parser.add_argument(
        "--skip-admin-check",
        action="store_true",
        help="Run without requiring administrator privileges",
    )
    return parser.parse_args()

def main() -> int:
    args = parse_args()

    if not args.skip_admin_check and not is_admin():
        logger.error("This script requires administrator privileges (or use --skip-admin-check).")
        return 1

    logger.info("Starting keylogger detection scan...")
    system = platform.system().lower()
    scan_paths = args.paths if args.paths else COMMON_KEYLOG_PATHS.get(system, [])

    suspicious_files, scanned_files = check_filesystem(scan_paths, max_files=args.max_files)

    # Combine heuristic and behavioral process detection
    heuristic_procs = check_processes()
    behavioral_procs = check_behavioral_indicators()
    all_processes = heuristic_procs + behavioral_procs

    findings = {
        "processes": all_processes,
        "ports": check_network(),
        "files": suspicious_files,
    }
    risk = calculate_risk(findings)

    if args.format == "json":
        report_file = generate_json_report(findings, risk, scanned_files)
    else:
        report_file = generate_text_report(findings, risk, scanned_files)

    logger.info(f"Scan complete! Report saved to {report_file}")
    logger.info("Summary of findings:")
    logger.info(f"- Suspicious processes: {len(findings['processes'])}")
    logger.info(f"- Suspicious ports: {len(findings['ports'])}")
    logger.info(f"- Suspicious files: {len(findings['files'])}")
    logger.info(f"- Risk score: {risk['score']} ({risk['level']})")

    return 0

if __name__ == "__main__":
    sys.exit(main())
