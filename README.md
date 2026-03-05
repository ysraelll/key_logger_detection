# Cross-Platform Keylogger Detector

A Python-based tool to detect potential keylogger indicators on Windows and Linux systems.

## Features
- Process monitoring with `psutil` (PID, executable path, command-line indicator matching)
- Network port inspection for suspicious listener/connection ports
- Filesystem scanning for suspicious filenames with scan limits
- Risk score and severity classification (`low` / `medium` / `high`)
- Report generation in text or JSON format

## Installation
```bash
git clone https://github.com/ysraelll/key_logger_detection.git
cd key_logger_detection
python -m pip install -r requirements.txt
```

## Usage

### Standard scan (text report)
```bash
sudo python keylogger_detector.py
```

### JSON report output
```bash
sudo python keylogger_detector.py --format json
```

### Custom paths and scan limits
```bash
sudo python keylogger_detector.py --paths /tmp /var/tmp --max-files 2000
```

### Non-admin test run (reduced visibility)
```bash
python keylogger_detector.py --skip-admin-check
```

## Output
The tool prints a console summary and writes a report file:
- `scan_report_<timestamp>.txt`
- `scan_report_<timestamp>.json`

Reports include:
- host/platform information
- suspicious processes
- suspicious ports
- suspicious files
- risk score and severity

## Notes
- The scanner uses heuristics and indicator matching and may produce false positives.
- Administrator/root permissions improve visibility into process and network data.
- Add or tune indicators in `keylogger_detector.py` for your environment.
