# Cross-Platform Keylogger Detector

A professional Python-based tool to detect potential keylogger indicators on Windows and Linux systems using a multi-layered detection engine.

## 🚀 Features
- **Multi-Layered Detection**:
    - **Heuristic Matching**: Flags known suspicious process names and ports.
    - **Behavioral Analysis**: Detects raw input device access on Linux and key-hooking API strings on Windows.
    - **YARA Integration**: Uses industry-standard YARA rules for deep binary pattern matching.
    - **Hash Database**: High-performance SHA-256 matching against millions of known malware signatures.
- **Professional Engineering**:
    - Risk score and severity classification (`low` / `medium` / `high`).
    - Report generation in text or JSON format.
    - Externalized configuration via `config.yaml`.
    - High-performance signature lookup using Python sets.

## 🛠️ Installation
```bash
git clone https://github.com/ysraelll/key_logger_detection.git
cd key_logger_detection
pip install .
```

## 💻 Usage

### 🐧 Linux
Run with `sudo` to ensure full visibility into system processes and `/dev/input` devices.
```bash
sudo keylogger-detect
```

### 🪟 Windows
Open your terminal (PowerShell or CMD) as **Administrator** and run:
```bash
keylogger-detect
```

### ⚙️ Advanced Options
**JSON report output:**
```bash
sudo keylogger-detect --format json
```

**Custom paths and scan limits:**
```bash
sudo keylogger-detect --paths /tmp /var/tmp --max-files 2000
```

**Non-admin test run (reduced visibility):**
```bash
keylogger-detect --skip-admin-check
```

## 📊 Output
The tool prints a console summary and writes a report file:
- `scan_report_<timestamp>.txt`
- `scan_report_<timestamp>.json`

Reports include:
- Host/platform information
- Suspicious processes (with the matched indicator: Heuristic, Behavioral, YARA, or Hash)
- Suspicious network ports
- Suspicious files
- Overall risk score and severity

## ⚙️ Configuration
You can tune the detection indicators without touching the code by modifying `config.yaml`. You can also update the `signatures.txt` file with the latest SHA-256 hashes from threat intelligence sources like **MalwareBazaar**.

## ⚠️ Notes
- The scanner uses heuristics and behavioral analysis; it may produce false positives.
- Administrator/root permissions are strongly recommended for accurate results.
