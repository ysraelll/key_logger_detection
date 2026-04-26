import os
from keylogger_detector.core.reports import generate_text_report, generate_json_report

def test_generate_text_report(tmp_path):
    findings = {
        "processes": [{"pid": "123", "name": "test", "indicator": "ind", "exe": "exe"}],
        "ports": [{"port": "80", "status": "LISTEN", "pid": "123", "remote": "-"}],
        "files": ["/tmp/test.log"]
    }
    risk = {"score": "50", "level": "medium"}

    # We need to change the current working directory to tmp_path
    # because reports.py writes to the current dir
    original_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        report_file = generate_text_report(findings, risk, 100)
        assert os.path.exists(report_file)
        with open(report_file, "r") as f:
            content = f.read()
            assert "Risk score: 50 (medium)" in content
            assert "PID 123" in content
    finally:
        os.chdir(original_cwd)

def test_generate_json_report(tmp_path):
    findings = {
        "processes": [],
        "ports": [],
        "files": []
    }
    risk = {"score": "0", "level": "low"}

    original_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        report_file = generate_json_report(findings, risk, 50)
        assert os.path.exists(report_file)
        import json
        with open(report_file, "r") as f:
            data = json.load(f)
            assert data["risk"]["level"] == "low"
            assert data["scanned_files"] == 50
    finally:
        os.chdir(original_cwd)
