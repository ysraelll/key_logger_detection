from unittest.mock import MagicMock
from keylogger_detector.core.scanner import check_processes, check_network, check_filesystem

def test_check_processes_detects_known(mocker):
    # Mock psutil.process_iter to return one suspicious process
    mock_proc = MagicMock()
    mock_proc.info = {
        "name": "keylogger",
        "exe": "/usr/bin/keylogger",
        "cmdline": ["keylogger", "-start"],
        "pid": 1234
    }
    mocker.patch("psutil.process_iter", return_value=[mock_proc])

    # Since we are likely on Linux in this environment,
    # the config has "keylogger" as a known linux process.
    results = check_processes()
    assert len(results) == 1
    assert results[0]["pid"] == "1234"
    assert results[0]["indicator"] == "keylogger"

def test_check_processes_ignores_benign(mocker):
    mock_proc = MagicMock()
    mock_proc.info = {
        "name": "chrome",
        "exe": "/usr/bin/chrome",
        "cmdline": ["chrome"],
        "pid": 5678
    }
    mocker.patch("psutil.process_iter", return_value=[mock_proc])

    results = check_processes()
    assert len(results) == 0

def test_check_network_detects_port(mocker):
    mock_conn = MagicMock()
    mock_conn.laddr.port = 1337 # Known suspicious port
    mock_conn.status = "LISTEN"
    mock_conn.pid = 999
    mock_conn.raddr = None

    mocker.patch("psutil.net_connections", return_value=[mock_conn])

    results = check_network()
    assert len(results) == 1
    assert results[0]["port"] == "1337"
    assert results[0]["pid"] == "999"

def test_check_filesystem_detects_keyword(tmp_path):
    # Create a suspicious file
    suspicious_file = tmp_path / "keylog_dump.txt"
    suspicious_file.write_text("some data")

    benign_file = tmp_path / "normal.txt"
    benign_file.write_text("some data")

    results, scanned = check_filesystem([str(tmp_path)], max_files=100)
    assert len(results) == 1
    assert "keylog_dump.txt" in results[0]
    assert scanned == 2
