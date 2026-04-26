from keylogger_detector.core.risk_engine import calculate_risk

def test_calculate_risk_low():
    findings = {
        "processes": [],
        "ports": [],
        "files": []
    }
    risk = calculate_risk(findings)
    assert risk["score"] == "0"
    assert risk["level"] == "low"

def test_calculate_risk_medium():
    findings = {
        "processes": [{}], # 30 pts
        "ports": [],
        "files": []
    }
    risk = calculate_risk(findings)
    assert int(risk["score"]) >= 30
    assert risk["level"] == "medium"

def test_calculate_risk_high():
    findings = {
        "processes": [{}, {}], # 60 pts
        "ports": [{}, {}],    # 40 pts
        "files": ["f1", "f2"] # 4 pts
    }
    risk = calculate_risk(findings)
    assert int(risk["score"]) >= 70
    assert risk["level"] == "high"

def test_risk_score_capping():
    # Test that process score caps at 60
    findings = {
        "processes": [{} for _ in range(10)],
        "ports": [],
        "files": []
    }
    risk = calculate_risk(findings)
    assert risk["score"] == "60"
