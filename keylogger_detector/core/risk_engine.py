from typing import Dict

def calculate_risk(findings: Dict[str, list]) -> Dict[str, str]:
    score = 0
    score += min(len(findings["processes"]) * 30, 60)
    score += min(len(findings["ports"]) * 20, 40)
    score += min(len(findings["files"]) * 2, 20)

    if score >= 70:
        level = "high"
    elif score >= 30:
        level = "medium"
    else:
        level = "low"

    return {"score": str(score), "level": level}
