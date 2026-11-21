"""CVSS v3.1 vector parser and dual-scoring schemas."""

from typing import Dict, Any, Optional
from pydantic import BaseModel
from cvss import CVSS3

SEVERITY_WEIGHT_MAP = {
    "CRITICAL": 10.0,
    "HIGH": 7.0,
    "MEDIUM": 4.0,
    "LOW": 1.0,
    "INFO": 0.0,
}

def parse_cvss_vector(vector_str: str) -> Dict[str, Any]:
    """Parse a CVSS:3.1 vector string into base score and qualitative severity rating."""
    try:
        c = CVSS3(vector_str)
        base_score = float(c.base_score)
        severity = c.severities()[0].upper()  # 'None', 'Low', 'Medium', 'High', 'Critical'
        if severity == "NONE":
            severity = "INFO"
    except Exception:
        # Fallback heuristic parser if vector string has minor formatting variations
        base_score = 5.0
        severity = "MEDIUM"
        if "AV:N" in vector_str and "AC:L" in vector_str and ("C:H" in vector_str or "I:H" in vector_str):
            base_score = 9.8
            severity = "CRITICAL"
        elif "AV:N" in vector_str and ("C:H" in vector_str or "I:H" in vector_str):
            base_score = 7.5
            severity = "HIGH"
        elif "AV:L" in vector_str or "UI:R" in vector_str:
            base_score = 3.5
            severity = "LOW"

    # Map CVSS base score range to standardized severity level
    if base_score >= 9.0:
        severity = "CRITICAL"
    elif base_score >= 7.0:
        severity = "HIGH"
    elif base_score >= 4.0:
        severity = "MEDIUM"
    elif base_score > 0.0:
        severity = "LOW"
    else:
        severity = "INFO"

    return {
        "vector": vector_str,
        "base_score": base_score,
        "severity": severity,
        "weight": SEVERITY_WEIGHT_MAP.get(severity, 1.0)
    }

class ScoringMetrics(BaseModel):
    """Dual-scoring model for CSPM evaluation."""
    passed_checks: int
    failed_checks: int
    total_checks: int
    pass_rate: float            # Primary metric: 0.0 - 100.0 %
    risk_index: float           # Secondary metric: CVSS severity-weighted score
    severity_breakdown: Dict[str, int]
    service_breakdown: Dict[str, Dict[str, Any]]
