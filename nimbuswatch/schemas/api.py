"""Pydantic schemas for API request and response envelopes."""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel

class FindingResponse(BaseModel):
    id: int
    scan_id: str
    rule_id: str
    title: str
    description: Optional[str]
    service: str
    resource_id: str
    resource_arn: Optional[str]
    status: str
    severity: str
    severity_vector: str
    cvss_base_score: float
    cis_control_v7: str
    remediation_cli: Optional[str]
    details: Optional[Dict[str, Any]]
    timestamp: Optional[str]

class CorrelatedAlertResponse(BaseModel):
    id: int
    scan_id: str
    combination_id: str
    title: str
    description: str
    misconfiguration_rule_id: str
    attack_pattern_id: str
    resource_id: str
    escalated_severity: str
    mitre_tactic: str
    mitre_technique: Optional[str]
    evidence: Optional[Dict[str, Any]]
    remediation_cli: Optional[str]
    timestamp: Optional[str]

class ScanTriggerResponse(BaseModel):
    scan_id: str
    status: str
    timestamp: str
    passed_checks: int
    failed_checks: int
    total_checks: int
    pass_rate: float
    risk_index: float
    findings_count: int
    toxic_combinations_count: int
    message: str

class ScanHistoryResponse(BaseModel):
    id: int
    scan_id: str
    timestamp: Optional[str]
    account_id: str
    region: str
    passed_checks: int
    failed_checks: int
    total_checks: int
    pass_rate: float
    risk_index: float
    status: str

class DashboardSummaryResponse(BaseModel):
    latest_scan: Optional[ScanHistoryResponse]
    metrics: Dict[str, Any]
    severity_distribution: Dict[str, int]
    service_distribution: Dict[str, Dict[str, Any]]
    toxic_combinations: List[CorrelatedAlertResponse]
    findings: List[FindingResponse]
    mock_mode: bool
