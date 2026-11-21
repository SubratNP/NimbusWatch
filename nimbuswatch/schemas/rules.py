"""Pydantic schemas for YAML-driven rules: Misconfigurations, Attack Patterns, and Toxic Combinations."""

from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field, field_validator

AwsService = Literal["IAM", "S3", "EC2", "CloudTrail", "RDS"]
SeverityLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

class DetectionLogic(BaseModel):
    """Detection logic specification within a misconfiguration rule."""
    check_type: str = Field(..., description="Evaluation strategy (e.g. attribute_check, security_group_ingress, bucket_policy, trail_status)")
    resource_type: str = Field(..., description="Target AWS resource type (e.g. s3_bucket, ec2_security_group, iam_account_summary, rds_instance)")
    attribute: Optional[str] = Field(None, description="Resource attribute path or field name")
    operator: Optional[str] = Field("equals", description="Comparison operator (equals, not_equals, contains, does_not_contain, greater_than, is_true, is_false)")
    expected_value: Optional[Any] = Field(None, description="Expected value for PASS evaluation")
    custom_params: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Custom parameters for service-specific logic")

class MisconfigurationRule(BaseModel):
    """Rule schema for AWS misconfiguration detection decoupled in YAML.
    
    Strictly enforces:
    - rule_id
    - title
    - description
    - service
    - severity_vector (CVSS v3.1 vector string)
    - cis_control_v7 (CIS AWS Foundations Benchmark v7.0.0 reference)
    - remediation_cli (actionable AWS CLI command)
    - detection_logic (declarative evaluation constructs)
    """
    rule_id: str = Field(..., description="Unique rule identifier (e.g. NW-AWS-S3-001)")
    title: str = Field(..., description="Concise rule title")
    description: str = Field(..., description="Detailed description of the security check and threat rationale")
    service: AwsService = Field(..., description="Target AWS Service (IAM, S3, EC2, CloudTrail, RDS)")
    severity_vector: str = Field(..., description="CVSS v3.1 vector string, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    cis_control_v7: str = Field(..., description="Mapped CIS AWS Foundations Benchmark v7.0.0 control")
    remediation_cli: str = Field(..., description="Actionable AWS CLI command for remediation")
    detection_logic: DetectionLogic = Field(..., description="Evaluation logic and parameters")

    @field_validator("severity_vector")
    @classmethod
    def validate_cvss_vector(cls, v: str) -> str:
        if not v.startswith("CVSS:3.1/"):
            raise ValueError("severity_vector must be a valid CVSS v3.1 string starting with 'CVSS:3.1/'")
        return v

class AttackPatternCondition(BaseModel):
    """Conditions for matching CloudTrail events."""
    error_codes: Optional[List[str]] = Field(default_factory=list, description="Target error codes like AccessDenied, Client.UnauthorizedOperation")
    match_failed_events_only: bool = Field(False, description="Filter only events with an error code")
    specific_user_agents: Optional[List[str]] = Field(default_factory=list)
    request_parameters: Optional[Dict[str, Any]] = Field(default_factory=dict)

class AttackPatternRule(BaseModel):
    """Schema for CloudTrail heuristic attack patterns defined in YAML."""
    attack_id: str = Field(..., description="Unique attack pattern ID (e.g. NW-ATK-AUTH-001)")
    title: str = Field(..., description="Attack pattern title")
    description: str = Field(..., description="Threat description")
    category: Literal["Reconnaissance", "Brute Force", "Exfiltration", "Unauthorized Access", "Privilege Escalation"] = Field(
        ..., description="Attack category"
    )
    service: AwsService = Field(..., description="Target AWS service associated with attack")
    event_names: List[str] = Field(..., description="List of target CloudTrail event names to inspect")
    threshold: int = Field(default=3, description="Minimum number of occurrences within the time window to trigger alert")
    time_window_minutes: int = Field(default=60, description="Sliding time window in minutes")
    condition: Optional[AttackPatternCondition] = Field(default_factory=AttackPatternCondition)
    mitre_tactic: str = Field("Credential Access", description="MITRE ATT&CK tactic")
    mitre_technique: Optional[str] = Field(None, description="MITRE ATT&CK technique ID and name")

class ToxicCombinationRule(BaseModel):
    """Schema for Toxic Combinations correlating a misconfiguration with an attack pattern."""
    combination_id: str = Field(..., description="Unique toxic combination identifier (e.g. NW-TOXIC-001)")
    title: str = Field(..., description="Elevated threat title")
    description: str = Field(..., description="Contextual narrative explaining why this combination is hazardous")
    misconfiguration_rule_id: str = Field(..., description="Target misconfiguration rule ID to correlate")
    attack_pattern_id: str = Field(..., description="Target attack pattern ID to correlate")
    escalated_severity: SeverityLevel = Field("CRITICAL", description="Escalated severity tier")
    mitre_tactic: str = Field(..., description="Primary MITRE ATT&CK Tactic")
    mitre_technique: Optional[str] = Field(None, description="Primary MITRE ATT&CK Technique")
    remediation_cli: str = Field(..., description="Priority AWS CLI remediation instructions")
