"""SQLAlchemy models for Scan History, Findings, and Correlated Toxic Alerts."""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Float, DateTime, Text, ForeignKey, JSON
)
from sqlalchemy.orm import relationship
from nimbuswatch.database.connection import Base

class ScanHistory(Base):
    """Represents an execution record of a security configuration & attack pattern scan."""
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    account_id = Column(String(32), default="123456789012")
    region = Column(String(32), default="us-east-1")
    
    # Dual Scoring Metrics
    passed_checks = Column(Integer, default=0)
    failed_checks = Column(Integer, default=0)
    total_checks = Column(Integer, default=0)
    pass_rate = Column(Float, default=0.0)  # Primary: Percentage (0.0 to 100.0)
    risk_index = Column(Float, default=0.0) # Secondary: Severity-weighted penalty score
    
    status = Column(String(32), default="COMPLETED")  # PENDING, IN_PROGRESS, COMPLETED, FAILED
    error_message = Column(Text, nullable=True)

    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    correlated_alerts = relationship("CorrelatedAlert", back_populates="scan", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "account_id": self.account_id,
            "region": self.region,
            "passed_checks": self.passed_checks,
            "failed_checks": self.failed_checks,
            "total_checks": self.total_checks,
            "pass_rate": round(self.pass_rate, 2),
            "risk_index": round(self.risk_index, 2),
            "status": self.status,
            "error_message": self.error_message,
        }

class Finding(Base):
    """Represents an individual evaluation outcome of a YAML rule against an AWS resource."""
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(64), ForeignKey("scan_history.scan_id", ondelete="CASCADE"), index=True, nullable=False)
    rule_id = Column(String(64), index=True, nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    service = Column(String(32), index=True, nullable=False)  # IAM, S3, EC2, CloudTrail, RDS
    
    resource_id = Column(String(255), nullable=False)
    resource_arn = Column(String(512), nullable=True)
    
    status = Column(String(16), nullable=False)  # PASS, FAIL, ERROR
    severity = Column(String(16), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW
    severity_vector = Column(String(128), nullable=False)  # CVSS v3.1 vector
    cvss_base_score = Column(Float, default=0.0)
    
    cis_control_v7 = Column(String(64), nullable=False)
    remediation_cli = Column(Text, nullable=True)
    details = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Relationship
    scan = relationship("ScanHistory", back_populates="findings")

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "service": self.service,
            "resource_id": self.resource_id,
            "resource_arn": self.resource_arn,
            "status": self.status,
            "severity": self.severity,
            "severity_vector": self.severity_vector,
            "cvss_base_score": round(self.cvss_base_score, 1),
            "cis_control_v7": self.cis_control_v7,
            "remediation_cli": self.remediation_cli,
            "details": self.details or {},
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }

class CorrelatedAlert(Base):
    """Represents a Toxic Combination alert linking a misconfiguration to an active attack pattern."""
    __tablename__ = "correlated_alerts"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(64), ForeignKey("scan_history.scan_id", ondelete="CASCADE"), index=True, nullable=False)
    combination_id = Column(String(64), index=True, nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    
    misconfiguration_rule_id = Column(String(64), nullable=False)
    attack_pattern_id = Column(String(64), nullable=False)
    
    resource_id = Column(String(255), nullable=False)
    escalated_severity = Column(String(16), default="CRITICAL")
    mitre_tactic = Column(String(128), nullable=False)  # e.g., "Initial Access", "Credential Access"
    mitre_technique = Column(String(128), nullable=True)
    
    evidence = Column(JSON, nullable=True)  # Attack count, sample event IDs, timestamps
    remediation_cli = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Relationship
    scan = relationship("ScanHistory", back_populates="correlated_alerts")

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "combination_id": self.combination_id,
            "title": self.title,
            "description": self.description,
            "misconfiguration_rule_id": self.misconfiguration_rule_id,
            "attack_pattern_id": self.attack_pattern_id,
            "resource_id": self.resource_id,
            "escalated_severity": self.escalated_severity,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "evidence": self.evidence or {},
            "remediation_cli": self.remediation_cli,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
