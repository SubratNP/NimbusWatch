"""AWS Configuration Scanner executing decoupled YAML rules across target services."""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from nimbuswatch.aws.client_factory import aws_clients
from nimbuswatch.engine.rule_loader import catalog
from nimbuswatch.schemas.rules import MisconfigurationRule
from nimbuswatch.schemas.scoring import parse_cvss_vector

logger = logging.getLogger(__name__)

class ConfigurationScanner:
    """Evaluates AWS resources against YAML misconfiguration rules."""

    def __init__(self):
        self.clients = aws_clients

    def run_all_scans(self) -> List[Dict[str, Any]]:
        """Run evaluations across all 5 target services: IAM, S3, EC2, CloudTrail, RDS."""
        findings: List[Dict[str, Any]] = []

        findings.extend(self.scan_iam())
        findings.extend(self.scan_s3())
        findings.extend(self.scan_ec2())
        findings.extend(self.scan_cloudtrail())
        findings.extend(self.scan_rds())

        return findings

    # --------------------------------------------------------------------------
    # IAM Evaluation
    # --------------------------------------------------------------------------
    def scan_iam(self) -> List[Dict[str, Any]]:
        findings = []
        rules = {r.rule_id: r for r in catalog.get_misconfiguration_rules("IAM")}
        iam = self.clients.get_client("iam")

        # Check Root MFA (NW-AWS-IAM-001)
        if "NW-AWS-IAM-001" in rules:
            rule = rules["NW-AWS-IAM-001"]
            try:
                summary = iam.get_account_summary().get("SummaryMap", {})
                mfa_enabled = summary.get("AccountMFAEnabled", 0) == 1
                status = "PASS" if mfa_enabled else "FAIL"
                findings.append(self._create_finding_dict(
                    rule=rule,
                    resource_id="root-account",
                    resource_arn="arn:aws:iam:::root",
                    status=status,
                    details={
                        "AccountMFAEnabled": summary.get("AccountMFAEnabled", 0),
                        "Users": summary.get("Users", 0),
                    },
                    remediation_cli=rule.remediation_cli
                ))
            except Exception as e:
                logger.error(f"Error checking IAM Root MFA: {e}")
                findings.append(self._create_finding_dict(
                    rule=rule,
                    resource_id="root-account",
                    resource_arn="arn:aws:iam:::root",
                    status="FAIL",
                    details={"error": str(e)},
                    remediation_cli=rule.remediation_cli
                ))

        # Check Wildcard Admin Policy (NW-AWS-IAM-002)
        if "NW-AWS-IAM-002" in rules:
            rule = rules["NW-AWS-IAM-002"]
            try:
                policies = iam.list_policies(Scope="Local").get("Policies", [])
                for policy in policies:
                    policy_arn = policy["Arn"]
                    policy_name = policy["PolicyName"]
                    default_ver = policy.get("DefaultVersionId", "v1")
                    ver_doc = iam.get_policy_version(
                        PolicyArn=policy_arn, VersionId=default_ver
                    ).get("PolicyVersion", {}).get("Document", {})

                    has_wildcard = self._check_wildcard_statements(ver_doc)
                    status = "FAIL" if has_wildcard else "PASS"
                    findings.append(self._create_finding_dict(
                        rule=rule,
                        resource_id=policy_name,
                        resource_arn=policy_arn,
                        status=status,
                        details={"has_wildcard_admin": has_wildcard, "policy_arn": policy_arn},
                        remediation_cli=rule.remediation_cli.replace("<username>", "target_user").replace("<policy-arn>", policy_arn)
                    ))
            except Exception as e:
                logger.error(f"Error checking IAM policies: {e}")

        return findings

    def _check_wildcard_statements(self, doc: Any) -> bool:
        if isinstance(doc, str):
            import json
            try:
                doc = json.loads(doc)
            except Exception:
                return False
        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            effect = stmt.get("Effect", "")
            action = stmt.get("Action", "")
            resource = stmt.get("Resource", "")
            if effect == "Allow":
                action_wildcard = action == "*" or (isinstance(action, list) and "*" in action)
                resource_wildcard = resource == "*" or (isinstance(resource, list) and "*" in resource)
                if action_wildcard and resource_wildcard:
                    return True
        return False

    # --------------------------------------------------------------------------
    # S3 Evaluation
    # --------------------------------------------------------------------------
    def scan_s3(self) -> List[Dict[str, Any]]:
        findings = []
        rules = {r.rule_id: r for r in catalog.get_misconfiguration_rules("S3")}
        s3 = self.clients.get_client("s3")

        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except Exception as e:
            logger.error(f"Error listing S3 buckets: {e}")
            return findings

        for bucket in buckets:
            bucket_name = bucket["Name"]
            bucket_arn = f"arn:aws:s3:::{bucket_name}"

            # NW-AWS-S3-001: Public Access Block
            if "NW-AWS-S3-001" in rules:
                rule = rules["NW-AWS-S3-001"]
                try:
                    pab = s3.get_public_access_block(Bucket=bucket_name).get("PublicAccessBlockConfiguration", {})
                    is_compliant = (
                        pab.get("BlockPublicAcls") is True
                        and pab.get("IgnorePublicAcls") is True
                        and pab.get("BlockPublicPolicy") is True
                        and pab.get("RestrictPublicBuckets") is True
                    )
                    status = "PASS" if is_compliant else "FAIL"
                    details = pab
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code")
                    if code in ("NoSuchPublicAccessBlockConfiguration", "404"):
                        status = "FAIL"
                        details = {"reason": "No PublicAccessBlock configuration defined"}
                    else:
                        status = "FAIL"
                        details = {"error": str(e)}

                findings.append(self._create_finding_dict(
                    rule=rule,
                    resource_id=bucket_name,
                    resource_arn=bucket_arn,
                    status=status,
                    details=details,
                    remediation_cli=rule.remediation_cli.replace("<bucket_name>", bucket_name)
                ))

            # NW-AWS-S3-002: Default Server-Side Encryption
            if "NW-AWS-S3-002" in rules:
                rule = rules["NW-AWS-S3-002"]
                try:
                    enc = s3.get_bucket_encryption(Bucket=bucket_name).get("ServerSideEncryptionConfiguration", {})
                    rules_list = enc.get("Rules", [])
                    status = "PASS" if rules_list else "FAIL"
                    details = {"rules_count": len(rules_list)}
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code")
                    if code in ("ServerSideEncryptionConfigurationNotFoundError", "404"):
                        status = "FAIL"
                        details = {"reason": "ServerSideEncryption configuration missing"}
                    else:
                        status = "FAIL"
                        details = {"error": str(e)}

                findings.append(self._create_finding_dict(
                    rule=rule,
                    resource_id=bucket_name,
                    resource_arn=bucket_arn,
                    status=status,
                    details=details,
                    remediation_cli=rule.remediation_cli.replace("<bucket_name>", bucket_name)
                ))

        return findings

    # --------------------------------------------------------------------------
    # EC2 Evaluation
    # --------------------------------------------------------------------------
    def scan_ec2(self) -> List[Dict[str, Any]]:
        findings = []
        rules = {r.rule_id: r for r in catalog.get_misconfiguration_rules("EC2")}
        ec2 = self.clients.get_client("ec2")

        # NW-AWS-EC2-001: Open SSH Security Group
        if "NW-AWS-EC2-001" in rules:
            rule = rules["NW-AWS-EC2-001"]
            try:
                sgs = ec2.describe_security_groups().get("SecurityGroups", [])
                for sg in sgs:
                    sg_id = sg["GroupId"]
                    sg_name = sg.get("GroupName", sg_id)
                    is_open = False
                    open_rules = []

                    for perm in sg.get("IpPermissions", []):
                        from_port = perm.get("FromPort")
                        to_port = perm.get("ToPort")
                        proto = perm.get("IpProtocol", "")

                        port_applies = (proto == "-1") or (
                            from_port is not None and to_port is not None and from_port <= 22 <= to_port
                        )

                        if port_applies:
                            for ip_range in perm.get("IpRanges", []):
                                if ip_range.get("CidrIp") == "0.0.0.0/0":
                                    is_open = True
                                    open_rules.append({"cidr": "0.0.0.0/0", "protocol": proto, "from_port": from_port, "to_port": to_port})
                            for ipv6_range in perm.get("Ipv6Ranges", []):
                                if ipv6_range.get("CidrIpv6") == "::/0":
                                    is_open = True
                                    open_rules.append({"cidr": "::/0", "protocol": proto, "from_port": from_port, "to_port": to_port})

                    status = "FAIL" if is_open else "PASS"
                    findings.append(self._create_finding_dict(
                        rule=rule,
                        resource_id=sg_name,
                        resource_arn=f"arn:aws:ec2:security-group/{sg_id}",
                        status=status,
                        details={"group_id": sg_id, "group_name": sg_name, "open_ingress": open_rules},
                        remediation_cli=rule.remediation_cli.replace("<group_id>", sg_id)
                    ))
            except Exception as e:
                logger.error(f"Error checking EC2 Security Groups: {e}")

        # NW-AWS-EC2-002: EBS Default Encryption in Region
        if "NW-AWS-EC2-002" in rules:
            rule = rules["NW-AWS-EC2-002"]
            try:
                ebs_status = ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault", False)
                status = "PASS" if ebs_status is True else "FAIL"
                findings.append(self._create_finding_dict(
                    rule=rule,
                    resource_id="ebs-region-encryption",
                    resource_arn="arn:aws:ec2:::ebs-encryption",
                    status=status,
                    details={"EbsEncryptionByDefault": ebs_status},
                    remediation_cli=rule.remediation_cli
                ))
            except Exception as e:
                # Default fallback if API not mocked or unsupported
                findings.append(self._create_finding_dict(
                    rule=rule,
                    resource_id="ebs-region-encryption",
                    resource_arn="arn:aws:ec2:::ebs-encryption",
                    status="FAIL",
                    details={"EbsEncryptionByDefault": False, "note": str(e)},
                    remediation_cli=rule.remediation_cli
                ))

        return findings

    # --------------------------------------------------------------------------
    # CloudTrail Evaluation
    # --------------------------------------------------------------------------
    def scan_cloudtrail(self) -> List[Dict[str, Any]]:
        findings = []
        rules = {r.rule_id: r for r in catalog.get_misconfiguration_rules("CloudTrail")}
        ct = self.clients.get_client("cloudtrail")

        try:
            trails = ct.describe_trails().get("trailList", [])
        except Exception as e:
            logger.error(f"Error describing CloudTrail trails: {e}")
            trails = []

        if not trails:
            # If no trails exist, report failure on both rules
            for rule in rules.values():
                findings.append(self._create_finding_dict(
                    rule=rule,
                    resource_id="no-trails-configured",
                    resource_arn="arn:aws:cloudtrail:::none",
                    status="FAIL",
                    details={"reason": "No CloudTrail trails exist in the account"},
                    remediation_cli=rule.remediation_cli
                ))
            return findings

        for trail in trails:
            trail_name = trail.get("Name", "unnamed-trail")
            trail_arn = trail.get("TrailARN", f"arn:aws:cloudtrail:::trail/{trail_name}")

            # NW-AWS-CT-001: Multi-Region Trail
            if "NW-AWS-CT-001" in rules:
                rule = rules["NW-AWS-CT-001"]
                is_multi = trail.get("IsMultiRegionTrail", False)
                status = "PASS" if is_multi else "FAIL"
                findings.append(self._create_finding_dict(
                    rule=rule,
                    resource_id=trail_name,
                    resource_arn=trail_arn,
                    status=status,
                    details={"IsMultiRegionTrail": is_multi},
                    remediation_cli=rule.remediation_cli.replace("<trail_name>", trail_name)
                ))

            # NW-AWS-CT-002: Log File Validation Enabled
            if "NW-AWS-CT-002" in rules:
                rule = rules["NW-AWS-CT-002"]
                log_val = trail.get("LogFileValidationEnabled", False)
                status = "PASS" if log_val else "FAIL"
                findings.append(self._create_finding_dict(
                    rule=rule,
                    resource_id=trail_name,
                    resource_arn=trail_arn,
                    status=status,
                    details={"LogFileValidationEnabled": log_val},
                    remediation_cli=rule.remediation_cli.replace("<trail_name>", trail_name)
                ))

        return findings

    # --------------------------------------------------------------------------
    # RDS Evaluation
    # --------------------------------------------------------------------------
    def scan_rds(self) -> List[Dict[str, Any]]:
        findings = []
        rules = {r.rule_id: r for r in catalog.get_misconfiguration_rules("RDS")}
        rds = self.clients.get_client("rds")

        try:
            instances = rds.describe_db_instances().get("DBInstances", [])
        except Exception as e:
            logger.error(f"Error describing RDS instances: {e}")
            return findings

        for instance in instances:
            db_id = instance.get("DBInstanceIdentifier", "unknown-db")
            db_arn = instance.get("DBInstanceArn", f"arn:aws:rds:::db:{db_id}")

            # NW-AWS-RDS-001: Publicly Accessible
            if "NW-AWS-RDS-001" in rules:
                rule = rules["NW-AWS-RDS-001"]
                is_public = instance.get("PubliclyAccessible", False)
                status = "FAIL" if is_public else "PASS"  # Should NOT be public
                findings.append(self._create_finding_dict(
                    rule=rule,
                    resource_id=db_id,
                    resource_arn=db_arn,
                    status=status,
                    details={"PubliclyAccessible": is_public, "Engine": instance.get("Engine")},
                    remediation_cli=rule.remediation_cli.replace("<instance_id>", db_id)
                ))

            # NW-AWS-RDS-002: Storage Encryption
            if "NW-AWS-RDS-002" in rules:
                rule = rules["NW-AWS-RDS-002"]
                is_encrypted = instance.get("StorageEncrypted", False)
                status = "PASS" if is_encrypted else "FAIL"
                findings.append(self._create_finding_dict(
                    rule=rule,
                    resource_id=db_id,
                    resource_arn=db_arn,
                    status=status,
                    details={"StorageEncrypted": is_encrypted, "KmsKeyId": instance.get("KmsKeyId")},
                    remediation_cli=rule.remediation_cli.replace("<instance_id>", db_id)
                ))

        return findings

    def _create_finding_dict(
        self,
        rule: MisconfigurationRule,
        resource_id: str,
        resource_arn: str,
        status: str,
        details: Dict[str, Any],
        remediation_cli: str
    ) -> Dict[str, Any]:
        cvss_info = parse_cvss_vector(rule.severity_vector)
        return {
            "rule_id": rule.rule_id,
            "title": rule.title,
            "description": rule.description,
            "service": rule.service,
            "resource_id": resource_id,
            "resource_arn": resource_arn,
            "status": status,
            "severity": cvss_info["severity"],
            "severity_vector": rule.severity_vector,
            "cvss_base_score": cvss_info["base_score"],
            "cis_control_v7": rule.cis_control_v7,
            "remediation_cli": remediation_cli,
            "details": details,
        }

scanner = ConfigurationScanner()
