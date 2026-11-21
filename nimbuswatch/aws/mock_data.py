"""Mock data initialization and AWS resource seeder using Moto."""

import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
import boto3
from moto import mock_aws
from nimbuswatch.config import settings

logger = logging.getLogger(__name__)

class MockEnvironment:
    """Manages Moto mock state and resource provisioning."""

    _instance = None
    _mock_context = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.is_active = False

    def start(self):
        """Start the moto mock context if not already active."""
        if not self.is_active:
            self._mock_context = mock_aws()
            self._mock_context.start()
            self.is_active = True
            logger.info("Moto mock_aws context initialized.")
            self.seed_resources()

    def stop(self):
        """Stop the moto mock context."""
        if self.is_active and self._mock_context:
            self._mock_context.stop()
            self.is_active = False
            logger.info("Moto mock_aws context stopped.")

    def seed_resources(self):
        """Provision realistic AWS resources across IAM, S3, EC2, CloudTrail, RDS."""
        region = settings.AWS_REGION
        logger.info(f"Seeding synthetic AWS resources in region {region}...")

        # 1. IAM Resources
        iam = boto3.client("iam", region_name=region)
        try:
            # Policy with wildcard
            wildcard_doc = (
                '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
            )
            iam.create_policy(
                PolicyName="OverlyPermissiveAdminPolicy",
                PolicyDocument=wildcard_doc,
                Description="Excessive wildcard permissions policy",
            )
            # Compliant Policy
            least_priv_doc = (
                '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::internal-logs-secure/*"}]}'
            )
            iam.create_policy(
                PolicyName="ReadOnlyLogsPolicy",
                PolicyDocument=least_priv_doc,
                Description="Least privilege S3 read-only policy",
            )
            # IAM User
            iam.create_user(UserName="developer-alice")
        except Exception as e:
            logger.warning(f"IAM seeding notice: {e}")

        # 2. S3 Buckets
        s3 = boto3.client("s3", region_name=region)
        try:
            # Vulnerable Bucket (No public block, No default encryption)
            s3.create_bucket(Bucket="finance-records-prod-2026")
            
            # Compliant Bucket (Public access block enabled, AES256 encryption enabled)
            s3.create_bucket(Bucket="internal-logs-secure")
            s3.put_public_access_block(
                Bucket="internal-logs-secure",
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
            s3.put_bucket_encryption(
                Bucket="internal-logs-secure",
                ServerSideEncryptionConfiguration={
                    "Rules": [
                        {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                    ]
                },
            )
        except Exception as e:
            logger.warning(f"S3 seeding notice: {e}")

        # 3. EC2 Security Groups & EBS
        ec2 = boto3.client("ec2", region_name=region)
        try:
            # Get default VPC
            vpcs = ec2.describe_vpcs()
            vpc_id = vpcs["Vpcs"][0]["VpcId"] if vpcs["Vpcs"] else None

            # Vulnerable Security Group: 0.0.0.0/0 to Port 22
            sg_vuln = ec2.create_security_group(
                GroupName="sg-web-public",
                Description="Public web server SG with SSH exposed",
                VpcId=vpc_id,
            )
            ec2.authorize_security_group_ingress(
                GroupId=sg_vuln["GroupId"],
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "Global SSH access"}],
                    },
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "HTTPS access"}],
                    },
                ],
            )

            # Compliant Security Group: Internal Bastion only
            sg_comp = ec2.create_security_group(
                GroupName="sg-internal-db",
                Description="Private database SG restricted to internal VPC",
                VpcId=vpc_id,
            )
            ec2.authorize_security_group_ingress(
                GroupId=sg_comp["GroupId"],
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 5432,
                        "ToPort": 5432,
                        "IpRanges": [{"CidrIp": "10.0.0.0/16", "Description": "VPC CIDR only"}],
                    }
                ],
            )
        except Exception as e:
            logger.warning(f"EC2 seeding notice: {e}")

        # 4. CloudTrail Trails
        ct = boto3.client("cloudtrail", region_name=region)
        try:
            # Create S3 bucket for trails
            s3.create_bucket(Bucket="nimbuswatch-trail-logs")

            # Vulnerable Trail (Single region, log validation disabled)
            ct.create_trail(
                Name="dev-local-trail",
                S3BucketName="nimbuswatch-trail-logs",
                IsMultiRegionTrail=False,
                EnableLogFileValidation=False,
            )

            # Compliant Trail (Multi region, log validation enabled)
            ct.create_trail(
                Name="enterprise-audit-trail",
                S3BucketName="nimbuswatch-trail-logs",
                IsMultiRegionTrail=True,
                EnableLogFileValidation=True,
            )
        except Exception as e:
            logger.warning(f"CloudTrail seeding notice: {e}")

        # 5. RDS Databases
        rds = boto3.client("rds", region_name=region)
        try:
            # Vulnerable RDS Instance (PubliclyAccessible=True, StorageEncrypted=False)
            rds.create_db_instance(
                DBInstanceIdentifier="prod-customer-db",
                AllocatedStorage=20,
                DBInstanceClass="db.t3.micro",
                Engine="postgres",
                MasterUsername="cloudadmin",
                MasterUserPassword="TempPassword123!",
                PubliclyAccessible=True,
                StorageEncrypted=False,
            )

            # Compliant RDS Instance (PubliclyAccessible=False, StorageEncrypted=True)
            rds.create_db_instance(
                DBInstanceIdentifier="analytics-dw-replica",
                AllocatedStorage=50,
                DBInstanceClass="db.t3.medium",
                Engine="postgres",
                MasterUsername="dwadmin",
                MasterUserPassword="SecurePassword456!",
                PubliclyAccessible=False,
                StorageEncrypted=True,
            )
        except Exception as e:
            logger.warning(f"RDS seeding notice: {e}")

        logger.info("Mock AWS resource seeding completed.")

def get_synthetic_cloudtrail_events() -> List[Dict[str, Any]]:
    """Generate realistic CloudTrail event records simulating active attacks for heuristic detection."""
    now = datetime.now(timezone.utc)
    events: List[Dict[str, Any]] = []

    # 1. Brute Force Console Logins against IAM Root / Admin (5 events within 10 mins)
    for i in range(5):
        event_time = now - timedelta(minutes=15 - i * 2)
        events.append({
            "EventId": f"ct-login-{i+1}",
            "EventName": "ConsoleLogin",
            "EventTime": event_time.isoformat(),
            "EventSource": "signin.amazonaws.com",
            "SourceIPAddress": "198.51.100.24",
            "UserAgent": "Mozilla/5.0 (Kali Linux; x86_64)",
            "ErrorMessage": "Failed authentication",
            "ErrorCode": "Failed authentication",
            "Username": "root",
            "Resources": [{"ResourceType": "AWS::IAM::User", "ResourceName": "root"}],
        })

    # 2. S3 Sensitive Data Exfiltration against finance-records-prod-2026 (7 GetObject calls)
    for i in range(7):
        event_time = now - timedelta(minutes=12 - i)
        events.append({
            "EventId": f"ct-s3-{i+1}",
            "EventName": "GetObject",
            "EventTime": event_time.isoformat(),
            "EventSource": "s3.amazonaws.com",
            "SourceIPAddress": "203.0.113.88",
            "UserAgent": "aws-sdk-go/v1.44.0 (go1.20; linux; amd64)",
            "Username": "compromised-app-role",
            "Resources": [
                {
                    "ResourceType": "AWS::S3::Object",
                    "ResourceName": f"arn:aws:s3:::finance-records-prod-2026/q3-salaries-{i}.csv"
                },
                {
                    "ResourceType": "AWS::S3::Bucket",
                    "ResourceName": "finance-records-prod-2026"
                }
            ],
            "RequestParameters": {
                "bucketName": "finance-records-prod-2026",
                "key": f"q3-salaries-{i}.csv"
            }
        })

    # 3. RDS Unauthorized Snapshot Access / Modification probes (4 events with AccessDenied)
    for i in range(4):
        event_time = now - timedelta(minutes=20 - i * 3)
        events.append({
            "EventId": f"ct-rds-{i+1}",
            "EventName": "ModifyDBSnapshotAttribute",
            "EventTime": event_time.isoformat(),
            "EventSource": "rds.amazonaws.com",
            "SourceIPAddress": "192.0.2.140",
            "UserAgent": "Boto3/1.34.0 Python/3.11",
            "ErrorCode": "AccessDenied",
            "ErrorMessage": "User is not authorized to perform: rds:ModifyDBSnapshotAttribute",
            "Username": "external-adversary",
            "Resources": [
                {
                    "ResourceType": "AWS::RDS::DBSnapshot",
                    "ResourceName": "arn:aws:rds:us-east-1:123456789012:snapshot:prod-customer-db-snapshot"
                },
                {
                    "ResourceType": "AWS::RDS::DBInstance",
                    "ResourceName": "prod-customer-db"
                }
            ]
        })

    # 4. EC2 Security Group Ingress Probes / Reconnaissance (4 events)
    for i in range(4):
        event_time = now - timedelta(minutes=18 - i * 4)
        events.append({
            "EventId": f"ct-ec2-{i+1}",
            "EventName": "AuthorizeSecurityGroupIngress",
            "EventTime": event_time.isoformat(),
            "EventSource": "ec2.amazonaws.com",
            "SourceIPAddress": "198.51.100.99",
            "UserAgent": "aws-cli/2.15.0",
            "Username": "unknown-contractor",
            "Resources": [
                {
                    "ResourceType": "AWS::EC2::SecurityGroup",
                    "ResourceName": "sg-web-public"
                }
            ]
        })

    # 5. Normal background benign events
    for i in range(5):
        event_time = now - timedelta(minutes=45 - i * 5)
        events.append({
            "EventId": f"ct-benign-{i+1}",
            "EventName": "DescribeInstances",
            "EventTime": event_time.isoformat(),
            "EventSource": "ec2.amazonaws.com",
            "SourceIPAddress": "10.0.1.50",
            "UserAgent": "aws-sdk-js/3.0.0",
            "Username": "internal-monitoring-service",
            "Resources": []
        })

    return events
