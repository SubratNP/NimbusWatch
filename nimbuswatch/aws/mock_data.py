"""Mock data initialization and AWS resource seeder using Moto."""

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List

# Moto otherwise loads ~1,300 public AMIs whose snapshots appear as "owned by self" in the
# mock account, flooding the public-EBS-snapshot check. Must be set before moto is imported.
os.environ.setdefault("MOTO_EC2_LOAD_DEFAULT_AMIS", "false")

import boto3  # noqa: E402
from moto import mock_aws  # noqa: E402
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
        self._seeded = False

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
            self._seeded = False
            logger.info("Moto mock_aws context stopped.")

    def seed_resources(self):
        """Provision realistic AWS resources across IAM, S3, EC2, CloudTrail, RDS."""
        # Idempotent per mock session: re-seeding would duplicate VPCs, instances, keys and
        # snapshots (those creates don't conflict) and leave half-applied updates.
        if self._seeded:
            logger.info("Mock resources already seeded for this session; skipping.")
            return
        self._seeded = True
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

        self._seed_extended(region)

        logger.info("Mock AWS resource seeding completed.")

    def _seed_extended(self, region: str) -> None:
        """Pass + fail examples for the extended CIS v7.1.0 / FSBP checks (engine/extended_checks.py)."""

        def step(label: str, fn: Callable[[], Any]) -> Any:
            try:
                return fn()
            except Exception as e:  # noqa: BLE001 — re-seeding an existing mock raises "already exists"
                logger.warning(f"Extended seeding notice ({label}): {e}")
                return None

        iam = boto3.client("iam", region_name=region)
        s3 = boto3.client("s3", region_name=region)
        ec2 = boto3.client("ec2", region_name=region)
        ct = boto3.client("cloudtrail", region_name=region)
        rds = boto3.client("rds", region_name=region)
        kms = boto3.client("kms", region_name=region)
        account_id = boto3.client("sts", region_name=region).get_caller_identity()["Account"]
        read_only_logs = f"arn:aws:iam::{account_id}:policy/ReadOnlyLogsPolicy"

        # IAM — weak password policy (FAIL 1.7, 1.8)
        step("password policy", lambda: iam.update_account_password_policy(
            MinimumPasswordLength=8, PasswordReusePrevention=5, RequireSymbols=False))

        # developer-alice: console password, no MFA, policy attached directly (FAIL 1.9, 1.14)
        step("alice console", lambda: iam.create_login_profile(UserName="developer-alice", Password="Temp-Passw0rd-2026!"))
        step("alice direct policy", lambda: iam.attach_user_policy(
            UserName="developer-alice",
            PolicyArn=read_only_logs))
        step("alice access key", lambda: iam.create_access_key(UserName="developer-alice"))

        # sre-bob: console password + virtual MFA, permissions via a group (PASS 1.9, 1.14)
        def bob():
            iam.create_user(UserName="sre-bob")
            iam.create_login_profile(UserName="sre-bob", Password="Str0ng-Passphrase-2026!")
            dev = iam.create_virtual_mfa_device(VirtualMFADeviceName="sre-bob-mfa")["VirtualMFADevice"]
            iam.enable_mfa_device(UserName="sre-bob", SerialNumber=dev["SerialNumber"],
                                  AuthenticationCode1="123456", AuthenticationCode2="654321")
            iam.create_group(GroupName="platform-sre")
            iam.attach_group_policy(GroupName="platform-sre",
                                    PolicyArn=read_only_logs)
            iam.add_user_to_group(GroupName="platform-sre", UserName="sre-bob")
        step("sre-bob", bob)

        # ci-deploy-bot: programmatic only, fresh access key (PASS 1.13)
        step("ci bot", lambda: (iam.create_user(UserName="ci-deploy-bot"), iam.create_access_key(UserName="ci-deploy-bot")))

        # S3 — internal-logs-secure: TLS-only policy + server access logging (PASS 2.1.1, S3.9);
        # account-level Block Public Access left unset (FAIL 2.1.4)
        tls_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
                "Resource": ["arn:aws:s3:::internal-logs-secure", "arn:aws:s3:::internal-logs-secure/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            }],
        }
        step("tls policy", lambda: s3.put_bucket_policy(Bucket="internal-logs-secure", Policy=json.dumps(tls_policy)))

        def access_logging():
            owner = s3.get_bucket_acl(Bucket="nimbuswatch-trail-logs")["Owner"]["ID"]
            s3.put_bucket_acl(
                Bucket="nimbuswatch-trail-logs",
                GrantWrite='uri="http://acs.amazonaws.com/groups/s3/LogDelivery"',
                GrantReadACP='uri="http://acs.amazonaws.com/groups/s3/LogDelivery"',
                GrantFullControl=f'id="{owner}"',
            )
            s3.put_bucket_logging(Bucket="internal-logs-secure", BucketLoggingStatus={
                "LoggingEnabled": {"TargetBucket": "nimbuswatch-trail-logs", "TargetPrefix": "s3-access/internal-logs-secure/"}})
        step("s3 access logging", access_logging)

        # EC2 — RDP open to the world (FAIL 5.3)
        def rdp():
            vpc_id = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])["Vpcs"][0]["VpcId"]
            sg = ec2.create_security_group(GroupName="sg-windows-jumpbox",
                                           Description="Windows jump host with RDP exposed", VpcId=vpc_id)
            ec2.authorize_security_group_ingress(GroupId=sg["GroupId"], IpPermissions=[{
                "IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "Global RDP access"}]}])
        step("rdp sg", rdp)

        # Instances — IMDSv1 allowed (FAIL 5.7) vs IMDSv2 enforced (PASS)
        ami = "ami-0abcdef1234567890"  # moto accepts any ID once default AMIs are disabled
        for name, tokens in (("web-frontend-01", "optional"), ("api-backend-01", "required")):
            step(f"instance {name}", lambda name=name, tokens=tokens: ec2.run_instances(
                ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.micro",
                MetadataOptions={"HttpTokens": tokens, "HttpEndpoint": "enabled"},
                TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}]))

        # VPCs — default VPC has no flow logs and a permissive default SG (FAIL 3.7, 5.5);
        # prod-vpc has flow logs and a locked-down default SG (PASS)
        def prod_vpc():
            vpc_id = ec2.create_vpc(CidrBlock="10.20.0.0/16", TagSpecifications=[{
                "ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": "prod-vpc"}]}])["Vpc"]["VpcId"]
            ec2.create_flow_logs(ResourceIds=[vpc_id], ResourceType="VPC", TrafficType="REJECT",
                                 LogDestinationType="s3", LogDestination="arn:aws:s3:::nimbuswatch-trail-logs")
            default_sg = ec2.describe_security_groups(Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}])["SecurityGroups"][0]
            if default_sg.get("IpPermissions"):
                ec2.revoke_security_group_ingress(GroupId=default_sg["GroupId"], IpPermissions=default_sg["IpPermissions"])
            if default_sg.get("IpPermissionsEgress"):
                ec2.revoke_security_group_egress(GroupId=default_sg["GroupId"], IpPermissions=default_sg["IpPermissionsEgress"])
        step("prod vpc", prod_vpc)

        # EBS snapshots — one publicly restorable (FAIL EC2.1), one private (PASS)
        def snapshots():
            vol = ec2.create_volume(AvailabilityZone=f"{region}a", Size=8)["VolumeId"]
            for name, public in (("web-root-backup", True), ("db-nightly-backup", False)):
                sid = ec2.create_snapshot(VolumeId=vol, Description=name, TagSpecifications=[{
                    "ResourceType": "snapshot", "Tags": [{"Key": "Name", "Value": name}]}])["SnapshotId"]
                if public:
                    ec2.modify_snapshot_attribute(SnapshotId=sid, Attribute="createVolumePermission",
                                                  OperationType="add", GroupNames=["all"])
        step("snapshots", snapshots)

        # KMS — rotation on (PASS 3.6) vs off (FAIL)
        def keys():
            ct_key = kms.create_key(Description="CloudTrail log encryption")["KeyMetadata"]
            kms.create_alias(AliasName="alias/cloudtrail-cmk", TargetKeyId=ct_key["KeyId"])
            kms.enable_key_rotation(KeyId=ct_key["KeyId"])
            legacy = kms.create_key(Description="Legacy application data key")["KeyMetadata"]
            kms.create_alias(AliasName="alias/legacy-app-cmk", TargetKeyId=legacy["KeyId"])
            return ct_key["Arn"]
        ct_key_arn = step("kms keys", keys)

        # CloudTrail — enterprise trail: KMS-encrypted and logging (PASS 3.5, CloudTrail.1);
        # dev-local-trail: neither (FAIL). Trail bucket has no access logging (FAIL 3.4)
        if ct_key_arn:
            step("trail kms", lambda: ct.update_trail(Name="enterprise-audit-trail", KmsKeyId=ct_key_arn))
        step("trail logging", lambda: ct.start_logging(Name="enterprise-audit-trail"))

        # RDS — prod-customer-db weak (FAIL 2.2.2, 2.2.4, RDS.11, RDS.8); replica hardened (PASS)
        step("rds weak", lambda: rds.modify_db_instance(
            DBInstanceIdentifier="prod-customer-db", AutoMinorVersionUpgrade=False, MultiAZ=False,
            BackupRetentionPeriod=0, DeletionProtection=False, ApplyImmediately=True))
        step("rds hardened", lambda: rds.modify_db_instance(
            DBInstanceIdentifier="analytics-dw-replica", AutoMinorVersionUpgrade=True, MultiAZ=True,
            BackupRetentionPeriod=7, DeletionProtection=True, ApplyImmediately=True))

        # Config recorder and GuardDuty deliberately not enabled (FAIL 3.3, GuardDuty.1)

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
