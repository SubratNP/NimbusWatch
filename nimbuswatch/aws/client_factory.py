"""Boto3 Client Factory supporting transparent toggle between Mock Mode and Live AWS."""

import os
import logging
from typing import Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

from nimbuswatch.config import settings
from nimbuswatch.aws.mock_data import MockEnvironment

logger = logging.getLogger(__name__)

class AWSClientFactory:
    """Provides AWS service clients for IAM, S3, EC2, CloudTrail, RDS with STS identity discovery."""

    def __init__(self):
        self.mock_mode = settings.MOCK_MODE
        self._session: Optional[boto3.Session] = None
        self._cached_identity: Optional[Dict[str, Any]] = None
        self._init_session()

    def _init_session(self):
        """Initialize or refresh the boto3 session based on current mode."""
        self._cached_identity = None
        if self.mock_mode:
            # Ensure dummy AWS credentials for Moto
            os.environ["AWS_ACCESS_KEY_ID"] = "testing"
            os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
            os.environ["AWS_SECURITY_TOKEN"] = "testing"
            os.environ["AWS_SESSION_TOKEN"] = "testing"
            os.environ["AWS_DEFAULT_REGION"] = settings.AWS_REGION
            
            # Start Moto mock environment and seed synthetic resources
            MockEnvironment.get_instance().start()
            self._session = boto3.Session(
                aws_access_key_id="testing",
                aws_secret_access_key="testing",
                aws_session_token="testing",
                region_name=settings.AWS_REGION,
            )
            logger.info("Initialized AWSClientFactory in MOCK MODE (Moto).")
        else:
            # Ensure Moto is stopped if previously active
            MockEnvironment.get_instance().stop()
            
            # Build live session parameters respecting settings / environment
            session_kwargs: Dict[str, Any] = {"region_name": settings.AWS_REGION}
            if settings.AWS_PROFILE:
                session_kwargs["profile_name"] = settings.AWS_PROFILE
            if settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
                session_kwargs["aws_access_key_id"] = settings.AWS_ACCESS_KEY_ID
                session_kwargs["aws_secret_access_key"] = settings.AWS_SECRET_ACCESS_KEY
                if settings.AWS_SESSION_TOKEN:
                    session_kwargs["aws_session_token"] = settings.AWS_SESSION_TOKEN

            try:
                self._session = boto3.Session(**session_kwargs)
                logger.info(f"Initialized AWSClientFactory in LIVE AWS MODE (Region: {settings.AWS_REGION}).")
            except Exception as e:
                logger.error(f"Failed to initialize live boto3.Session: {e}")
                self._session = boto3.Session(region_name=settings.AWS_REGION)

    def set_mode(
        self,
        mock_mode: bool,
        region: Optional[str] = None,
        profile: Optional[str] = None,
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
        session_token: Optional[str] = None,
    ):
        """Dynamically switch between Mock Mode and Live AWS Mode with optional credentials."""
        self.mock_mode = mock_mode
        settings.MOCK_MODE = mock_mode

        if region:
            settings.AWS_REGION = region.strip()
            os.environ["AWS_DEFAULT_REGION"] = settings.AWS_REGION

        if profile is not None:
            clean_profile = profile.strip()
            settings.AWS_PROFILE = clean_profile if clean_profile else None
            if settings.AWS_PROFILE:
                os.environ["AWS_PROFILE"] = settings.AWS_PROFILE
            else:
                os.environ.pop("AWS_PROFILE", None)

        if access_key_id is not None:
            clean_ak = access_key_id.strip()
            settings.AWS_ACCESS_KEY_ID = clean_ak if clean_ak else None
            if settings.AWS_ACCESS_KEY_ID:
                os.environ["AWS_ACCESS_KEY_ID"] = settings.AWS_ACCESS_KEY_ID
            else:
                os.environ.pop("AWS_ACCESS_KEY_ID", None)

        if secret_access_key is not None:
            clean_sk = secret_access_key.strip()
            settings.AWS_SECRET_ACCESS_KEY = clean_sk if clean_sk else None
            if settings.AWS_SECRET_ACCESS_KEY:
                os.environ["AWS_SECRET_ACCESS_KEY"] = settings.AWS_SECRET_ACCESS_KEY
            else:
                os.environ.pop("AWS_SECRET_ACCESS_KEY", None)

        if session_token is not None:
            clean_token = session_token.strip()
            settings.AWS_SESSION_TOKEN = clean_token if clean_token else None
            if settings.AWS_SESSION_TOKEN:
                os.environ["AWS_SESSION_TOKEN"] = settings.AWS_SESSION_TOKEN
            else:
                os.environ.pop("AWS_SESSION_TOKEN", None)

        self._init_session()

    def get_client(self, service_name: str, region_name: str = None):
        """Return a boto3 client for the requested service."""
        target_region = region_name or settings.AWS_REGION
        if not self._session:
            self._init_session()

        if service_name.lower() == "iam":
            # IAM is global, endpoint in us-east-1
            return self._session.client("iam", region_name=target_region)
        return self._session.client(service_name.lower(), region_name=target_region)

    def get_caller_identity(self) -> Dict[str, Any]:
        """Discover active AWS caller identity via STS."""
        if self._cached_identity:
            return self._cached_identity

        if self.mock_mode:
            identity = {
                "account_id": settings.AWS_ACCOUNT_ID or "123456789012",
                "arn": f"arn:aws:iam::{settings.AWS_ACCOUNT_ID or '123456789012'}:root",
                "user_id": "AIDA1234567890EXAMPLE",
                "mode": "MOCK",
                "authenticated": True,
            }
            self._cached_identity = identity
            return identity

        try:
            sts = self.get_client("sts")
            resp = sts.get_caller_identity()
            identity = {
                "account_id": resp.get("Account"),
                "arn": resp.get("Arn"),
                "user_id": resp.get("UserId"),
                "mode": "LIVE",
                "authenticated": True,
            }
            self._cached_identity = identity
            return identity
        except (NoCredentialsError, PartialCredentialsError) as e:
            logger.warning(f"No AWS credentials located: {e}")
            return {
                "account_id": None,
                "arn": None,
                "user_id": None,
                "mode": "LIVE",
                "authenticated": False,
                "error": "No AWS credentials found. Configure via AWS CLI, IAM Role, or .env file.",
            }
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "ClientError")
            msg = e.response.get("Error", {}).get("Message", str(e))
            logger.warning(f"STS get_caller_identity failed ({code}): {msg}")
            return {
                "account_id": None,
                "arn": None,
                "user_id": None,
                "mode": "LIVE",
                "authenticated": False,
                "error": f"{code}: {msg}",
            }
        except Exception as e:
            logger.error(f"Unexpected error getting caller identity: {e}")
            return {
                "account_id": None,
                "arn": None,
                "user_id": None,
                "mode": "LIVE",
                "authenticated": False,
                "error": str(e),
            }

    def get_account_id(self) -> str:
        """Return the current AWS Account ID."""
        identity = self.get_caller_identity()
        if identity.get("account_id"):
            return identity["account_id"]
        return settings.AWS_ACCOUNT_ID or "123456789012"

    def verify_connectivity(self) -> Dict[str, Any]:
        """Probes STS, the 5 core services (IAM, S3, EC2, CloudTrail, RDS) and KMS, Config, GuardDuty."""
        identity = self.get_caller_identity()
        results: Dict[str, Any] = {
            "mode": "MOCK" if self.mock_mode else "LIVE",
            "region": settings.AWS_REGION,
            "identity": identity,
            "services": {},
            "all_passed": False,
        }

        if not identity.get("authenticated") and not self.mock_mode:
            results["all_passed"] = False
            return results

        # 1. IAM Probe
        try:
            iam = self.get_client("iam")
            iam.get_account_summary()
            results["services"]["IAM"] = {"status": "OK", "detail": "Account summary accessible"}
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            results["services"]["IAM"] = {"status": "WARNING", "detail": f"{code}: Limited IAM permissions"}
        except Exception as e:
            results["services"]["IAM"] = {"status": "ERROR", "detail": str(e)}

        # 2. S3 Probe
        try:
            s3 = self.get_client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
            results["services"]["S3"] = {"status": "OK", "detail": f"Listed {len(buckets)} bucket(s)"}
        except Exception as e:
            results["services"]["S3"] = {"status": "ERROR", "detail": str(e)}

        # 3. EC2 Probe
        try:
            ec2 = self.get_client("ec2")
            ec2.describe_regions(RegionNames=[settings.AWS_REGION])
            results["services"]["EC2"] = {"status": "OK", "detail": f"EC2 API accessible in {settings.AWS_REGION}"}
        except Exception as e:
            results["services"]["EC2"] = {"status": "ERROR", "detail": str(e)}

        # 4. CloudTrail Probe
        try:
            ct = self.get_client("cloudtrail")
            trails = ct.describe_trails().get("trailList", [])
            results["services"]["CloudTrail"] = {"status": "OK", "detail": f"Found {len(trails)} trail(s)"}
        except Exception as e:
            results["services"]["CloudTrail"] = {"status": "ERROR", "detail": str(e)}

        # 5. RDS Probe
        try:
            rds = self.get_client("rds")
            rds.describe_db_instances(MaxRecords=20)
            results["services"]["RDS"] = {"status": "OK", "detail": "RDS API accessible"}
        except Exception as e:
            results["services"]["RDS"] = {"status": "ERROR", "detail": str(e)}

        # 6-8. Services used by the extended CIS v7.1.0 / FSBP checks. A permission gap here is a
        # WARNING, not an ERROR: the core scan still works and the affected checks report the error.
        extra_probes = {
            "KMS": ("kms", lambda c: c.list_keys(Limit=1), "KMS API accessible"),
            "Config": ("config", lambda c: c.describe_configuration_recorders(), "AWS Config API accessible"),
            "GuardDuty": ("guardduty", lambda c: c.list_detectors(MaxResults=1), "GuardDuty API accessible"),
        }
        for label, (service, call, ok_detail) in extra_probes.items():
            try:
                call(self.get_client(service))
                results["services"][label] = {"status": "OK", "detail": ok_detail}
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code")
                results["services"][label] = {"status": "WARNING", "detail": f"{code}: related checks will report errors"}
            except Exception as e:
                results["services"][label] = {"status": "WARNING", "detail": str(e)}

        # Calculate all_passed
        non_errors = all(s.get("status") in ("OK", "WARNING") for s in results["services"].values())
        results["all_passed"] = non_errors and identity.get("authenticated", False)

        return results

# Global factory singleton
aws_clients = AWSClientFactory()
