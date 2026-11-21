"""Boto3 Client Factory supporting transparent toggle between Mock Mode and Live AWS."""

import os
import boto3
from nimbuswatch.config import settings
from nimbuswatch.aws.mock_data import MockEnvironment

class AWSClientFactory:
    """Provides AWS service clients for IAM, S3, EC2, CloudTrail, RDS."""

    def __init__(self):
        self.mock_mode = settings.MOCK_MODE
        if self.mock_mode:
            # Ensure dummy AWS credentials for Moto if not present in environment
            os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
            os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
            os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
            os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
            os.environ.setdefault("AWS_DEFAULT_REGION", settings.AWS_REGION)
            
            # Start Moto mock environment and seed synthetic resources
            MockEnvironment.get_instance().start()

    def get_client(self, service_name: str, region_name: str = None):
        """Return a boto3 client for the requested service."""
        target_region = region_name or settings.AWS_REGION
        if service_name.lower() == "iam":
            # IAM is a global service in AWS
            return boto3.client("iam", region_name=target_region)
        return boto3.client(service_name.lower(), region_name=target_region)

# Global factory singleton
aws_clients = AWSClientFactory()
