"""AWS package initialization."""

from nimbuswatch.aws.client_factory import aws_clients, AWSClientFactory
from nimbuswatch.aws.mock_data import MockEnvironment, get_synthetic_cloudtrail_events

__all__ = ["aws_clients", "AWSClientFactory", "MockEnvironment", "get_synthetic_cloudtrail_events"]
