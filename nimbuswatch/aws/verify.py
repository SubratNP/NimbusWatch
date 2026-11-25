"""CLI diagnostic tool to verify AWS credentials, STS identity, and service permissions."""

import sys
from nimbuswatch.config import settings
from nimbuswatch.aws.client_factory import aws_clients

def main():
    print("=" * 65)
    print("  NimbusWatch — AWS Connectivity & Credential Verification")
    print("=" * 65)

    mode = "MOCK (Moto in-memory)" if aws_clients.mock_mode else "LIVE AWS"
    print(f"\nExecution Mode : {mode}")
    print(f"Target Region  : {settings.AWS_REGION}")
    if settings.AWS_PROFILE:
        print(f"AWS Profile    : {settings.AWS_PROFILE}")

    print("\nProbing AWS STS & Service Endpoints...")
    results = aws_clients.verify_connectivity()
    identity = results.get("identity", {})

    print("-" * 65)
    if identity.get("authenticated"):
        print(f"STS Status     : [AUTHENTICATED]")
        print(f"Account ID     : {identity.get('account_id')}")
        print(f"Caller ARN     : {identity.get('arn')}")
        print(f"User / Role ID : {identity.get('user_id')}")
    else:
        print(f"STS Status     : [NOT AUTHENTICATED]")
        print(f"Error Details  : {identity.get('error', 'Unknown error')}")
        print("\nTo authenticate with AWS, either:")
        print("  1. Run 'aws sso login' (or 'aws configure') in your terminal.")
        print("  2. Create a .env file with AWS_ACCESS_KEY_ID & AWS_SECRET_ACCESS_KEY.")
        print("  3. Set NIMBUS_MOCK_MODE=True to run with Moto mock data.")

    print("\nService Connectivity Breakdown:")
    print("-" * 65)
    print(f"{'Service':<14} | {'Status':<10} | {'Details'}")
    print("-" * 65)
    for service, info in results.get("services", {}).items():
        status = info.get("status", "UNKNOWN")
        detail = info.get("detail", "")
        status_tag = f"[{status}]"
        print(f"{service:<14} | {status_tag:<10} | {detail}")
    print("-" * 65)

    if results.get("all_passed"):
        print("\nAll target AWS services are reachable and ready for scanning.")
        return 0
    else:
        if aws_clients.mock_mode:
            print("\nMock environment initialized successfully.")
            return 0
        else:
            print("\nWarning: Some services or credentials are not fully accessible.")
            return 1

if __name__ == "__main__":
    sys.exit(main())
