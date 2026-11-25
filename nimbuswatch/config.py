"""Configuration management for nimbuswatch."""

import os
from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    APP_NAME: str = "nimbuswatch"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    
    # AWS Integration Settings
    # Defaults to MOCK_MODE=True for instant, credential-free execution
    MOCK_MODE: bool = os.getenv("NIMBUS_MOCK_MODE", "True").lower() in ("true", "1", "yes")
    AWS_REGION: str = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    AWS_ACCOUNT_ID: str = os.getenv("AWS_ACCOUNT_ID", "123456789012")
    AWS_PROFILE: str | None = os.getenv("AWS_PROFILE", None)
    AWS_ACCESS_KEY_ID: str | None = os.getenv("AWS_ACCESS_KEY_ID", None)
    AWS_SECRET_ACCESS_KEY: str | None = os.getenv("AWS_SECRET_ACCESS_KEY", None)
    AWS_SESSION_TOKEN: str | None = os.getenv("AWS_SESSION_TOKEN", None)
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/nimbuswatch.db")
    
    # Rule Paths
    RULES_DIR: Path = Path(os.getenv("NIMBUS_RULES_DIR", str(BASE_DIR / "nimbuswatch" / "rules")))
    
    # Report output directory
    REPORTS_DIR: Path = Path(os.getenv("NIMBUS_REPORTS_DIR", str(BASE_DIR / "reports")))

    # Authentication (single admin) — see nimbuswatch/auth.py. Read from the environment or .env.
    ADMIN_USERNAME: str = Field("admin", validation_alias="NIMBUS_ADMIN_USER")
    ADMIN_PASSWORD_HASH: str | None = Field(None, validation_alias="NIMBUS_ADMIN_PASSWORD_HASH")
    SESSION_SECRET: str | None = Field(None, validation_alias="NIMBUS_SESSION_SECRET")
    SESSION_HOURS: float = Field(12.0, validation_alias="NIMBUS_SESSION_HOURS")
    COOKIE_SECURE: bool = Field(False, validation_alias="NIMBUS_COOKIE_SECURE")
    # Where the admin account created from the GUI is stored (ignored if NIMBUS_ADMIN_PASSWORD_HASH is set)
    AUTH_FILE: Path = Field(BASE_DIR / "nimbuswatch_auth.json", validation_alias="NIMBUS_AUTH_FILE")
    # First-run setup is only accepted from the server machine itself unless this is true
    ALLOW_REMOTE_SETUP: bool = Field(False, validation_alias="NIMBUS_ALLOW_REMOTE_SETUP")

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True)

settings = Settings()
settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
