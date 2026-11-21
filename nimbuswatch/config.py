"""Configuration management for nimbuswatch."""

import os
from pathlib import Path
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
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/nimbuswatch.db")
    
    # Rule Paths
    RULES_DIR: Path = Path(os.getenv("NIMBUS_RULES_DIR", str(BASE_DIR / "nimbuswatch" / "rules")))
    
    # Report output directory
    REPORTS_DIR: Path = Path(os.getenv("NIMBUS_REPORTS_DIR", str(BASE_DIR / "reports")))

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
