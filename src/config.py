"""
config.py – Centralized configuration management using Pydantic Settings.
"""

from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # JWT
    secret_key: str = Field(..., alias="SECRET_KEY", min_length=32)
    algorithm: str = Field("HS256", alias="ALGORITHM")
    access_token_expire_minutes: int = Field(15, alias="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(7, alias="REFRESH_TOKEN_EXPIRE_DAYS")
    
    # Database
    database_url: str = Field("sqlite:///./auction.db", alias="DATABASE_URL")
    
    # Security
    bcrypt_rounds: int = Field(12, alias="BCRYPT_ROUNDS")
    max_login_attempts: int = Field(5, alias="MAX_LOGIN_ATTEMPTS")
    lockout_duration_minutes: int = Field(15, alias="LOCKOUT_DURATION_MINUTES")
    encryption_key: str = Field(..., alias="ENCRYPTION_KEY")
    
    # Rate limiting
    rate_limit_requests_login: int = Field(5, alias="RATE_LIMIT_REQUESTS_LOGIN")
    rate_limit_requests_register: int = Field(3, alias="RATE_LIMIT_REQUESTS_REGISTER")
    rate_limit_requests_bid: int = Field(30, alias="RATE_LIMIT_REQUESTS_BID")
    rate_limit_requests_general: int = Field(100, alias="RATE_LIMIT_REQUESTS_GENERAL")
    rate_limit_window: int = Field(60, alias="RATE_LIMIT_WINDOW")
    redis_url: Optional[str] = Field(None, alias="REDIS_URL")
    
    # CORS
    allowed_origins: str = Field("", alias="ALLOWED_ORIGINS")
    
    # Cookie
    cookie_secure: bool = Field(False, alias="COOKIE_SECURE")
    cookie_samesite: str = Field("lax", alias="COOKIE_SAMESITE")
    
    # Environment
    environment: str = Field("development", alias="ENVIRONMENT")
    session_secret: str = Field("", alias="SESSION_SECRET")
    
    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        if v not in ["development", "production", "test"]:
            raise ValueError(f"Invalid environment: {v}")
        return v
    
    @property
    def is_production(self) -> bool:
        return self.environment == "production"
    
    @property
    def is_development(self) -> bool:
        return self.environment == "development"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get settings singleton."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


