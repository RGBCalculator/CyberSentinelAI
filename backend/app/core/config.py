from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, SecretStr

class Settings(BaseSettings):
    PROJECT_NAME: str = "CyberSentinel AI"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"

    # Database
    MONGO_URI: str
    MONGO_DB_NAME: str = Field(default="cybersentinel")

    # Security
    SECRET_KEY: SecretStr
    CORS_ORIGINS: list[str] = Field(default=["http://localhost:3000"])
    ALGORITHM: str = Field(default="HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30)
    REFRESH_TOKEN_EXPIRE_MINUTES: int = Field(default=10080) # Default 7 days
    MAX_FAILED_LOGIN_ATTEMPTS: int = Field(default=5)
    ACCOUNT_LOCK_DURATION_MINUTES: int = Field(default=15)

    # Threat Intel
    VIRUSTOTAL_API_KEY: SecretStr = Field(default=SecretStr(""))
    PHISHTANK_API_KEY: SecretStr = Field(default=SecretStr(""))
    ABUSEIPDB_API_KEY: SecretStr = Field(default=SecretStr(""))

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

settings = Settings()
