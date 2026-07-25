import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    PROJECT_NAME: str = "CyberSentinel AI"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Database
    MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017/cybersentinel")
    MONGO_DB_NAME: str = os.getenv("MONGO_DB_NAME", "cybersentinel")
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "placeholder_secret_key")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    REFRESH_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_MINUTES", "10080")) # Default 7 days
    MAX_FAILED_LOGIN_ATTEMPTS: int = int(os.getenv("MAX_FAILED_LOGIN_ATTEMPTS", "5"))
    ACCOUNT_LOCK_DURATION_MINUTES: int = int(os.getenv("ACCOUNT_LOCK_DURATION_MINUTES", "15"))
    
    # Threat Intel
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    PHISHTANK_API_KEY: str = os.getenv("PHISHTANK_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")

settings = Settings()
