from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # App
    APP_NAME: str = "PhishGuard"
    DEBUG: bool = False
    SECRET_KEY: str = "change-this-secret-key-in-production"

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./phishguard.db"

    # Redis (rate limiting + cache)
    # Railway provides REDIS_URL automatically when you add Redis plugin
    REDIS_URL: str = "memory://"  # fallback: in-memory (no Redis needed for dev)

    # CORS
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "https://*.railway.app",
        "https://*.up.railway.app",
    ]

    # External Threat Intelligence APIs (gratis)
    # PhishTank: gratis tanpa API key, 1000 req/hari dengan key
    PHISHTANK_API_KEY: str = ""
    # Google Safe Browsing: 10.000 req/hari GRATIS
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    # OpenPhish: gratis feed publik
    OPENPHISH_FEED_URL: str = "https://openphish.com/feed.txt"

    # VirusTotal: 4 req/menit gratis (500/hari)
    VIRUSTOTAL_API_KEY: str = ""

    # File upload limits
    MAX_FILE_SIZE_MB: int = 10
    ALLOWED_FILE_EXTENSIONS: List[str] = [
        ".pdf", ".doc", ".docx", ".xls", ".xlsx",
        ".ppt", ".pptx", ".txt", ".eml", ".msg",
    ]

    # NLP Model
    NLP_MODEL_NAME: str = "distilbert-base-uncased"  # atau path lokal
    NLP_MODEL_PATH: str = "./models/phish_nlp"

    # JWT
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 hari

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
