"""
PhishGuard AI - Application Configuration
Uses Pydantic Settings to load and validate environment settings.
"""

from typing import List, Optional, Union, Dict, Any
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "PhishGuard AI"
    APP_ENV: str = "development"
    DEBUG: Any = True
    
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    
    # Database
    DATABASE_URL: str = "sqlite:///./app.db"
    
    # JWT & Auth
    JWT_SECRET_KEY: str = "development-super-secret-key-change-in-production-32bytesmin"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440 # 24 hours
    
    # ML Models
    ML_MODEL_PATH: str = "ml/models/phishing_model.joblib"
    ML_METADATA_PATH: str = "ml/models/model_metadata.json"
    
    # CORS
    CORS_ORIGINS: Union[str, List[str]] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ]
    
    # Rate Limiting
    RATE_LIMIT_LOGIN_PER_MINUTE: int = 10
    RATE_LIMIT_SCAN_PER_MINUTE: int = 60

    # ── Layer 1: Threat Intelligence API Keys (all optional) ──
    VIRUSTOTAL_API_KEY: Optional[str] = None
    GOOGLE_SAFE_BROWSING_KEY: Optional[str] = None
    PHISHTANK_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None

    # ── Layer 3 & 5: Headless Sandbox & Canary ──
    ENABLE_LAYER3_SANDBOX: bool = False  # Requires Playwright + Chromium
    ENABLE_LAYER5_CANARY: bool = False   # Requires Layer 3 sandbox

    # ── Layer 4: AI Multi-Modal (NLP / Vision) ──
    GEMINI_API_KEY: Optional[str] = None   # For LLM-powered NLP analysis
    OPENAI_API_KEY: Optional[str] = None   # Alternative LLM provider

    # ── Pipeline Configuration ──
    SCREENSHOT_DIR: str = "ml/screenshots"
    BRAND_DOMAINS_PATH: str = "ml/datasets/brand_domains.json"
    LAYER_TIMEOUT_SECONDS: float = 5.0     # Per-layer network timeout

    # ── Layer 6: Ensemble Weight Configuration ──
    # Weights for the ensemble risk scoring formula:
    # Total = w1(Static/Lexical) + w2(Network/JARM) + w3(DOM/Script) + w4(Vision/Logo) + w5(NLP/Urgency)
    ENSEMBLE_W1_STATIC: float = 0.30       # Layer 1: Pre-Fetch Analytics
    ENSEMBLE_W2_NETWORK: float = 0.20      # Layer 2: Network Transport
    ENSEMBLE_W3_DOM: float = 0.20          # Layer 3: DOM & Script Heuristics
    ENSEMBLE_W4_VISION: float = 0.15       # Layer 4: Vision Match
    ENSEMBLE_W5_NLP: float = 0.15          # Layer 4/5: NLP Urgency + Canary

    @field_validator("CORS_ORIGINS", mode="before")
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",") if i.strip()]
        if isinstance(v, list):
            return list(v)
        raise ValueError(v)

    @model_validator(mode="after")
    def validate_security_settings(self) -> "Settings":
        if self.APP_ENV == "production":
            if "development" in self.JWT_SECRET_KEY.lower() or len(self.JWT_SECRET_KEY) < 32:
                raise ValueError(
                    "CRITICAL SECURITY RISK: In production mode, JWT_SECRET_KEY must be a cryptographically "
                    "secure random string of at least 32 characters loaded from environment secrets."
                )
        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
