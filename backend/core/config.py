from pydantic_settings import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    # App
    APP_NAME: str = "syl-pentools API"
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api/v1"
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql+asyncpg://pentest:pentest@localhost:5432/pentest")
    DATABASE_SYNC_URL: str = os.getenv("DATABASE_SYNC_URL", "postgresql://pentest:pentest@localhost:5432/pentest")
    
    # Redis
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    # Celery
    CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/1")
    CELERY_RESULT_BACKEND: str = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/2")
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    
    # Scanners
    NUCLEI_TEMPLATES_PATH: str = os.getenv("NUCLEI_TEMPLATES_PATH", "/opt/nuclei-templates")
    NMAP_PATH: str = os.getenv("NMAP_PATH", "nmap")
    
    # Reports
    REPORTS_DIR: str = os.getenv("REPORTS_DIR", "/tmp/reports")
    TEMPLATES_DIR: str = os.getenv("TEMPLATES_DIR", "/app/templates")
    
    # WebSocket
    WS_HEARTBEAT_INTERVAL: int = 30
    
    # Frontend URL for email links
    APP_URL: str = os.getenv("APP_URL", "http://localhost:3000")
    
    # Stripe
    STRIPE_SECRET_KEY: str = os.getenv("STRIPE_SECRET_KEY", "")
    STRIPE_PUBLISHABLE_KEY: str = os.getenv("STRIPE_PUBLISHABLE_KEY", "")
    STRIPE_WEBHOOK_SECRET: str = os.getenv("STRIPE_WEBHOOK_SECRET", "")
    STRIPE_PRICE_FREE: str = os.getenv("STRIPE_PRICE_FREE", "")
    STRIPE_PRICE_NETSCAN: str = os.getenv("STRIPE_PRICE_NETSCAN", "")
    STRIPE_PRICE_APPSCAN: str = os.getenv("STRIPE_PRICE_APPSCAN", "")
    STRIPE_PRICE_EXPLOIT: str = os.getenv("STRIPE_PRICE_EXPLOIT", "")
    STRIPE_PRICE_ENTERPRISE: str = os.getenv("STRIPE_PRICE_ENTERPRISE", "")
    
    # MFA / SSO
    MFA_ISSUER: str = os.getenv("MFA_ISSUER", "Pentest Tools")
    SAML_ENTITY_ID: str = os.getenv("SAML_ENTITY_ID", "")
    SAML_ACS_URL: str = os.getenv("SAML_ACS_URL", "")
    SAML_METADATA_URL: str = os.getenv("SAML_METADATA_URL", "")
    SAML_X509_CERT: str = os.getenv("SAML_X509_CERT", "")
    SAML_PRIVATE_KEY: str = os.getenv("SAML_PRIVATE_KEY", "")
    OIDC_CLIENT_ID: str = os.getenv("OIDC_CLIENT_ID", "")
    OIDC_CLIENT_SECRET: str = os.getenv("OIDC_CLIENT_SECRET", "")
    OIDC_DISCOVERY_URL: str = os.getenv("OIDC_DISCOVERY_URL", "")
    
    # Email
    SMTP_HOST: str = os.getenv("SMTP_HOST", "")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER: str = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM: str = os.getenv("SMTP_FROM", "noreply@syl-pentools.local")
    SMTP_TLS: bool = os.getenv("SMTP_TLS", "true").lower() == "true"
    
    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "allow"

settings = Settings()