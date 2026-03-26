import os
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env'))

class Config:
    SECRET_KEY         = os.getenv("SECRET_KEY", "dev-secret-change-in-production")
    DB_HOST            = os.getenv("DB_HOST", "localhost")
    DB_PORT            = int(os.getenv("DB_PORT", 3306))
    DB_NAME            = os.getenv("DB_NAME", "DPP")
    DB_USER            = os.getenv("DB_USER", "root")
    DB_PASSWORD        = os.getenv("DB_PASSWORD", "")
    JWT_EXPIRY_HOURS   = int(os.getenv("JWT_EXPIRY_HOURS", 8))
    FLASK_DEBUG        = os.getenv("FLASK_DEBUG", "0") == "1"
    PASSPORT_BASE_URL  = os.getenv("PASSPORT_BASE_URL", "http://localhost:5000")
    REDIS_URL          = os.getenv("REDIS_URL", "memory://")
    ALLOWED_ORIGINS    = os.getenv("ALLOWED_ORIGINS", "http://localhost:5000")
