import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "phishguard.db"
MODEL_DIR = BASE_DIR / "models"
MODEL_PATH = MODEL_DIR / "phishing_model.joblib"
MODEL_METADATA_PATH = MODEL_DIR / "model_metadata.json"
DATASET_PATH = BASE_DIR / "data" / "phishing_dataset.csv"
SECRET_KEY = os.getenv("SECRET_KEY")
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "5000"))
MAX_CONTENT_LENGTH = 16 * 1024 * 1024
THREAT_INTELLIGENCE_PROVIDER = os.getenv("THREAT_INTELLIGENCE_PROVIDER", "urlhaus")
THREAT_INTELLIGENCE_ENABLED = os.getenv("THREAT_INTELLIGENCE_ENABLED", "true").strip().lower() not in {"0", "false", "no", "disabled"}
THREAT_INTELLIGENCE_URLHAUS_API_URL = os.getenv("THREAT_INTELLIGENCE_URLHAUS_API_URL", "https://urlhaus.abuse.ch/api/v1/urls/recent/")
THREAT_INTELLIGENCE_TIMEOUT_SECONDS = int(os.getenv("THREAT_INTELLIGENCE_TIMEOUT_SECONDS", "10"))
THREAT_INTELLIGENCE_MAX_RESPONSE_BYTES = int(os.getenv("THREAT_INTELLIGENCE_MAX_RESPONSE_BYTES", str(1 * 1024 * 1024)))
