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
