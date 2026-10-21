import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import MODEL_METADATA_PATH
from src.predictor import load_model

if __name__ == "__main__":
    if load_model() is None:
        raise SystemExit("No compatible trained model found. Prepare a dataset and run training/train_model.py first.")
    if not MODEL_METADATA_PATH.exists():
        raise SystemExit("No saved evaluation metadata found. Retrain the model to generate evaluation results.")
    data = json.loads(MODEL_METADATA_PATH.read_text(encoding="utf-8"))
    print(json.dumps(data, indent=2))
