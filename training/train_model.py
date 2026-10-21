import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.predictor import train_and_save_model

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the PhishGuard URL classifier.")
    parser.add_argument("--dataset", type=Path, default=ROOT / "data" / "phishing_dataset.csv")
    parser.add_argument(
        "--source",
        default="User-supplied CSV (source not verified)",
        help="Dataset source label to record in evaluation metadata.",
    )
    parser.add_argument(
        "--phishing-label",
        type=int,
        choices=(0, 1),
        default=1,
        help="Which value in the source dataset represents phishing; this class is mapped to model label 1.",
    )
    args = parser.parse_args()
    train_and_save_model(
        dataset_path=args.dataset,
        dataset_source=args.source,
        phishing_label=args.phishing_label,
    )
    print("Model trained successfully.")
