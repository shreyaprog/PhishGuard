import json
import logging
import pickle
import zipfile
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    precision_recall_curve,
    recall_score,
    roc_curve,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from config import DATASET_PATH, MODEL_METADATA_PATH, MODEL_PATH
from .dataset_loader import load_dataset
from .feature_extractor import FEATURE_COLUMNS, extract_features


def build_feature_frame(dataset_rows):
    rows = []
    for row in dataset_rows:
        features = extract_features(row["url"])
        rows.append({**features, "label": row["label"]})
    return pd.DataFrame(rows)


def train_and_save_model(
    dataset_path=DATASET_PATH,
    model_path=MODEL_PATH,
    metadata_path=MODEL_METADATA_PATH,
    dataset_source="User-supplied CSV (source not verified)",
    phishing_label=1,
):
    rows = load_dataset(dataset_path, phishing_label=phishing_label)
    frame = build_feature_frame(rows)
    X = frame[FEATURE_COLUMNS]
    y = frame["label"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    model = Pipeline([
        ("logreg", LogisticRegression(max_iter=4000, class_weight="balanced", random_state=42))
    ])
    model.fit(X_train, y_train)
    preds = model.predict(X_test)
    probs = model.predict_proba(X_test)[:, 1]
    tn, fp, fn, tp = confusion_matrix(y_test, preds, labels=[0, 1]).ravel()
    trained_at = datetime.now().astimezone().isoformat(timespec="seconds")
    false_positive_points, true_positive_points, _ = roc_curve(y_test, probs, pos_label=1)
    curve_precision, curve_recall, _ = precision_recall_curve(y_test, probs, pos_label=1)
    coefficients = model.named_steps["logreg"].coef_[0]

    metrics = {
        "accuracy": round(float(accuracy_score(y_test, preds)), 4),
        "precision": round(float(precision_score(y_test, preds, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, preds, zero_division=0)), 4),
        "f1": round(float(f1_score(y_test, preds, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, probs)), 4) if len(np.unique(y_test)) > 1 else None,
        "average_precision": round(float(average_precision_score(y_test, probs)), 4) if len(np.unique(y_test)) > 1 else None,
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "classification_report": classification_report(
            y_test,
            preds,
            labels=[0, 1],
            target_names=["legitimate", "phishing"],
            output_dict=True,
            zero_division=0,
        ),
        "false_positive_rate": round(float(fp / (fp + tn)), 4) if fp + tn else None,
        "false_negative_rate": round(float(fn / (fn + tp)), 4) if fn + tp else None,
        "dataset_size": len(frame),
        "train_size": len(X_train),
        "test_size": len(X_test),
        "positive_count": int(y.sum()),
        "negative_count": int((1 - y).sum()),
        "class_distribution": {"phishing": int(y.sum()), "legitimate": int((1 - y).sum())},
        "evaluation_method": "Random stratified train/test split (75/25); not domain-grouped.",
        "model_type": "LogisticRegression",
        "dataset_source": dataset_source,
        "source_phishing_label": phishing_label,
        "training_timestamp": trained_at,
        "roc_curve": {
            "false_positive_rate": [round(float(value), 5) for value in false_positive_points],
            "true_positive_rate": [round(float(value), 5) for value in true_positive_points],
        },
        "precision_recall_curve": {
            "precision": [round(float(value), 5) for value in curve_precision],
            "recall": [round(float(value), 5) for value in curve_recall],
        },
        "feature_coefficients": [
            {"feature": name, "coefficient": round(float(value), 5)}
            for name, value in zip(FEATURE_COLUMNS, coefficients)
        ],
    }
    artifact = {
        "model": model,
        "feature_columns": FEATURE_COLUMNS,
        "model_name": "LogisticRegression",
        "training_timestamp": trained_at,
        "dataset_path": str(dataset_path),
        "dataset_source": dataset_source,
        "source_phishing_label": phishing_label,
    }
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, model_path)
    metadata_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return model, metrics


def load_model(model_path=MODEL_PATH):
    if not Path(model_path).exists():
        return None
    try:
        payload = joblib.load(model_path)
        model = payload.get("model") if isinstance(payload, dict) else None
        columns = payload.get("feature_columns") if isinstance(payload, dict) else None
        classifier = model.named_steps.get("logreg") if hasattr(model, "named_steps") else None
        if (
            not isinstance(columns, (list, tuple))
            or list(columns) != FEATURE_COLUMNS
            or classifier is None
            or not hasattr(classifier, "predict_proba")
            or not np.array_equal(classifier.classes_, np.array([0, 1]))
        ):
            logging.warning("Model artefact at %s is incompatible; using rule-only analysis.", model_path)
            return None
        return payload
    except (
        OSError,
        EOFError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        ImportError,
        pickle.UnpicklingError,
        zipfile.BadZipFile,
    ) as exc:
        logging.warning("Could not load model artefact at %s: %s", model_path, exc)
        return None


def predict_url(raw_url: str, model_payload=None):
    features = extract_features(raw_url)
    values = [features[col] for col in FEATURE_COLUMNS]
    if model_payload is None:
        model_payload = load_model()
    if model_payload is None:
        return {"status": "degraded", "label": None, "probability": None}
    model = model_payload.get("model")
    frame = pd.DataFrame([values], columns=FEATURE_COLUMNS)
    probabilities = model.predict_proba(frame)[0]
    classes = list(model.named_steps["logreg"].classes_)
    positive_index = classes.index(1)
    probability = float(probabilities[positive_index])
    label = int(model.predict(frame)[0])
    if not np.isfinite(probability) or not 0 <= probability <= 1 or label not in (0, 1):
        logging.warning("Model returned an invalid prediction; using rule-only analysis.")
        return {"status": "degraded", "label": None, "probability": None}
    return {
        "status": "ok",
        "label": label,
        "probability": probability,
        "explanation": explain_prediction(values, model_payload),
    }


def explain_prediction(values, model_payload=None, limit=5):
    if model_payload is None:
        model_payload = load_model()
    if model_payload is None:
        return []
    classifier = model_payload["model"].named_steps["logreg"]
    contributions = [
        (name, float(value * coefficient))
        for name, value, coefficient in zip(FEATURE_COLUMNS, values, classifier.coef_[0])
        if value != 0 and coefficient != 0
    ]
    contributions.sort(key=lambda item: abs(item[1]), reverse=True)
    return [
        {
            "feature": name,
            "contribution": round(value, 4),
            "direction": "phishing-like" if value > 0 else "legitimate-like",
        }
        for name, value in contributions[:limit]
    ]


def model_status():
    payload = load_model()
    if payload is None:
        return {"available": False, "message": "No trained model artefact is available yet."}
    return {"available": True, "message": "Model loaded successfully."}
