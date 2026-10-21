import numpy as np

from src.predictor import load_model, predict_url, train_and_save_model


def test_missing_model_is_degraded(tmp_path):
    assert load_model(tmp_path / "not-trained.joblib") is None


def test_training_saves_model_metadata_and_explanation(tmp_path):
    dataset = tmp_path / "training.csv"
    dataset.write_text(
        "url,label\n"
        "https://plain-one.example.test,0\n"
        "https://plain-two.example.test,0\n"
        "https://plain-three.example.test,0\n"
        "https://plain-four.example.test,0\n"
        "https://verify-login-one.example.test/reset,1\n"
        "https://verify-login-two.example.test/reset,1\n"
        "https://verify-login-three.example.test/reset,1\n"
        "https://verify-login-four.example.test/reset,1\n",
        encoding="utf-8",
    )
    model_path = tmp_path / "model.joblib"
    metadata_path = tmp_path / "metadata.json"
    train_and_save_model(dataset, model_path, metadata_path)

    payload = load_model(model_path)
    prediction = predict_url("https://verify-login.example.test/reset", payload)
    assert prediction["status"] == "ok"
    assert 0 <= prediction["probability"] <= 1
    assert prediction["explanation"]
    metadata = metadata_path.read_text(encoding="utf-8")
    assert '"false_positive_rate"' in metadata
    assert '"roc_curve"' in metadata


def test_invalid_model_probability_degrades():
    class FakeClassifier:
        classes_ = np.array([0, 1])

    class FakeModel:
        named_steps = {"logreg": FakeClassifier()}

        @staticmethod
        def predict_proba(_frame):
            return np.array([[0.1, 1.2]])

        @staticmethod
        def predict(_frame):
            return np.array([1])

    prediction = predict_url(
        "https://example.test",
        {"model": FakeModel(), "feature_columns": []},
    )
    assert prediction["status"] == "degraded"
    assert prediction["probability"] is None
