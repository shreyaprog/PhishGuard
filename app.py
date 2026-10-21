import json
import logging
import csv
import sqlite3
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from secrets import compare_digest, token_urlsafe

from flask import Flask, abort, flash, jsonify, make_response, redirect, render_template, request, session, url_for

from config import HOST, MAX_CONTENT_LENGTH, MODEL_METADATA_PATH, PORT, SECRET_KEY
from src.database import (
    add_scan,
    clear_history,
    delete_scan,
    get_dashboard_stats,
    get_indicator_count,
    get_indicators,
    get_scan_by_id,
    get_scan_history,
    history_csv_content,
    import_indicators_from_csv,
    init_db,
    search_indicators,
)
from src.predictor import load_model, predict_url
from src.report_generator import render_html_report
from src.risk_scorer import combine_signals
from src.rule_engine import run_rule_engine
from src.url_parser import parse_url, validate_url

app = Flask(__name__)
app.secret_key = SECRET_KEY or token_urlsafe(32)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
init_db()


@app.context_processor
def provide_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = token_urlsafe(32)
    return {"csrf_token": session["_csrf_token"]}


@app.before_request
def protect_state_changes():
    if request.method == "POST":
        submitted = request.form.get("csrf_token", "")
        expected = session.get("_csrf_token", "")
        if not expected or not compare_digest(submitted.encode("utf-8"), expected.encode("utf-8")):
            abort(400, description="Invalid or missing form security token.")


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'self'; object-src 'none'"
    )
    return response


def _model_label_to_text(label):
    if label == 1:
        return "phishing-like"
    if label == 0:
        return "likely legitimate"
    return "unknown"


@app.route("/")
def dashboard():
    stats = get_dashboard_stats()
    return render_template("dashboard.html", stats=stats)


@app.route("/scan", methods=["GET", "POST"])
def scan_page():
    if request.method == "GET":
        return render_template("scan.html", result=None, error=None, submitted_url=None)
    submitted_url = request.form.get("url", "")
    if not submitted_url.strip():
        return render_template("scan.html", result=None, error="URL is required.", submitted_url="")
    if len(submitted_url.strip()) > 2048:
        return render_template(
            "scan.html",
            result=None,
            error="URL is too long for interactive scanning (maximum 2048 characters).",
            submitted_url=submitted_url,
        )
    valid, msg = validate_url(submitted_url)
    if not valid:
        return render_template("scan.html", result=None, error=msg, submitted_url=submitted_url)
    parsed = parse_url(submitted_url)
    findings = run_rule_engine(submitted_url)
    model_payload = load_model()
    model_out = predict_url(submitted_url, model_payload) if model_payload else {"status": "degraded", "label": None, "probability": None}
    model_available = model_out["status"] == "ok"
    score_info = combine_signals(model_probability=model_out.get("probability"), findings=findings)
    explanation = "The overall score is a heuristic that combines model output and grouped rule signals; it is not a calibrated probability."
    if score_info["signals_disagree"]:
        explanation += " The model and rule engine disagree; review both sets of evidence."
    if not model_available:
        explanation = "The model is unavailable or returned an unusable prediction, so the result uses rule-based analysis only. The score is not a probability."

    result = {
        "submitted_url": submitted_url,
        "normalised_url": parsed["normalised"],
        "scan_time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model_verdict": _model_label_to_text(model_out.get("label")) if model_out.get("label") is not None else "unknown",
        "model_probability": model_out.get("probability"),
        "rule_score": score_info["rule_score"],
        "risk_score": score_info["risk_score"],
        "overall_risk": score_info["overall_risk"],
        "signals_disagree": score_info["signals_disagree"],
        "model_explanation": model_out.get("explanation", []),
        "model_metadata": {
            "model_type": model_payload.get("model_name"),
            "dataset_source": model_payload.get("dataset_source"),
            "training_timestamp": model_payload.get("training_timestamp"),
        } if model_available else {},
        "findings": findings,
        "model_version": "logistic-regression" if model_available else "degraded-mode",
        "analysis_status": "complete" if model_available else "degraded",
        "explanation": explanation,
    }
    scan_id = add_scan(result)
    result["id"] = scan_id
    return render_template("scan.html", result=result, error=None, submitted_url=submitted_url)


@app.route("/history")
def history_page():
    category = request.args.get("risk", "")
    search = request.args.get("q", "").strip()[:256]
    allowed_categories = {"", "High risk", "Suspicious", "Low apparent risk", "Inconclusive"}
    if category not in allowed_categories:
        category = ""
    rows = get_scan_history(limit=50, category=category or None, search=search or None)
    return render_template("history.html", history=rows, selected_risk=category, search=search)


@app.route("/history/export.csv")
def export_history():
    response = make_response(history_csv_content())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=phishguard-history.csv"
    return response


@app.route("/history/delete/<int:scan_id>", methods=["POST"])
def delete_history_item(scan_id):
    if get_scan_by_id(scan_id) is None:
        abort(404)
    delete_scan(scan_id)
    flash("Scan record deleted.")
    return redirect(url_for("history_page"))


@app.route("/history/clear", methods=["POST"])
def clear_history_page():
    if request.form.get("confirm") != "yes":
        flash("Confirm the clear-history action before continuing.")
        return redirect(url_for("history_page"))
    clear_history()
    flash("Scan history cleared.")
    return redirect(url_for("history_page"))


@app.route("/history/<int:scan_id>")
def scan_detail_page(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return "Not found", 404
    return render_template("scan_detail.html", scan=scan)


@app.route("/history/<int:scan_id>/report.json")
def scan_json_report(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return "Not found", 404
    response = make_response(jsonify(scan))
    response.headers["Content-Disposition"] = f"attachment; filename=phishguard-scan-{scan_id}.json"
    return response


@app.route("/history/<int:scan_id>/report.html")
def scan_html_report(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return "Not found", 404
    response = make_response(render_html_report(scan))
    response.headers["Content-Disposition"] = f"attachment; filename=phishguard-scan-{scan_id}.html"
    return response


@app.route("/threat-intelligence")
def threat_intelligence_page():
    query = request.args.get("q", "")
    results = search_indicators(query) if query else []
    return render_template(
        "threat_intelligence.html",
        indicators=get_indicators(),
        indicator_count=get_indicator_count(),
        query=query,
        results=results,
    )


@app.route("/threat-intelligence/upload", methods=["POST"])
def upload_indicators():
    file = request.files.get("csv_file")
    if not file or not file.filename or not file.filename.lower().endswith(".csv"):
        flash("Choose a CSV file to import.")
        return redirect(url_for("threat_intelligence_page"))
    content = file.stream.read(2 * 1024 * 1024 + 1)
    if len(content) > 2 * 1024 * 1024:
        flash("CSV file exceeds the 2 MB import limit.")
        return redirect(url_for("threat_intelligence_page"))
    try:
        text = content.decode("utf-8-sig")
        imported = import_indicators_from_csv(StringIO(text))
    except (UnicodeDecodeError, ValueError, csv.Error) as exc:
        flash(f"CSV import failed: {exc}")
        return redirect(url_for("threat_intelligence_page"))
    except sqlite3.Error:
        logging.exception("Threat indicator import failed while writing to SQLite.")
        flash("CSV import failed because the local indicator database could not be updated.")
        return redirect(url_for("threat_intelligence_page"))
    flash(f"Imported {imported} new indicator(s). Duplicate indicators were skipped.")
    return redirect(url_for("threat_intelligence_page"))


@app.route("/model-performance")
def model_performance_page():
    metrics = {}
    metrics_error = None
    payload = load_model()
    if payload is None:
        metrics_error = "No compatible trained model is available; performance metrics are not shown."
    elif Path(MODEL_METADATA_PATH).exists():
        try:
            metrics = json.loads(Path(MODEL_METADATA_PATH).read_text(encoding="utf-8"))
            if not isinstance(metrics, dict):
                raise ValueError("Evaluation metadata must be a JSON object.")
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            logging.warning("Could not read model evaluation metadata: %s", exc)
            metrics_error = "Saved model evaluation metadata could not be read."
            metrics = {}
    elif payload is not None:
        metrics_error = "Model artefact exists but has no saved evaluation metadata."

    def svg_points(x_values, y_values):
        if not isinstance(x_values, list) or not isinstance(y_values, list) or len(x_values) != len(y_values):
            return ""
        points = []
        for x_value, y_value in zip(x_values, y_values):
            try:
                x = float(x_value)
                y = float(y_value)
            except (TypeError, ValueError):
                return ""
            if not 0 <= x <= 1 or not 0 <= y <= 1:
                return ""
            points.append(f"{10 + x * 80:.1f},{90 - y * 80:.1f}")
        return " ".join(points)

    roc_curve = metrics.get("roc_curve", {})
    pr_curve = metrics.get("precision_recall_curve", {})
    coefficients = metrics.get("feature_coefficients", [])
    if isinstance(coefficients, list):
        coefficients = sorted(
            (item for item in coefficients if isinstance(item, dict)),
            key=lambda item: abs(float(item.get("coefficient", 0)))
            if isinstance(item.get("coefficient", 0), (int, float)) else 0,
            reverse=True,
        )[:8]
    else:
        coefficients = []
    return render_template(
        "model_performance.html",
        metrics=metrics,
        metrics_error=metrics_error,
        roc_points=svg_points(
            roc_curve.get("false_positive_rate"), roc_curve.get("true_positive_rate")
        ) if isinstance(roc_curve, dict) else "",
        pr_points=svg_points(
            pr_curve.get("recall"), pr_curve.get("precision")
        ) if isinstance(pr_curve, dict) else "",
        coefficients=coefficients,
    )


@app.route("/security-guide")
def security_guide_page():
    return render_template("security_guide.html")


@app.route("/cloud-security")
def cloud_security_page():
    return render_template("cloud_security.html")


@app.route("/about")
def about_page():
    return render_template("about.html")


@app.route("/report/<int:scan_id>")
def report_download(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return "Not found", 404
    response = make_response(render_html_report(scan))
    response.headers["Content-Disposition"] = f"attachment; filename=phishguard-scan-{scan_id}.html"
    return response


if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=False)
