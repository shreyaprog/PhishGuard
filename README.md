# PhishGuard

PhishGuard is a local phishing URL analysis and threat intelligence application. It lets users submit URLs for a preliminary risk assessment and search a locally maintained list of URL indicators imported from CSV. Analysis is performed locally: the app does not visit submitted URLs and requires no paid cloud infrastructure.

## Project description

Phishing links can trick users into revealing credentials and financial information, potentially leading to unauthorised access to email, cloud storage, and other online services. PhishGuard helps users recognise suspicious links by combining URL analysis with local threat-indicator lookup and clear explanations of the available evidence.

The project demonstrates how an accessible preventive tool can complement cloud security controls such as multi-factor authentication (MFA), identity and access management (IAM), and security monitoring. PhishGuard is an educational, preliminary analysis tool; it does not guarantee that a URL is safe or replace browser protection, reputation services, or cloud security controls.

**Project objective:** Develop a practical, accessible phishing URL analysis tool that helps users identify potentially suspicious links and check them against a locally maintained threat intelligence database.

**Key technologies:** Python, Flask, URL parsing and feature analysis, CSV-based threat intelligence, SQLite, and local data processing. The implemented version also includes a transparent rule engine and an optional scikit-learn model.

## Problem and objectives

Phishing can expose personal and cloud account credentials. PhishGuard demonstrates how static URL characteristics can support an initial risk assessment, explain the evidence behind that assessment, and connect the result to defensive cloud controls. It is an educational tool, not a browser protection product or a guarantee that a site is safe.

## Features

- URL parsing and structural feature extraction; no server-side URL requests.
- Explainable rule findings and a grouped heuristic score.
- Optional logistic-regression model with local feature contributions.
- SQLite scan history, category filtering, deletion, and CSV export.
- Per-scan JSON and printable HTML reports with escaped URL content.
- Local threat-indicator lookup and validated CSV import; this is not a live threat feed.
- Offline model metrics, confusion matrix, ROC and precision-recall plots when trained evaluation data is available.
- Practical security-awareness and cloud-security guidance.
- CSRF checks for state-changing forms and security response headers.

## Technology and project layout

Python 3.11+ (tested here on Python 3.14), Flask, SQLite, scikit-learn, pandas, NumPy, joblib, tldextract, and pytest. Main code is in `app.py` and `src/`; templates and static assets are in `templates/` and `static/`; training scripts are in `training/`; tests are in `tests/`; supporting material is in `docs/`.

## Setup on Windows

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Start in rule-only mode (no dataset or model is bundled):

```powershell
python app.py
```

Open <http://127.0.0.1:5000>. The app binds to localhost by default. Set `HOST` and `PORT` environment variables only for a controlled demonstration. Set a private `SECRET_KEY` environment variable if using a persistent deployment.

## Dataset setup and model training

The workspace does **not** bundle a hand-labelled sample dataset or pre-trained artefact. This avoids presenting invented examples or toy scores as measured model performance.

1. Obtain the public PhiUSIIL Phishing URL Dataset from the [UCI Machine Learning Repository](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset). Follow its license and citation instructions.
2. Save the official CSV as `data\phiusiil_uci_source.csv`. The published class counts identify label `0` as phishing and label `1` as legitimate. The trainer maps the selected source phishing class to its internal label `1`; it reads the source URL field and ignores precomputed web-page feature columns.
3. Inspect the source label mapping and rows before training; the loader rejects missing, malformed, or unsupported labels.
4. Run:

```powershell
python training\train_model.py --dataset data\phiusiil_uci_source.csv --source "UCI PhiUSIIL Phishing URL Dataset (UCI dataset 967)" --phishing-label 0
```

This saves a model to `models\phishing_model.joblib` and real held-out evaluation metadata to `models\model_metadata.json`. The evaluation currently uses a random stratified 75/25 split, not a domain-grouped split; related domains may occur across both sets. Treat metrics as offline dataset results, not real-world accuracy.

Details and supported schema are in [docs/dataset_guide.md](docs/dataset_guide.md).

## Run tests

```powershell
python -m pytest -q
```

## Reports and local indicators

Scan History supports risk filtering, deletion, clear-history confirmation, and CSV export. Each scan offers JSON and printable HTML downloads. The Threat Intelligence page is an explicitly local indicator list, not a live feed; CSV import requires a valid `url` column and skips duplicate URLs. No match means unknown or unverified, not legitimate.

## Troubleshooting

- **Model unavailable:** The app continues with rule-only analysis. Add a correctly labelled CSV and run the training command.
- **Model incompatible:** Remove only the incompatible files in `models/`, retrain from the prepared dataset, and restart the app.
- **Dataset not found:** Follow the UCI acquisition and preparation steps above; no public dataset is silently downloaded.
- **CSV import rejected:** Use UTF-8 CSV with a `url` header and valid `http://` or `https://` URLs. Imports are limited to 2 MB.
- **Port in use:** Set `PORT` to an available local port before starting the app.

## Cloud security connection

Credential theft can enable cloud console access, abuse of excessive IAM permissions, storage exposure, and account takeover. MFA, least privilege, short-lived credentials, audit logging, suspicious sign-in detection, encryption, and incident response are complementary controls. PhishGuard itself does not protect cloud accounts.

## Limitations and future work

URL-only heuristics do not inspect page content or message context. Datasets can be biased or stale; random splits can overestimate generalisation; model probabilities are not guaranteed to be calibrated. Reputation checks and real-time feeds are intentionally not configured. Future work could add a domain-grouped evaluation, user-imported curated indicators, and more evaluation on recent independently sourced datasets.

## Demo

Follow [docs/demo_guide.md](docs/demo_guide.md) for a presentation workflow and [docs/viva_questions.md](docs/viva_questions.md) for viva preparation.
