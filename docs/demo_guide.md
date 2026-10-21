# Live demo guide

1. Start the Flask app with `python app.py` and open `http://127.0.0.1:5000`.
2. Show the Dashboard. Its counts are based on locally stored scans; new installations display zeros rather than sample activity.
3. Open Scan URL and test a reserved example such as `https://login.example.test/account/verify`. Explain that indicators are not proof and the server does not visit the URL.
4. Review the evidence, grouped rule score, overall heuristic score, and rule-only notice if a trained dataset/model is unavailable.
5. Open Scan History, apply a risk filter, view a record, then show JSON/HTML downloads and CSV export. Use the confirmation prompt only if you intend to delete demo data.
6. Show Threat Intelligence. Explain that it contains only locally imported records, and that no match does not mean safe. Demonstrate CSV import only with a clearly labelled test file.
7. Open Model Performance. Until a real public dataset has been prepared and model training has completed, there should be no metrics. If trained, explain offline split limitations and error rates.
8. Finish with Cloud Security Impact and the Security Awareness Guide. Emphasize MFA, least privilege, logging, and customer responsibilities.

Use only reserved `.test` example domains during demonstrations; do not submit live suspicious URLs unless you have permission and a suitable safety process.
