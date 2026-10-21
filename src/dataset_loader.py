import csv
from pathlib import Path


def load_dataset(path, phishing_label=1):
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")
    rows = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        field_map = {
            name.strip().lower(): name
            for name in (reader.fieldnames or [])
            if name and name.strip()
        }
        url_column = next((field_map[key] for key in ("url", "website") if key in field_map), None)
        label_column = next(
            (field_map[key] for key in ("label", "class", "phishing", "target") if key in field_map),
            None,
        )
        if url_column is None or label_column is None:
            raise ValueError("Dataset must include URL and label columns.")
        for row in reader:
            url = (row.get(url_column) or "").strip()
            label = row.get(label_column)
            if not url or label is None or label == "":
                continue
            try:
                numeric_label = float(label)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Dataset row {reader.line_num} has a non-numeric label.") from exc
            if not numeric_label.is_integer():
                raise ValueError(f"Dataset row {reader.line_num} has a non-integer label.")
            raw_label = int(numeric_label)
            rows.append({"url": url, "label": int(raw_label == phishing_label)})
    if not rows:
        raise ValueError(f"No valid rows found in dataset: {path}")
    labels = {row["label"] for row in rows}
    if not labels.issubset({0, 1}) or labels != {0, 1}:
        raise ValueError("Dataset labels must contain both 0 (legitimate) and 1 (phishing), and no other values.")
    if min(sum(row["label"] == label for row in rows) for label in (0, 1)) < 3:
        raise ValueError("At least three examples of each label are required for a stratified split.")
    return rows
