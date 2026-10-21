# Dataset guide

## Recommended source

Use the [PhiUSIIL Phishing URL Dataset on UCI](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset). Download it manually from the official repository page, review its documentation, license and citation, and keep a copy of the original data separately. PhishGuard does not automatically download datasets.

The repository does not include fabricated training rows or a model trained on a tiny demonstration sample. Until a real dataset is prepared and the model is trained, the application operates in rule-only mode and the performance page shows no evaluation metrics.

## Prepare the CSV

You can train directly from UCI's CSV by selecting its `URL` and `label` columns. The source includes additional web-page features; PhishGuard ignores them and extracts its own URL-only features. The source contains 235,795 rows: 100,945 with label `0` and 134,850 with label `1`. UCI describes 100,945 phishing and 134,850 legitimate URLs, so this dataset's mapping is `0 = phishing`, `1 = legitimate`. PhishGuard's trainer takes an explicit `--phishing-label` option and maps that raw class to its internal positive class `1`.

For other sources, a prepared two-column CSV may use:

```csv
url,label
https://reserved-example.test/path,0
https://another-reserved-example.test/path,1
```

The rows above only illustrate the file shape; they are not phishing ground truth and must not be used to train or evaluate the model. Populate the file using the dataset's URL and target columns, preserving its documented label meaning. Pass the source's phishing class explicitly with `--phishing-label`. Do not use precomputed labels from unrelated sources or infer labels from the URL's appearance.

The CSV loader accepts `url`, `URL`, or `website` for the URL field and `label`, `class`, `phishing`, or `target` for the label field. Labels must be integers `0` or `1`, and both classes must be present. For a new dataset version, manually verify that target mapping before training.

## Train and evaluate

From the project root:

```powershell
python training\train_model.py --dataset data\phiusiil_uci_source.csv --source "UCI PhiUSIIL Phishing URL Dataset (UCI dataset 967)" --phishing-label 0
```

The script extracts URL features, performs a random stratified 75/25 split, fits logistic regression, and saves the model and evaluation metadata in `models/`. Reported metrics, ROC/precision-recall points, and confusion matrix come from the held-out split. This split is not grouped by domain or campaign, so leakage can make scores optimistic. It does not establish real-world accuracy.
