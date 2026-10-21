# Methodology

PhishGuard validates and parses a submitted HTTP(S) URL locally. It never opens or fetches that URL. Static features include URL and hostname lengths, subdomain structure, punctuation, query count, IP-host status, explicit ports, percent encoding, punycode, and selected account/payment keyword groups.

The independent rule engine produces findings with an identifier, severity, URL evidence, rationale, recommendation, and limitation. Rules are grouped before scoring to avoid adding multiple highly correlated indicators from the same category. The resulting score is a transparent heuristic from 0–100; it is not a probability.

Rule groups contribute at most 35 points for host structure, 20 for obfuscation, and 15 for sensitive words. When a model exists, the combined heuristic score is `55% * model score (0-100) + 45% * rule score`; in rule-only mode it is the rule score. A combined score of 70+ or a model score at least 0.80 is high risk. A combined score of 35-69 or a model score at least 0.65 is suspicious. Lower scores with model support below 0.40 (or with no model) are low apparent risk; remaining cases are inconclusive. These thresholds are review aids, not calibrated probability cutoffs.

When a compatible trained model exists, logistic regression returns a phishing-class score and class label. A per-URL explanation is calculated from the fitted linear coefficients and that URL's feature values. These contributions describe the fitted model's logit direction, not causal evidence. Global coefficients are shown separately from an individual scan explanation.

Training uses a random, stratified 75/25 split. Accuracy, precision, recall, F1, confusion matrix, false-positive rate, false-negative rate, ROC-AUC, average precision and curves are computed from the held-out partition. A random split can put related URLs/domains or campaigns in both partitions; domain-grouped or time-based evaluation is needed for stronger generalisation claims. Offline scores are not guarantees about current threats.
