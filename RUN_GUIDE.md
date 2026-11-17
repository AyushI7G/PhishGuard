# PhishGuard - Run Guide

## 1. Install ML Dependencies

pip install -r ml/requirements.txt

---

## 2. Run the Node Backend and ML Service

node server.js

The Node API serves the frontend on `http://127.0.0.1:3000` and starts the
local Flask inference service on `http://127.0.0.1:5001`.
The backend binds to loopback by default. Set `HOST`, `PORT`, and
`CORS_ORIGINS` in the process environment to change the local configuration.
Do not expose the unauthenticated API directly to the internet.

SHAP is used for model explanations when its native dependencies are available.
If SHAP cannot be imported, the inference service logs a warning and falls back
to perturbation-based explanations; email, URL, and attachment inference remain
available.

To retrain from the checked-in datasets before starting the server:

```text
python ml/train.py
```

To train and compare BERT, RoBERTa, CNN, and LSTM email classifiers separately:

```text
python ml/train_neural_models.py
```

This trains on the full CEAS_08 dataset and writes model checkpoints to
`ml/artifacts/neural_models/`. It does not create evaluation metrics or a test
split. BERT and RoBERTa fetch pretrained model weights/tokenizers on first
use. The trained models are separate from the XGBoost models used by the
running application. For a smaller trial, use
`python ml/train_neural_models.py --models cnn lstm --epochs 1 --max-rows 5000`.

To reproduce the five-model, three-dataset comparison (15 combinations):

```text
python --version
python -m pip install -r ml/requirements.txt
python ml/benchmark_models.py
```

The benchmark requires Python 3.10 or newer. It fine-tunes the standard
`bert-base-uncased` and `roberta-base` checkpoints; their resolved model
revision, package versions, dataset checksums, and hyperparameters are saved
with the results. The first run downloads those checkpoints.

The benchmark uses a fixed seed and grouped 60%/20%/20% train/validation/test
splits. URL records are grouped by hostname; CEAS email duplicates are grouped
by normalized sender, subject, and body. It writes one JSON result per
combination, per-epoch training/validation curves, `summary.csv`, and
`run_manifest.json` under `results/model_comparison/`. Precision, recall, and
F1 treat phishing as the positive class; the saved confusion matrix orders
classes as legitimate then phishing.

The PhishTank feed contains positive URLs only. Its benchmark therefore adds
distinct `urldata.csv` URLs labelled `good` as negatives, excluding hosts that
appear in PhishTank positives. The manifest records this mixed-source dataset;
those scores are not PhishTank-only performance. No metrics are claimed until
the benchmark completes. Full BERT/RoBERTa runs can take substantial time and
benefit from a CUDA-capable GPU. For a smoke test, use `--max-rows 1000
--epochs 1`; capped results must not be presented as full-dataset results.
Capped runs sample each class evenly with the fixed seed, so their test-set
metrics reflect the balanced sample rather than each source dataset's natural
class prevalence.

To reproduce and export each model's predictions on the same held-out samples
from a completed benchmark:

```text
python ml/generate_predictions.py
```

This retrains each model with the benchmark settings and pinned transformer
revisions, then writes one JSON and one CSV per model/dataset combination to
`results/predictions/`. Outputs include actual/predicted labels, class
probabilities, confidence, stable sample IDs, and correct/misclassified
examples. `--resume` continues an interrupted export from its completed
combinations. Prediction generation requires the original datasets and the
completed benchmark files to remain unchanged.

To export the saved training/testing settings and split statistics:

```text
python ml/export_methodology.py
```

The exporter validates the manifest and all 15 result files, then writes
`METHODOLOGY.md`, `methodology.json`, and `methodology.csv` in
`results/model_comparison/`. Actual split percentages are calculated from the
saved row counts; they may differ slightly from the requested 60%/20%/20%
because groups are kept intact. Missing or inapplicable settings are not
replaced with assumptions.

To create plots and cautious training/generalization diagnostics from the
saved benchmark history without retraining:

```text
python ml/plot_training_results.py
```

This writes training-curve, test confusion-matrix, and model-comparison charts
plus diagnosis summaries under `results/plots/`. Neural convergence is not
inferred from the single saved epoch, and no missing historical values are
filled in.

To export CNN classification metrics, confusion matrices, and the recorded
training/validation/testing losses for all three datasets:

```text
python ml/export_cnn_evaluation.py
```

The script validates the saved confusion matrices against the benchmark's
classification metrics and writes a formula/report, JSON, and CSV under
`results/cnn_evaluation/`. It does not retrain the CNN.

---

Open `http://127.0.0.1:3000` in the browser. Gmail sign-in uses the configured
Google Identity Services client ID in the frontend and requires that origin to
be authorized in the Google Cloud OAuth client settings.

---

## Features

- Email phishing detection
- URL phishing detection
- SHAP explainability graphs
- Gmail inbox scanning
- Email and Gmail attachment scanning (up to 35 MB total per email)
- Risk score visualization
- XGBoost-based ML prediction

---

## Technologies Used

- Flask
- XGBoost
- SHAP
- Plotly
- Gmail API
- OAuth 2.0
- HTML/CSS/JavaScript

Attachment model metrics are from synthetic training data only and are not a
real-world detection guarantee. Static analysis does not replace antivirus or
sandboxing.
