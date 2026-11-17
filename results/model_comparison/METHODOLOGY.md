# Recorded Training and Testing Methodology

Generated from the completed benchmark manifest and all 15 per-run result files. Counts and settings below are recorded values; split percentages are derived from the recorded row counts. Requested percentages are not substituted for the actual grouped-split counts.

## Run-wide settings

- Seed: `42`
- Row cap per dataset: `1000`
- Row-cap policy: Deterministic class-balanced random sampling using the run seed.
- Split procedure: StratifiedGroupKFold: 5 folds for 20% test, then 4 folds on the remaining 80% for 60% train / 20% validation / 20% test.
- Dataset checksums: recorded in [`run_manifest.json`](./run_manifest.json).
- Positive class: phishing; decision threshold: 0.5.
- Test loss: unweighted binary log loss.

## Dataset construction and grouping

| Dataset | Input records / preprocessing | Group key |
|---|---|---|
| `ceas_08` | Rows with labels 0 or 1; input text concatenates sender, subject, body, and URLs when present. | SHA-256 of lowercased sender, subject, and body after whitespace normalization. |
| `urldata` | Non-empty URLs labelled good (0) or bad (1); input is the URL. | Normalized URL hostname. |
| `phishtank` | Verified=yes and online=yes PhishTank URLs are positive; distinct URLData good URLs on hosts absent from the positive feed are negative. Input is the URL. | Normalized URL hostname across PhishTank positives and URLData negatives. |

The PhishTank benchmark is a mixed-source set: verified and online PhishTank positives plus URLData `good` negatives whose hosts do not occur in the positive feed. It is not a PhishTank-only evaluation.

## Leakage controls

- A deterministic class-balanced row cap is applied before splitting when configured.
- StratifiedGroupKFold creates a 20% test split first, then a 25% validation split of the remaining 80%; requested proportions are 60% train / 20% validation / 20% test, while recorded row counts are authoritative.
- The benchmark checks that no group occurs in more than one split.
- TF-IDF and the CNN/LSTM vocabulary are fitted on training text only; validation and test text are transformed using those training-fitted features.
- Class weights are computed from training labels only. Validation loss is used for early stopping/checkpoint selection; the held-out test split is used for final metrics.
- The report cannot establish that external pretrained-transformer pretraining corpora are disjoint from these datasets.

## All 15 combinations

Class counts use `legitimate / phishing` order. Percentages are each split's share of that combination's recorded dataset rows.

| Dataset | Model | Rows | Train rows (%) | Validation rows (%) | Test rows (%) | Groups train/val/test | Class counts train; val; test | Optimizer | Learning rate | Batch | Loss / selection | Epochs or boosting rounds | Other recorded hyperparameters |
|---|---|---:|---|---|---|---|---|---|---:|---:|---|---|---|
| `ceas_08` | `xgboost` | 1000 | 600 (60.00%) | 200 (20.00%) | 200 (20.00%) | 600/200/200 | train: 300/300; validation: 100/100; test: 100/100 | Not applicable (gradient-boosted trees) | 0.08 | Not applicable | binary:logistic objective; validation logloss is monitored for early stopping (error and logloss are evaluated). | Not epoch-based; max 500 rounds, 38 curve rounds, best validation round 37; patience 1 | `{"max_features": 100000, "ngram_range": [1, 2], "min_df": 2, "max_depth": 6, "scale_pos_weight": 1.0, "threads": 11}` |
| `ceas_08` | `bert` | 1000 | 600 (60.00%) | 200 (20.00%) | 200 (20.00%) | 600/200/200 | train: 300/300; validation: 100/100; test: 100/100 | AdamW | 2e-05 | 16 | Weighted cross-entropy; class weights computed from training labels. | 1 requested / 1 recorded; best epoch 1; early-stopping patience 1 | `{"checkpoint": "google-bert/bert-base-uncased", "resolved_revision": "86b5e0934494bd15c9632b12f734a8a67f723594", "max_length": 128, "class_weighting": "balanced"}` |
| `ceas_08` | `roberta` | 1000 | 600 (60.00%) | 200 (20.00%) | 200 (20.00%) | 600/200/200 | train: 300/300; validation: 100/100; test: 100/100 | AdamW | 2e-05 | 16 | Weighted cross-entropy; class weights computed from training labels. | 1 requested / 1 recorded; best epoch 1; early-stopping patience 1 | `{"checkpoint": "FacebookAI/roberta-base", "resolved_revision": "e2da8e2f811d1448a5b465c236feacd80ffbac7b", "max_length": 128, "class_weighting": "balanced"}` |
| `ceas_08` | `cnn` | 1000 | 600 (60.00%) | 200 (20.00%) | 200 (20.00%) | 600/200/200 | train: 300/300; validation: 100/100; test: 100/100 | AdamW | 0.001 | 128 | Weighted cross-entropy; class weights computed from training labels. | 1 requested / 1 recorded; best epoch 1; early-stopping patience 1 | `{"embedding_dim": 96, "vocab_size_limit": 50000, "max_length": 128, "class_weighting": "balanced"}` |
| `ceas_08` | `lstm` | 1000 | 600 (60.00%) | 200 (20.00%) | 200 (20.00%) | 600/200/200 | train: 300/300; validation: 100/100; test: 100/100 | AdamW | 0.001 | 128 | Weighted cross-entropy; class weights computed from training labels. | 1 requested / 1 recorded; best epoch 1; early-stopping patience 1 | `{"embedding_dim": 96, "vocab_size_limit": 50000, "max_length": 128, "class_weighting": "balanced"}` |
| `urldata` | `xgboost` | 1000 | 600 (60.00%) | 200 (20.00%) | 200 (20.00%) | 526/176/171 | train: 300/300; validation: 100/100; test: 100/100 | Not applicable (gradient-boosted trees) | 0.08 | Not applicable | binary:logistic objective; validation logloss is monitored for early stopping (error and logloss are evaluated). | Not epoch-based; max 500 rounds, 54 curve rounds, best validation round 53; patience 1 | `{"max_features": 100000, "ngram_range": [1, 2], "min_df": 2, "max_depth": 6, "scale_pos_weight": 1.0, "threads": 11}` |
| `urldata` | `bert` | 1000 | 600 (60.00%) | 200 (20.00%) | 200 (20.00%) | 526/176/171 | train: 300/300; validation: 100/100; test: 100/100 | AdamW | 2e-05 | 16 | Weighted cross-entropy; class weights computed from training labels. | 1 requested / 1 recorded; best epoch 1; early-stopping patience 1 | `{"checkpoint": "google-bert/bert-base-uncased", "resolved_revision": "86b5e0934494bd15c9632b12f734a8a67f723594", "max_length": 128, "class_weighting": "balanced"}` |
| `urldata` | `roberta` | 1000 | 600 (60.00%) | 200 (20.00%) | 200 (20.00%) | 526/176/171 | train: 300/300; validation: 100/100; test: 100/100 | AdamW | 2e-05 | 16 | Weighted cross-entropy; class weights computed from training labels. | 1 requested / 1 recorded; best epoch 1; early-stopping patience 1 | `{"checkpoint": "FacebookAI/roberta-base", "resolved_revision": "e2da8e2f811d1448a5b465c236feacd80ffbac7b", "max_length": 128, "class_weighting": "balanced"}` |
| `urldata` | `cnn` | 1000 | 600 (60.00%) | 200 (20.00%) | 200 (20.00%) | 526/176/171 | train: 300/300; validation: 100/100; test: 100/100 | AdamW | 0.001 | 128 | Weighted cross-entropy; class weights computed from training labels. | 1 requested / 1 recorded; best epoch 1; early-stopping patience 1 | `{"embedding_dim": 96, "vocab_size_limit": 50000, "max_length": 128, "class_weighting": "balanced"}` |
| `urldata` | `lstm` | 1000 | 600 (60.00%) | 200 (20.00%) | 200 (20.00%) | 526/176/171 | train: 300/300; validation: 100/100; test: 100/100 | AdamW | 0.001 | 128 | Weighted cross-entropy; class weights computed from training labels. | 1 requested / 1 recorded; best epoch 1; early-stopping patience 1 | `{"embedding_dim": 96, "vocab_size_limit": 50000, "max_length": 128, "class_weighting": "balanced"}` |
| `phishtank` | `xgboost` | 1000 | 600 (60.00%) | 200 (20.00%) | 200 (20.00%) | 528/178/174 | train: 300/300; validation: 100/100; test: 100/100 | Not applicable (gradient-boosted trees) | 0.08 | Not applicable | binary:logistic objective; validation logloss is monitored for early stopping (error and logloss are evaluated). | Not epoch-based; max 500 rounds, 90 curve rounds, best validation round 89; patience 1 | `{"max_features": 100000, "ngram_range": [1, 2], "min_df": 2, "max_depth": 6, "scale_pos_weight": 1.0, "threads": 11}` |
| `phishtank` | `bert` | 1000 | 600 (60.00%) | 200 (20.00%) | 200 (20.00%) | 528/178/174 | train: 300/300; validation: 100/100; test: 100/100 | AdamW | 2e-05 | 16 | Weighted cross-entropy; class weights computed from training labels. | 1 requested / 1 recorded; best epoch 1; early-stopping patience 1 | `{"checkpoint": "google-bert/bert-base-uncased", "resolved_revision": "86b5e0934494bd15c9632b12f734a8a67f723594", "max_length": 128, "class_weighting": "balanced"}` |
| `phishtank` | `roberta` | 1000 | 600 (60.00%) | 200 (20.00%) | 200 (20.00%) | 528/178/174 | train: 300/300; validation: 100/100; test: 100/100 | AdamW | 2e-05 | 16 | Weighted cross-entropy; class weights computed from training labels. | 1 requested / 1 recorded; best epoch 1; early-stopping patience 1 | `{"checkpoint": "FacebookAI/roberta-base", "resolved_revision": "e2da8e2f811d1448a5b465c236feacd80ffbac7b", "max_length": 128, "class_weighting": "balanced"}` |
| `phishtank` | `cnn` | 1000 | 600 (60.00%) | 200 (20.00%) | 200 (20.00%) | 528/178/174 | train: 300/300; validation: 100/100; test: 100/100 | AdamW | 0.001 | 128 | Weighted cross-entropy; class weights computed from training labels. | 1 requested / 1 recorded; best epoch 1; early-stopping patience 1 | `{"embedding_dim": 96, "vocab_size_limit": 50000, "max_length": 128, "class_weighting": "balanced"}` |
| `phishtank` | `lstm` | 1000 | 600 (60.00%) | 200 (20.00%) | 200 (20.00%) | 528/178/174 | train: 300/300; validation: 100/100; test: 100/100 | AdamW | 0.001 | 128 | Weighted cross-entropy; class weights computed from training labels. | 1 requested / 1 recorded; best epoch 1; early-stopping patience 1 | `{"embedding_dim": 96, "vocab_size_limit": 50000, "max_length": 128, "class_weighting": "balanced"}` |

## Model-specific preprocessing and training

- **XGBoost:** training-only TF-IDF, unigram/bigram features, `min_df=2`, `max_features=100000`, sublinear TF and Unicode accent stripping; `binary:logistic`, depth 6, subsample and column sample 0.85, recorded scale-positive weight, up to 500 estimators, learning rate 0.08, validation early stopping. No optimizer or mini-batch applies.
- **BERT / RoBERTa:** their saved checkpoint and resolved revision are in each row's `other recorded hyperparameters`; tokenizer truncation and max-length padding use length 128. AdamW, weighted cross-entropy, batch size 16, learning rate `2e-5`, gradient-norm clipping at 1.0, and the recorded epoch count. The classification weights are balanced using training labels.
- **CNN / LSTM:** lowercase regex tokenization, vocabulary built from training text only (limit 50,000), maximum sequence length 128, 96-dimensional embedding, AdamW, weighted cross-entropy, batch size 128, learning rate `0.001`, gradient-norm clipping at 1.0, and the recorded epoch count.

## Reproduction

From the project root, run `python ml/export_methodology.py`. The script reads the completed `run_manifest.json` and all 15 per-combination JSON files, validates their identities and split-stat consistency, then writes `methodology.json`, `methodology.csv`, and this report in `results/model_comparison/`.

The report intentionally does not claim that external transformer pretraining data is disjoint from benchmark data. A `null` value in the JSON indicates that a field is not applicable or was not recorded; it is not replaced with an assumed value.
