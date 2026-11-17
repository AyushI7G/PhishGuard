#!/usr/bin/env python
"""Export the recorded benchmark methodology and split statistics."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS_DIR = ROOT / "results" / "model_comparison"
MODELS = ("xgboost", "bert", "roberta", "cnn", "lstm")
DATASETS = ("ceas_08", "urldata", "phishtank")
SPLIT_NAMES = ("train", "validation", "test")

DATASET_METHODS = {
    "ceas_08": {
        "records": (
            "Rows with labels 0 or 1; input text concatenates sender, subject, "
            "body, and URLs when present."
        ),
        "groups": (
            "SHA-256 of lowercased sender, subject, and body after whitespace "
            "normalization."
        ),
    },
    "urldata": {
        "records": "Non-empty URLs labelled good (0) or bad (1); input is the URL.",
        "groups": "Normalized URL hostname.",
    },
    "phishtank": {
        "records": (
            "Verified=yes and online=yes PhishTank URLs are positive; distinct "
            "URLData good URLs on hosts absent from the positive feed are "
            "negative. Input is the URL."
        ),
        "groups": (
            "Normalized URL hostname across PhishTank positives and URLData "
            "negatives."
        ),
    },
}

LEAKAGE_CONTROLS = [
    "A deterministic class-balanced row cap is applied before splitting when configured.",
    "StratifiedGroupKFold creates a 20% test split first, then a 25% validation "
    "split of the remaining 80%; requested proportions are 60% train / 20% "
    "validation / 20% test, while recorded row counts are authoritative.",
    "The benchmark checks that no group occurs in more than one split.",
    "TF-IDF and the CNN/LSTM vocabulary are fitted on training text only; "
    "validation and test text are transformed using those training-fitted features.",
    "Class weights are computed from training labels only. Validation loss is "
    "used for early stopping/checkpoint selection; the held-out test split is "
    "used for final metrics.",
    "The report cannot establish that external pretrained-transformer pretraining "
    "corpora are disjoint from these datasets.",
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def split_statistics(splits: dict, dataset_rows: int) -> dict:
    if dataset_rows <= 0:
        raise ValueError("dataset_rows must be positive.")
    if set(splits) != set(SPLIT_NAMES):
        raise ValueError("Each run must record train, validation, and test splits.")

    enriched = {}
    for name in SPLIT_NAMES:
        split = splits[name]
        rows = split.get("rows")
        if not isinstance(rows, int) or rows < 0:
            raise ValueError(f"Invalid {name} row count: {rows!r}")
        class_counts = split.get("class_counts")
        if not isinstance(class_counts, dict) or sum(class_counts.values()) != rows:
            raise ValueError(f"Invalid class counts for {name} split.")
        enriched[name] = {
            "rows": rows,
            "percent_of_dataset": rows * 100.0 / dataset_rows,
            "groups": split.get("groups"),
            "class_counts": class_counts,
        }

    if sum(enriched[name]["rows"] for name in SPLIT_NAMES) != dataset_rows:
        raise ValueError("Recorded split rows do not sum to dataset_rows.")
    return enriched


def training_details(result: dict, manifest: dict) -> dict:
    model = result["model"]
    params = result.get("hyperparameters", {})
    config = result.get("model_config", {})
    curve = result.get("training_curve", [])

    if model == "xgboost":
        return {
            "optimizer": "Not applicable (gradient-boosted trees)",
            "learning_rate": params.get("learning_rate"),
            "batch_size": None,
            "loss": (
                "binary:logistic objective; validation logloss is monitored "
                "for early stopping (error and logloss are evaluated)."
            ),
            "epochs_requested": None,
            "epochs_completed": None,
            "max_boosting_rounds": params.get("estimators"),
            "recorded_boosting_rounds": len(curve),
            "best_validation_round": config.get("best_epoch"),
            "early_stopping_patience": params.get("early_stopping_patience"),
            "early_stopping_metric": "validation logloss",
            "gradient_clip_norm": None,
            "other_parameters": {
                key: params.get(key)
                for key in (
                    "max_features",
                    "ngram_range",
                    "min_df",
                    "max_depth",
                    "scale_pos_weight",
                    "threads",
                )
            },
        }

    return {
        "optimizer": "AdamW",
        "learning_rate": params.get("learning_rate"),
        "batch_size": params.get("batch_size"),
        "loss": (
            "Weighted cross-entropy; class weights computed from training labels."
        ),
        "epochs_requested": config.get("epochs_requested"),
        "epochs_completed": len(curve),
        "max_boosting_rounds": None,
        "recorded_boosting_rounds": None,
        "best_validation_round": None,
        "early_stopping_patience": manifest.get("parameters", {}).get("patience"),
        "early_stopping_metric": "validation loss",
        "gradient_clip_norm": 1.0,
        "best_epoch": config.get("best_epoch"),
        "other_parameters": {
            key: params.get(key)
            for key in (
                "checkpoint",
                "resolved_revision",
                "embedding_dim",
                "vocab_size_limit",
                "max_length",
                "class_weighting",
            )
            if key in params
        },
    }


def make_run_record(result: dict, manifest: dict) -> dict:
    dataset_rows = result.get("dataset_rows")
    if not isinstance(dataset_rows, int):
        raise ValueError("A result is missing its recorded dataset_rows.")
    return {
        "model": result["model"],
        "dataset": result["dataset"],
        "status": result["status"],
        "seed": result.get("seed"),
        "device": result.get("device"),
        "dataset_rows": dataset_rows,
        "dataset_class_counts": result.get("class_counts"),
        "splits": split_statistics(result.get("splits", {}), dataset_rows),
        "positive_label": result.get("positive_label"),
        "decision_threshold": result.get("decision_threshold"),
        "training": training_details(result, manifest),
        "training_accuracy_method": result.get("training_accuracy_method"),
        "test_loss_definition": "Unweighted binary log loss.",
        "phishtank_negative_sampling": result.get("phishtank_negative_sampling"),
    }


def load_runs(results_dir: Path) -> tuple[dict, list[dict]]:
    manifest_path = results_dir / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("status") != "completed":
        raise ValueError(f"Benchmark manifest is not completed: {manifest.get('status')!r}")
    if set(manifest.get("models", [])) != set(MODELS):
        raise ValueError("The manifest does not contain all five expected models.")
    if set(manifest.get("datasets", [])) != set(DATASETS):
        raise ValueError("The manifest does not contain all three expected datasets.")

    entries = manifest.get("results", [])
    expected = {(dataset, model) for dataset in DATASETS for model in MODELS}
    actual = {(entry.get("dataset"), entry.get("model")) for entry in entries}
    if len(entries) != 15 or actual != expected:
        raise ValueError("The manifest must contain exactly the 15 completed combinations.")

    records = []
    for entry in entries:
        if entry.get("status") != "completed":
            raise ValueError(
                f"Incomplete combination: {entry.get('dataset')}/{entry.get('model')}"
            )
        result_path = (results_dir / entry["result_file"]).resolve()
        if result_path.parent != results_dir.resolve():
            raise ValueError(f"Unexpected result file path: {entry['result_file']!r}")
        result = json.loads(result_path.read_text(encoding="utf-8"))
        if (
            result.get("model") != entry["model"]
            or result.get("dataset") != entry["dataset"]
            or result.get("status") != "completed"
        ):
            raise ValueError(f"Result identity/status mismatch in {result_path.name}.")
        records.append(make_run_record(result, manifest))

    for dataset in DATASETS:
        dataset_records = [row for row in records if row["dataset"] == dataset]
        baseline = dataset_records[0]
        for row in dataset_records[1:]:
            if (
                row["dataset_rows"] != baseline["dataset_rows"]
                or row["dataset_class_counts"] != baseline["dataset_class_counts"]
                or row["splits"] != baseline["splits"]
            ):
                raise ValueError(
                    f"Split statistics differ across models for {dataset}."
                )
    records.sort(key=lambda row: (DATASETS.index(row["dataset"]), MODELS.index(row["model"])))
    return manifest, records


def percent(value: float) -> str:
    return f"{value:.2f}%"


def markdown_report(manifest: dict, records: list[dict]) -> str:
    lines = [
        "# Recorded Training and Testing Methodology",
        "",
        "Generated from the completed benchmark manifest and all 15 per-run result files. "
        "Counts and settings below are recorded values; split percentages are derived "
        "from the recorded row counts. Requested percentages are not substituted for "
        "the actual grouped-split counts.",
        "",
        "## Run-wide settings",
        "",
        f"- Seed: `{manifest.get('seed')}`",
        f"- Row cap per dataset: `{manifest.get('max_rows_per_dataset')}`",
        f"- Row-cap policy: {manifest.get('row_cap_policy')}",
        f"- Split procedure: {manifest.get('split_method')}",
        f"- Dataset checksums: recorded in [`run_manifest.json`](./run_manifest.json).",
        "- Positive class: phishing; decision threshold: 0.5.",
        "- Test loss: unweighted binary log loss.",
        "",
        "## Dataset construction and grouping",
        "",
        "| Dataset | Input records / preprocessing | Group key |",
        "|---|---|---|",
    ]
    for dataset in DATASETS:
        method = DATASET_METHODS[dataset]
        lines.append(
            f"| `{dataset}` | {method['records']} | {method['groups']} |"
        )
    lines.extend([
        "",
        "The PhishTank benchmark is a mixed-source set: verified and online "
        "PhishTank positives plus URLData `good` negatives whose hosts do not "
        "occur in the positive feed. It is not a PhishTank-only evaluation.",
        "",
        "## Leakage controls",
        "",
    ])
    lines.extend(f"- {item}" for item in LEAKAGE_CONTROLS)
    lines.extend([
        "",
        "## All 15 combinations",
        "",
        "Class counts use `legitimate / phishing` order. Percentages are each split's "
        "share of that combination's recorded dataset rows.",
        "",
        "| Dataset | Model | Rows | Train rows (%) | Validation rows (%) | Test rows (%) "
        "| Groups train/val/test | Class counts train; val; test | Optimizer | "
        "Learning rate | Batch | Loss / selection | Epochs or boosting rounds | "
        "Other recorded hyperparameters |",
        "|---|---|---:|---|---|---|---|---|---|---:|---:|---|---|---|",
    ])
    for row in records:
        splits = row["splits"]
        train, validation, test = (splits[name] for name in SPLIT_NAMES)
        training = row["training"]
        class_text = "; ".join(
            f"{name}: {splits[name]['class_counts'].get('legitimate', 'Not recorded')}/"
            f"{splits[name]['class_counts'].get('phishing', 'Not recorded')}"
            for name in SPLIT_NAMES
        )
        groups_text = "/".join(
            str(splits[name]["groups"])
            if splits[name]["groups"] is not None
            else "Not recorded"
            for name in SPLIT_NAMES
        )
        if row["model"] == "xgboost":
            epochs_text = (
                f"Not epoch-based; max {training['max_boosting_rounds']} rounds, "
                f"{training['recorded_boosting_rounds']} curve rounds, best "
                f"validation round {training['best_validation_round']}; patience "
                f"{training['early_stopping_patience']}"
            )
        else:
            epochs_text = (
                f"{training['epochs_requested']} requested / "
                f"{training['epochs_completed']} recorded; best epoch "
                f"{training.get('best_epoch')}; early-stopping patience "
                f"{manifest.get('parameters', {}).get('patience', 'Not recorded')}"
            )
        other = json.dumps(training["other_parameters"], ensure_ascii=True)
        lines.append(
            f"| `{row['dataset']}` | `{row['model']}` | {row['dataset_rows']} "
            f"| {train['rows']} ({percent(train['percent_of_dataset'])}) "
            f"| {validation['rows']} ({percent(validation['percent_of_dataset'])}) "
            f"| {test['rows']} ({percent(test['percent_of_dataset'])}) "
            f"| {groups_text} | {class_text} | {training['optimizer']} "
            f"| {training['learning_rate'] if training['learning_rate'] is not None else 'Not recorded'} "
            f"| {training['batch_size'] if training['batch_size'] is not None else 'Not applicable'} "
            f"| {training['loss']} | {epochs_text} | `{other}` |"
        )
    lines.extend([
        "",
        "## Model-specific preprocessing and training",
        "",
        "- **XGBoost:** training-only TF-IDF, unigram/bigram features, `min_df=2`, "
        "`max_features=100000`, sublinear TF and Unicode accent stripping; "
        "`binary:logistic`, depth 6, subsample and column sample 0.85, recorded "
        "scale-positive weight, up to 500 estimators, learning rate 0.08, validation "
        "early stopping. No optimizer or mini-batch applies.",
        "- **BERT / RoBERTa:** their saved checkpoint and resolved revision are in "
        "each row's `other recorded hyperparameters`; tokenizer truncation and "
        "max-length padding use length 128. AdamW, weighted cross-entropy, batch size "
        "16, learning rate `2e-5`, gradient-norm clipping at 1.0, and the recorded "
        "epoch count. The classification weights are balanced using training labels.",
        "- **CNN / LSTM:** lowercase regex tokenization, vocabulary built from "
        "training text only (limit 50,000), maximum sequence length 128, 96-dimensional "
        "embedding, AdamW, weighted cross-entropy, batch size 128, learning rate "
        "`0.001`, gradient-norm clipping at 1.0, and the recorded epoch count.",
        "",
        "## Reproduction",
        "",
        "From the project root, run `python ml/export_methodology.py`. The script reads "
        "the completed `run_manifest.json` and all 15 per-combination JSON files, "
        "validates their identities and split-stat consistency, then writes "
        "`methodology.json`, `methodology.csv`, and this report in "
        "`results/model_comparison/`.",
        "",
        "The report intentionally does not claim that external transformer pretraining "
        "data is disjoint from benchmark data. A `null` value in the JSON indicates "
        "that a field is not applicable or was not recorded; it is not replaced with "
        "an assumed value.",
        "",
    ])
    return "\n".join(lines)


def write_exports(results_dir: Path, manifest: dict, records: list[dict]) -> None:
    export = {
        "schema_version": 1,
        "generated_by": "ml/export_methodology.py",
        "generated_by_sha256": sha256_file(Path(__file__)),
        "source_manifest": "run_manifest.json",
        "source_benchmark_script_sha256": manifest.get("benchmark_script_sha256"),
        "seed": manifest.get("seed"),
        "max_rows_per_dataset": manifest.get("max_rows_per_dataset"),
        "row_cap_policy": manifest.get("row_cap_policy"),
        "split_method": manifest.get("split_method"),
        "grouping": manifest.get("grouping"),
        "row_counts_before_optional_cap": manifest.get("row_counts_before_optional_cap"),
        "dataset_sha256": manifest.get("dataset_sha256"),
        "run_parameters": manifest.get("parameters"),
        "dataset_preprocessing": DATASET_METHODS,
        "leakage_controls": LEAKAGE_CONTROLS,
        "runs": records,
    }
    (results_dir / "methodology.json").write_text(
        json.dumps(export, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )

    csv_path = results_dir / "methodology.csv"
    fields = [
        "dataset", "model", "seed", "device", "dataset_rows",
        "dataset_class_counts", "train_rows", "train_percent", "train_groups",
        "train_class_counts", "validation_rows", "validation_percent",
        "validation_groups", "validation_class_counts", "test_rows",
        "test_percent", "test_groups", "test_class_counts", "optimizer",
        "learning_rate", "batch_size", "loss", "epochs_requested",
        "epochs_completed", "best_epoch", "max_boosting_rounds",
        "recorded_boosting_rounds", "best_validation_round",
        "early_stopping_patience", "other_parameters",
        "early_stopping_metric", "gradient_clip_norm",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in records:
            flat = {
                "dataset": row["dataset"],
                "model": row["model"],
                "seed": row["seed"],
                "device": row["device"],
                "dataset_rows": row["dataset_rows"],
                "dataset_class_counts": json.dumps(row["dataset_class_counts"]),
                "optimizer": row["training"]["optimizer"],
                "learning_rate": row["training"]["learning_rate"],
                "batch_size": row["training"]["batch_size"],
                "loss": row["training"]["loss"],
                "epochs_requested": row["training"]["epochs_requested"],
                "epochs_completed": row["training"]["epochs_completed"],
                "best_epoch": row["training"].get("best_epoch"),
                "max_boosting_rounds": row["training"]["max_boosting_rounds"],
                "recorded_boosting_rounds": row["training"]["recorded_boosting_rounds"],
                "best_validation_round": row["training"]["best_validation_round"],
                "early_stopping_patience": row["training"]["early_stopping_patience"],
                "early_stopping_metric": row["training"].get("early_stopping_metric"),
                "gradient_clip_norm": row["training"].get("gradient_clip_norm"),
                "other_parameters": json.dumps(row["training"]["other_parameters"]),
            }
            for split_name in SPLIT_NAMES:
                split = row["splits"][split_name]
                flat[f"{split_name}_rows"] = split["rows"]
                flat[f"{split_name}_percent"] = f"{split['percent_of_dataset']:.6f}"
                flat[f"{split_name}_groups"] = split["groups"]
                flat[f"{split_name}_class_counts"] = json.dumps(split["class_counts"])
            writer.writerow(flat)

    (results_dir / "METHODOLOGY.md").write_text(
        markdown_report(manifest, records),
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=DEFAULT_RESULTS_DIR,
        help="Directory containing run_manifest.json and per-combination results.",
    )
    args = parser.parse_args()
    results_dir = args.results_dir.resolve()
    manifest, records = load_runs(results_dir)
    write_exports(results_dir, manifest, records)
    print(
        f"Exported methodology for {len(records)} combinations to {results_dir}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
