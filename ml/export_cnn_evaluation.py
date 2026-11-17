#!/usr/bin/env python
"""Export CNN evaluation metrics from the completed benchmark records."""

from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "results" / "model_comparison"
OUTPUT_DIR = ROOT / "results" / "cnn_evaluation"
DATASETS = ("ceas_08", "urldata", "phishtank")

def classification_metrics(matrix: list[list[int]]) -> dict:
    if (
        not isinstance(matrix, list)
        or len(matrix) != 2
        or any(not isinstance(row, list) or len(row) != 2 for row in matrix)
        or any(
            not isinstance(value, int) or value < 0
            for row in matrix
            for value in row
        )
    ):
        raise ValueError("Expected a non-negative 2x2 integer confusion matrix.")

    tn, fp = matrix[0]
    fn, tp = matrix[1]
    total = tn + fp + fn + tp
    if total == 0:
        raise ValueError("Cannot calculate metrics for an empty test set.")

    def divide(numerator: int, denominator: int) -> float | None:
        return numerator / denominator if denominator else None

    accuracy = divide(tp + tn, total)
    precision = divide(tp, tp + fp)
    recall = divide(tp, tp + fn)
    specificity = divide(tn, tn + fp)
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None
        and recall is not None
        and precision + recall
        else 0.0
    )
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall_sensitivity": recall,
        "specificity": specificity,
        "f1_score": f1,
        "test_samples_from_confusion_matrix": total,
        "confusion_matrix": matrix,
    }


def load_cnn_results(source_dir: Path) -> list[dict]:
    records = []
    for dataset in DATASETS:
        path = source_dir / f"{dataset}__cnn.json"
        if not path.is_file():
            raise FileNotFoundError(f"Missing CNN benchmark result: {path}")
        source = json.loads(path.read_text(encoding="utf-8"))
        if source.get("status") != "completed":
            raise ValueError(f"CNN run is not complete: {path.name}")
        if source.get("model") != "cnn" or source.get("dataset") != dataset:
            raise ValueError(f"Unexpected result identity in {path.name}")

        matrix = source.get("metrics", {}).get("confusion_matrix")
        calculated = classification_metrics(matrix)
        test_rows = source.get("splits", {}).get("test", {}).get("rows")
        if calculated["test_samples_from_confusion_matrix"] != test_rows:
            raise ValueError(f"Test count does not match confusion matrix in {path.name}")

        for metric in ("accuracy", "precision", "recall", "f1"):
            calculated_key = {
                "recall": "recall_sensitivity",
                "f1": "f1_score",
            }.get(metric, metric)
            saved_value = source.get("metrics", {}).get(metric)
            actual_value = calculated[calculated_key]
            if (
                saved_value is None
                or actual_value is None
                or not math.isclose(
                    float(saved_value), float(actual_value), rel_tol=1e-10, abs_tol=1e-10
                )
            ):
                raise ValueError(
                    f"Saved {metric} does not match confusion matrix in {path.name}"
                )

        curve = source.get("training_curve")
        if not isinstance(curve, list) or not curve:
            raise ValueError(f"Training history missing from {path.name}")
        last = curve[-1]
        required_losses = ("training_loss", "validation_loss")
        if any(key not in last for key in required_losses):
            raise ValueError(f"Recorded training/validation loss missing from {path.name}")
        test_loss = source.get("metrics", {}).get("log_loss")
        if test_loss is None or not math.isfinite(float(test_loss)):
            raise ValueError(f"Recorded test log loss missing from {path.name}")

        records.append({
            "dataset": dataset,
            "model": "cnn",
            "status": "completed",
            "seed": source.get("seed"),
            "device": source.get("device"),
            "dataset_rows": source.get("dataset_rows"),
            "train_rows": source.get("splits", {}).get("train", {}).get("rows"),
            "validation_rows": source.get("splits", {}).get("validation", {}).get("rows"),
            "test_rows": test_rows,
            **calculated,
            "training_loss": float(last["training_loss"]),
            "validation_loss": float(last["validation_loss"]),
            "testing_loss": float(test_loss),
            "testing_loss_name": "unweighted binary log loss",
            "training_loss_recorded_epoch": last.get("epoch"),
            "validation_loss_recorded_epoch": last.get("epoch"),
            "training_accuracy_at_recorded_epoch": last.get("training_accuracy"),
            "validation_accuracy_at_recorded_epoch": last.get("validation_accuracy"),
            "loss_interpretation": (
                "Training and validation losses are the last saved history point; "
                "testing loss is the saved held-out test binary log loss."
            ),
            "source_file": path.name,
        })
    return records


def write_exports(output_dir: Path, records: list[dict]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "title": "CNN evaluation metrics",
        "source": (
            "Completed CNN runs in results/model_comparison; no model was "
            "retrained and no historical values were generated."
        ),
        "positive_class": "phishing",
        "confusion_matrix_order": {
            "rows": ["actual legitimate", "actual phishing"],
            "columns": ["predicted legitimate", "predicted phishing"],
        },
        "classification_metrics": {
            "accuracy": {
                "formula": "(TP + TN) / (TP + TN + FP + FN)",
                "meaning": "Fraction of test examples classified correctly.",
            },
            "precision": {
                "formula": "TP / (TP + FP)",
                "meaning": "Of predicted phishing examples, fraction actually phishing.",
            },
            "recall_sensitivity": {
                "formula": "TP / (TP + FN)",
                "meaning": "Of actual phishing examples, fraction detected.",
            },
            "specificity": {
                "formula": "TN / (TN + FP)",
                "meaning": "Of actual legitimate examples, fraction correctly identified.",
            },
            "f1_score": {
                "formula": "2 * precision * recall / (precision + recall)",
                "meaning": "Harmonic mean of phishing-class precision and recall.",
            },
            "confusion_matrix": {
                "formula": "[[TN, FP], [FN, TP]]",
                "meaning": (
                    "Counts, not a loss; actual labels are rows and predictions "
                    "are columns, each ordered legitimate then phishing."
                ),
            },
        },
        "loss_values": {
            "training_loss": (
                "Recorded weighted cross-entropy training loss at the final "
                "saved training-history epoch."
            ),
            "training_validation_formula": (
                "Weighted cross-entropy: -sum_i(w[y_i] * log(p[i,y_i])) / "
                "sum_i(w[y_i]), using class weights computed from training labels."
            ),
            "validation_loss": (
                "Recorded weighted cross-entropy validation loss at the final "
                "saved training-history epoch."
            ),
            "testing_loss": (
                "Recorded unweighted binary log loss on held-out test data."
            ),
            "testing_formula": (
                "-(1/N) * sum_i(y_i*log(p_i) + (1-y_i)*log(1-p_i)), "
                "where p_i is phishing probability."
            ),
            "distinction": (
                "Loss values evaluate probability fit and are not classification "
                "rates; accuracy/precision/recall/specificity/F1 are classification "
                "metrics calculated at the benchmark's 0.5 decision threshold."
            ),
        },
        "records": records,
        "limitations": [
            "The saved CNN runs contain one training epoch; losses and training/"
            "validation accuracy are reported only at that recorded epoch.",
            "The saved training accuracy is in-batch pre-update accuracy and is "
            "not a post-epoch full-training-set evaluation.",
            "All runs used a 1,000-row class-balanced cap and 200-example balanced "
            "test split; results are not full-dataset or natural-prevalence estimates.",
            "PhishTank metrics use verified PhishTank positives with URLData clean "
            "negatives, excluding hosts found among the positives.",
        ],
    }
    (output_dir / "cnn_metrics.json").write_text(
        json.dumps(payload, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )

    fields = [
        "dataset", "model", "seed", "device", "dataset_rows", "train_rows",
        "validation_rows", "test_rows", "accuracy", "precision",
        "recall_sensitivity", "specificity", "f1_score", "confusion_matrix",
        "training_loss", "validation_loss", "testing_loss",
        "testing_loss_name", "training_loss_recorded_epoch",
        "validation_loss_recorded_epoch", "training_accuracy_at_recorded_epoch",
        "validation_accuracy_at_recorded_epoch", "loss_interpretation", "source_file",
    ]
    with (output_dir / "cnn_metrics.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for record in records:
            row = {key: record.get(key) for key in fields}
            row["confusion_matrix"] = json.dumps(record["confusion_matrix"])
            writer.writerow(row)

    lines = [
        "# CNN Evaluation Metrics",
        "",
        "Values are taken from the completed CNN benchmark JSONs. Classification "
        "metrics and confusion matrices are derived from the saved test confusion "
        "matrices and checked against the saved accuracy, precision, recall, and F1. "
        "Losses are copied from the saved training curve and test metrics; no model "
        "was retrained.",
        "",
        "## Classification metrics",
        "",
        "The positive class is phishing. In each matrix `[[TN, FP], [FN, TP]]`, "
        "rows are actual labels and columns are predicted labels, ordered "
        "legitimate then phishing.",
        "",
        "| Metric | Formula | Meaning |",
        "|---|---|---|",
        "| Accuracy | `(TP + TN) / (TP + TN + FP + FN)` | Fraction of all test examples correctly classified. |",
        "| Precision | `TP / (TP + FP)` | Fraction of predicted phishing examples that are phishing. |",
        "| Recall / Sensitivity | `TP / (TP + FN)` | Fraction of phishing examples detected. |",
        "| Specificity | `TN / (TN + FP)` | Fraction of legitimate examples correctly identified. |",
        "| F1-score | `2 × precision × recall / (precision + recall)` | Harmonic mean of phishing-class precision and recall. |",
        "| Confusion matrix | `[[TN, FP], [FN, TP]]` | Test-example counts, not a loss. |",
        "",
        "If a denominator is zero, the corresponding rate is reported as null; "
        "F1 is zero when precision and recall sum to zero.",
        "",
        "## Loss values (not classification metrics)",
        "",
        "- **Training loss:** recorded weighted cross-entropy at the final saved "
        "training-history epoch. For labels `y_i`, sample probabilities "
        "`p[i,y_i]`, and training-derived class weights `w`, the weighted mean "
        "is `-sum_i(w[y_i] × log(p[i,y_i])) / sum_i(w[y_i])`.",
        "- **Validation loss:** recorded weighted cross-entropy at the final saved "
        "training-history epoch.",
        "- **Testing loss:** recorded unweighted binary log loss on the held-out "
        "test set: `-(1/N) × sum_i(y_i × log(p_i) + (1-y_i) × log(1-p_i))`, "
        "where `p_i` is phishing probability.",
        "- Loss evaluates probability fit; it is not a percentage of correctly "
        "classified examples. The classification metrics use the benchmark's "
        "0.5 phishing-probability threshold.",
        "",
        "## Results",
        "",
        "| Dataset | Test n | Accuracy | Precision | Recall / Sensitivity | Specificity | F1-score | "
        "Confusion matrix `[[TN,FP],[FN,TP]]` | Training loss | Validation loss | Testing loss |",
        "|---|---:|---:|---:|---:|---:|---:|---|---:|---:|---:|",
    ]
    for record in records:
        lines.append(
            f"| `{record['dataset']}` | {record['test_rows']} "
            f"| {record['accuracy']:.4f} | {record['precision']:.4f} "
            f"| {record['recall_sensitivity']:.4f} "
            f"| {record['specificity']:.4f} | {record['f1_score']:.4f} "
            f"| `{json.dumps(record['confusion_matrix'], separators=(',', ':'))}` "
            f"| {record['training_loss']:.6f} | {record['validation_loss']:.6f} "
            f"| {record['testing_loss']:.6f} |"
        )
    lines.extend([
        "",
        "## Limitations and reproduction",
        "",
        "- The training runs used a 1,000-row class-balanced cap, one epoch, and "
        "200 class-balanced test examples. These values do not represent the "
        "full datasets or natural class prevalence.",
        "- Training accuracy is recorded as in-batch pre-update accuracy; "
        "training/validation losses are the one saved epoch's history point.",
        "- PhishTank evaluation combines verified PhishTank positives with "
        "URLData `good` negatives from hosts absent in the positive set.",
        "- Recreate the JSON, CSV, and report using "
        "`python ml/export_cnn_evaluation.py`.",
        "",
    ])
    (output_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, default=SOURCE_DIR)
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    args = parser.parse_args()
    records = load_cnn_results(args.source_dir.resolve())
    write_exports(args.output_dir.resolve(), records)
    print(
        f"Exported actual CNN metrics for {len(records)} datasets to "
        f"{args.output_dir.resolve()}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
