#!/usr/bin/env python
"""Plot saved training histories and evaluation results without retraining."""

from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "results" / "model_comparison"
PLOTS_DIR = ROOT / "results" / "plots"
MODELS = ("xgboost", "bert", "roberta", "cnn", "lstm")
DATASETS = ("ceas_08", "urldata", "phishtank")
MODEL_COLORS = {
    "xgboost": "#4477AA",
    "bert": "#EE6677",
    "roberta": "#228833",
    "cnn": "#CCBB44",
    "lstm": "#AA3377",
}
METRICS = ("accuracy", "precision", "recall", "f1")


def load_results(results_dir: Path) -> list[dict]:
    records = []
    for dataset in DATASETS:
        for model in MODELS:
            path = results_dir / f"{dataset}__{model}.json"
            if not path.is_file():
                raise FileNotFoundError(f"Missing completed benchmark result: {path}")
            result = json.loads(path.read_text(encoding="utf-8"))
            if (
                result.get("status") != "completed"
                or result.get("dataset") != dataset
                or result.get("model") != model
            ):
                raise ValueError(f"Result identity/status mismatch in {path.name}.")
            curve = result.get("training_curve")
            if not isinstance(curve, list) or not curve:
                raise ValueError(f"No recorded training history in {path.name}.")
            for point in curve:
                required = (
                    "epoch",
                    "training_loss",
                    "training_accuracy",
                    "validation_loss",
                    "validation_accuracy",
                )
                if any(key not in point for key in required):
                    raise ValueError(f"Incomplete recorded curve point in {path.name}.")
                if not all(
                    math.isfinite(float(point[key]))
                    for key in required
                ):
                    raise ValueError(f"Non-finite training history in {path.name}.")
                if not 0 <= point["training_accuracy"] <= 1 or not 0 <= point["validation_accuracy"] <= 1:
                    raise ValueError(f"Invalid accuracy history in {path.name}.")
            matrix = result.get("metrics", {}).get("confusion_matrix")
            if (
                not isinstance(matrix, list)
                or len(matrix) != 2
                or any(not isinstance(row, list) or len(row) != 2 for row in matrix)
            ):
                raise ValueError(f"Invalid saved confusion matrix in {path.name}.")
            records.append(result)
    return records


def output_base(plots_dir: Path, dataset: str, model: str, suffix: str) -> Path:
    return plots_dir / f"{dataset}__{model}__{suffix}"


def plot_training_curves(records: list[dict], plots_dir: Path) -> None:
    import matplotlib.pyplot as plt

    max_loss = max(
        float(point[key])
        for record in records
        for point in record["training_curve"]
        for key in ("training_loss", "validation_loss")
    )
    loss_limit = max_loss * 1.05 if max_loss > 0 else 1.0
    for record in records:
        model = record["model"]
        dataset = record["dataset"]
        curve = record["training_curve"]
        steps = [point["epoch"] for point in curve]
        x_label = "Boosting round" if model == "xgboost" else "Epoch"
        color = MODEL_COLORS[model]
        figure, (accuracy_axis, loss_axis) = plt.subplots(
            2, 1, figsize=(9, 7), sharex=True, constrained_layout=True
        )
        accuracy_axis.plot(
            steps,
            [point["training_accuracy"] for point in curve],
            color=color,
            marker="o",
            markersize=3,
            linewidth=2,
            label="Training",
        )
        accuracy_axis.plot(
            steps,
            [point["validation_accuracy"] for point in curve],
            color=color,
            marker="s",
            markersize=3,
            linewidth=2,
            linestyle="--",
            label="Validation",
        )
        accuracy_axis.set_ylim(0, 1.02)
        accuracy_axis.set_ylabel("Accuracy")
        accuracy_axis.set_title(f"{model.upper()} on {dataset}: recorded accuracy")
        accuracy_axis.grid(True, alpha=0.25)
        accuracy_axis.legend(loc="best")

        loss_axis.plot(
            steps,
            [point["training_loss"] for point in curve],
            color=color,
            marker="o",
            markersize=3,
            linewidth=2,
            label="Training",
        )
        loss_axis.plot(
            steps,
            [point["validation_loss"] for point in curve],
            color=color,
            marker="s",
            markersize=3,
            linewidth=2,
            linestyle="--",
            label="Validation",
        )
        loss_axis.set_ylim(0, loss_limit)
        loss_axis.set_xlabel(x_label)
        loss_axis.set_ylabel("Loss")
        loss_axis.set_title("Recorded loss (shared y-axis scale across all runs)")
        loss_axis.grid(True, alpha=0.25)
        loss_axis.legend(loc="best")
        figure.suptitle(
            f"{model.upper()} — {dataset} | {len(curve)} recorded "
            f"{'rounds' if model == 'xgboost' else 'epoch(s)'}",
            fontsize=14,
        )
        figure.savefig(
            output_base(plots_dir, dataset, model, "training").with_suffix(".png"),
            dpi=160,
        )
        plt.close(figure)


def plot_metric_comparisons(records: list[dict], plots_dir: Path) -> None:
    import matplotlib.pyplot as plt
    import numpy as np

    datasets = list(DATASETS)
    x = np.arange(len(datasets))
    width = 0.15
    for metric in METRICS:
        figure, axis = plt.subplots(figsize=(10, 6), constrained_layout=True)
        for model_index, model in enumerate(MODELS):
            values = []
            for dataset in datasets:
                result = next(
                    row for row in records
                    if row["dataset"] == dataset and row["model"] == model
                )
                values.append(result["metrics"][metric])
            offset = (model_index - (len(MODELS) - 1) / 2) * width
            bars = axis.bar(
                x + offset,
                values,
                width,
                label=model.upper(),
                color=MODEL_COLORS[model],
            )
            axis.bar_label(bars, fmt="%.2f", fontsize=7, padding=2, rotation=90)
        axis.set_ylim(0, 1.12)
        axis.set_ylabel(metric.capitalize())
        axis.set_xticks(x, [dataset.replace("_", " ").title() for dataset in datasets])
        axis.set_title(f"Test {metric.capitalize()} by model and dataset")
        axis.grid(axis="y", alpha=0.25)
        axis.set_axisbelow(True)
        axis.legend(title="Model", ncols=5, loc="upper center")
        figure.savefig(
            plots_dir / f"model_comparison__{metric}.png",
            dpi=160,
        )
        plt.close(figure)


def plot_confusion_matrices(records: list[dict], plots_dir: Path) -> None:
    import matplotlib.pyplot as plt
    import numpy as np

    vmax = max(
        int(value)
        for result in records
        for row in result["metrics"]["confusion_matrix"]
        for value in row
    )
    for result in records:
        matrix = np.asarray(result["metrics"]["confusion_matrix"], dtype=int)
        figure, axis = plt.subplots(figsize=(6, 5), constrained_layout=True)
        image = axis.imshow(matrix, cmap="Blues", vmin=0, vmax=vmax)
        for row in range(2):
            for column in range(2):
                axis.text(
                    column,
                    row,
                    str(matrix[row, column]),
                    ha="center",
                    va="center",
                    color="white" if matrix[row, column] > vmax * 0.55 else "black",
                    fontsize=14,
                )
        axis.set_xticks([0, 1], ["Legitimate", "Phishing"])
        axis.set_yticks([0, 1], ["Legitimate", "Phishing"])
        axis.set_xlabel("Predicted label")
        axis.set_ylabel("Actual label")
        axis.set_title(
            f"{result['model'].upper()} — {result['dataset']} "
            f"(test confusion matrix; counts)"
        )
        figure.colorbar(image, ax=axis, label="Number of test samples")
        figure.savefig(
            output_base(
                plots_dir, result["dataset"], result["model"], "confusion_matrix"
            ).with_suffix(".png"),
            dpi=160,
        )
        plt.close(figure)


def diagnose(record: dict) -> dict:
    curve = record["training_curve"]
    last = curve[-1]
    metrics = record["metrics"]
    train_accuracy = float(last["training_accuracy"])
    validation_accuracy = float(last["validation_accuracy"])
    train_loss = float(last["training_loss"])
    validation_loss = float(last["validation_loss"])
    test_accuracy = float(metrics["accuracy"])
    gap = train_accuracy - validation_accuracy
    generalization_gap = validation_accuracy - test_accuracy
    model = record["model"]

    if model == "xgboost":
        best_round = int(record["model_config"]["best_epoch"])
        convergence = (
            f"Early stopping selected boosting round {best_round} from "
            f"{len(curve)} recorded rounds (learning rate "
            f"{record['hyperparameters']['learning_rate']}); this is a "
            "validation-based stopping point, not proof of global convergence."
        )
    elif len(curve) > 1:
        convergence = (
            f"{len(curve)} epoch(s) are recorded; validation loss changed from "
            f"{curve[0]['validation_loss']:.4f} to "
            f"{curve[-1]['validation_loss']:.4f}. This history alone does not "
            "establish convergence."
        )
    else:
        convergence = (
            "Only one training epoch was recorded; convergence cannot be "
            "assessed from a single point."
        )

    if len(curve) <= 1:
        overfit = (
            f"Single-epoch snapshot: training-minus-validation accuracy is "
            f"{gap:+.3f}, and training-minus-validation loss is "
            f"{train_loss - validation_loss:+.3f}; insufficient history to "
            "claim overfitting."
        )
    elif gap >= 0.10 and train_loss < validation_loss:
        overfit = (
            f"Potential overfitting/generalization-gap signal: training "
            f"accuracy exceeds validation by {gap:.3f} and training loss is "
            "lower at the selected final recorded point."
        )
    else:
        overfit = (
            f"No strong end-point overfit signal by the configured heuristic "
            f"(training-minus-validation accuracy {gap:+.3f}; loss difference "
            f"{train_loss - validation_loss:+.3f})."
        )

    if train_accuracy < 0.70 and validation_accuracy < 0.70:
        underfit = (
            "Low training and validation accuracy at the recorded endpoint; "
            "possible underfitting or insufficient training, not distinguishable "
            "with the available run length."
        )
    else:
        underfit = (
            f"No low-both-accuracies signal at the endpoint "
            f"(training {train_accuracy:.3f}, validation "
            f"{validation_accuracy:.3f}); this does not rule out underfitting."
        )

    if abs(generalization_gap) >= 0.10 - 1e-9:
        generalization = (
            f"Validation-test accuracy differs by {generalization_gap:+.3f} "
            "(validation minus test), a notable gap on the saved test split."
        )
    else:
        generalization = (
            f"Validation-test accuracy differs by {generalization_gap:+.3f} "
            "(validation minus test); no large gap by the 0.10 descriptive "
            "threshold."
        )

    return {
        "dataset": record["dataset"],
        "model": model,
        "recorded_points": len(curve),
        "training_accuracy_last": train_accuracy,
        "validation_accuracy_last": validation_accuracy,
        "test_accuracy": test_accuracy,
        "training_loss_last": train_loss,
        "validation_loss_last": validation_loss,
        "overfitting": overfit,
        "underfitting": underfit,
        "convergence": convergence,
        "generalization": generalization,
    }


def write_diagnoses(records: list[dict], plots_dir: Path) -> None:
    diagnoses = [diagnose(record) for record in records]
    (plots_dir / "training_diagnosis.json").write_text(
        json.dumps(
            {
                "source": "Saved model_comparison per-run JSON files",
                "heuristics": {
                    "potential_overfitting": (
                        "More than one history point, train accuracy exceeds "
                        "validation accuracy by at least 0.10, and train loss "
                        "is lower than validation loss at the final point."
                    ),
                    "possible_underfitting": (
                        "Training and validation accuracies are both below 0.70 "
                        "at the final recorded point."
                    ),
                    "notable_generalization_gap": (
                        "Absolute validation versus test accuracy difference "
                        "is at least 0.10."
                    ),
                    "convergence": (
                        "Not inferred from one neural epoch. For XGBoost, report "
                        "the recorded validation-based early-stopping round."
                    ),
                },
                "runs": diagnoses,
                "limitations": [
                    "Neural training accuracy is recorded as in-batch pre-update "
                    "accuracy; it is not directly equivalent to a post-epoch "
                    "full-training-set evaluation.",
                    "The saved run requested one neural epoch, so neural "
                    "convergence and sustained overfitting trends cannot be "
                    "determined.",
                    "Every test set has 200 class-balanced sampled records; "
                    "generalization statements apply only to these held-out "
                    "samples and this sampling procedure.",
                    "Threshold-based diagnoses are descriptive signals, not "
                    "statistical tests or causal conclusions.",
                ],
            },
            indent=2,
            allow_nan=False,
        ) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Training history and generalization notes",
        "",
        "All charts and notes below are generated from saved per-run JSON results; "
        "no historical values are interpolated or fabricated.",
        "",
        "## Interpretation limits",
        "",
        "- Neural models have one recorded training epoch; convergence and "
        "multi-epoch overfitting trends cannot be established.",
        "- Neural training accuracy is in-batch pre-update accuracy, unlike a "
        "post-epoch full-training-set evaluation.",
        "- Each held-out test split has 200 class-balanced sampled rows. Test "
        "generalization statements are limited to these sampled records.",
        "- Potential overfitting is flagged only when a history has multiple "
        "points, training accuracy exceeds validation by at least 0.10, and "
        "training loss is below validation loss. Possible underfitting means "
        "both endpoint accuracies are below 0.70. These are descriptive "
        "heuristics, not statistical tests.",
        "- XGBoost's selected round is its validation-based early-stopping point; "
        "it is not proof of global convergence.",
        "",
        "## Per-run observations",
        "",
        "| Dataset | Model | Train acc (last recorded) | Validation acc | Test acc | "
        "Overfitting signal | Underfitting signal | Convergence | "
        "Validation-to-test |",
        "|---|---|---:|---:|---:|---|---|---|---|",
    ]
    for item in diagnoses:
        lines.append(
            f"| `{item['dataset']}` | `{item['model']}` "
            f"| {item['training_accuracy_last']:.3f} "
            f"| {item['validation_accuracy_last']:.3f} "
            f"| {item['test_accuracy']:.3f} "
            f"| {item['overfitting']} "
            f"| {item['underfitting']} "
            f"| {item['convergence']} "
            f"| {item['generalization']} |"
        )
    lines.extend([
        "",
        "## Plot inventory",
        "",
        "- One training/validation accuracy and loss plot per model/dataset "
        "combination (`*__training.png`). Accuracy uses a shared 0–1 scale; "
        "loss uses a shared scale across all runs.",
        "- One test confusion matrix per combination "
        "(`*__confusion_matrix.png`), from the saved test predictions.",
        "- Four metric-comparison charts (`model_comparison__*.png`) compare "
        "models across datasets on a common 0–1 scale.",
        "",
        "Recreate everything with `python ml/plot_training_results.py` after "
        "installing `ml/requirements.txt`.",
        "",
    ])
    (plots_dir / "TRAINING_DIAGNOSIS.md").write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    with (plots_dir / "training_diagnosis.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        writer = csv.DictWriter(stream, fieldnames=list(diagnoses[0]))
        writer.writeheader()
        writer.writerows(diagnoses)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, default=RESULTS_DIR)
    parser.add_argument("--output-dir", type=Path, default=PLOTS_DIR)
    args = parser.parse_args()
    records = load_results(args.results_dir.resolve())
    plots_dir = args.output_dir.resolve()
    plots_dir.mkdir(parents=True, exist_ok=True)
    plot_training_curves(records, plots_dir)
    plot_metric_comparisons(records, plots_dir)
    plot_confusion_matrices(records, plots_dir)
    write_diagnoses(records, plots_dir)
    png_count = len(list(plots_dir.glob("*.png")))
    if png_count != 34:
        raise RuntimeError(f"Expected 34 plot images; found {png_count}.")
    print(f"Generated {png_count} plots and diagnosis summaries in {plots_dir}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
