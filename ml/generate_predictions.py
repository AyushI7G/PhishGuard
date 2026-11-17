#!/usr/bin/env python
"""Reproduce benchmark models and export their shared test-set predictions."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

import benchmark_models as benchmark


PREDICTION_DIR = benchmark.ROOT / "results" / "predictions"
PREDICTION_FIELDS = [
    "sample_id",
    "dataset_index",
    "source",
    "actual_label",
    "predicted_label",
    "actual_label_id",
    "predicted_label_id",
    "probability_legitimate",
    "probability_phishing",
    "predicted_probability",
    "confidence",
    "correct",
    "text",
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def atomic_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=PREDICTION_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def write_summary(output_dir: Path, results: list[dict]) -> None:
    summary_path = output_dir / "summary.csv"
    fields = [
        "dataset",
        "model",
        "status",
        "prediction_count",
        "correct_count",
        "misclassified_count",
        "accuracy",
        "precision",
        "recall",
        "f1",
        "log_loss",
        "reference_metrics_match",
        "json_file",
        "csv_file",
    ]
    rows = []
    for result in results:
        metrics = result.get("metrics", {})
        rows.append({
            "dataset": result["dataset"],
            "model": result["model"],
            "status": result["status"],
            "prediction_count": result.get("prediction_count", ""),
            "correct_count": (
                metrics.get("confusion_matrix", [[0, 0], [0, 0]])[0][0]
                + metrics.get("confusion_matrix", [[0, 0], [0, 0]])[1][1]
                if metrics else ""
            ),
            "misclassified_count": (
                metrics.get("confusion_matrix", [[0, 0], [0, 0]])[0][1]
                + metrics.get("confusion_matrix", [[0, 0], [0, 0]])[1][0]
                if metrics else ""
            ),
            "accuracy": metrics.get("accuracy", ""),
            "precision": metrics.get("precision", ""),
            "recall": metrics.get("recall", ""),
            "f1": metrics.get("f1", ""),
            "log_loss": metrics.get("log_loss", ""),
            "reference_metrics_match": result.get("reference_metrics_match", ""),
            "json_file": result.get("json_file", ""),
            "csv_file": result.get("csv_file", ""),
        })
    path = summary_path
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--benchmark-dir",
        type=Path,
        default=benchmark.RESULTS_DIR,
        help="Completed model comparison results used to reproduce the run.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=PREDICTION_DIR,
        help="Directory for per-combination JSON/CSV prediction outputs.",
    )
    parser.add_argument("--models", nargs="+", choices=benchmark.MODELS, default=None)
    parser.add_argument("--datasets", nargs="+", choices=benchmark.DATASETS, default=None)
    parser.add_argument("--examples-per-type", type=int, default=5)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--cpu", action="store_true", help="Force neural models to CPU.")
    args = parser.parse_args()
    if args.examples_per_type < 1:
        parser.error("--examples-per-type must be positive.")
    return args


def load_reference_run(benchmark_dir: Path, models: list[str], datasets: list[str]):
    manifest_path = benchmark_dir / "run_manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Benchmark manifest not found: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("status") != "completed":
        raise ValueError("Prediction generation requires a completed benchmark run.")

    reference_entries = {
        (entry["dataset"], entry["model"]): entry
        for entry in manifest.get("results", [])
        if entry.get("status") == "completed"
    }
    missing = [
        f"{dataset}/{model}"
        for dataset in datasets
        for model in models
        if (dataset, model) not in reference_entries
    ]
    if missing:
        raise ValueError(
            "The reference benchmark is missing completed combinations: "
            + ", ".join(missing)
        )

    for dataset, filename in (
        ("ceas_08", "CEAS_08.csv"),
        ("urldata", "urldata.csv"),
        ("phishtank", "dataset_phishtank.csv"),
    ):
        if dataset not in datasets:
            continue
        current_hash = sha256_file(benchmark.DATASET_DIR / filename)
        if current_hash != manifest["dataset_sha256"].get(dataset):
            raise ValueError(
                f"Dataset checksum changed since the benchmark: {filename}"
            )

    for (dataset, model), entry in reference_entries.items():
        if dataset not in datasets or model not in models:
            continue
        result_path = benchmark_dir / entry["result_file"]
        if not result_path.is_file():
            raise FileNotFoundError(f"Benchmark result not found: {result_path}")
        result = json.loads(result_path.read_text(encoding="utf-8"))
        if result.get("status") != "completed":
            raise ValueError(f"Benchmark result is incomplete: {result_path}")
    return manifest, reference_entries


def build_training_args(manifest: dict, reference_entries: dict, benchmark_dir: Path):
    params = dict(manifest["parameters"])
    params["output_dir"] = benchmark_dir
    params.pop("models", None)
    params.pop("datasets", None)
    args = argparse.Namespace(**params)
    args.cpu = args.cpu or False
    for model in ("bert", "roberta"):
        matching = next(
            (
                entry for (dataset, candidate_model), entry in reference_entries.items()
                if candidate_model == model
            ),
            None,
        )
        if matching is None:
            continue
        result = json.loads(
            (benchmark_dir / matching["result_file"]).read_text(encoding="utf-8")
        )
        hyperparameters = result["hyperparameters"]
        if model == "bert":
            args.bert_model = hyperparameters["checkpoint"]
            args.bert_revision = hyperparameters.get("resolved_revision")
        else:
            args.roberta_model = hyperparameters["checkpoint"]
            args.roberta_revision = hyperparameters.get("resolved_revision")
    return args


def prepare_datasets(datasets: list[str], manifest: dict):
    email_records = benchmark.read_email_dataset() if "ceas_08" in datasets else []
    url_records = benchmark.read_url_dataset() if any(
        dataset in datasets for dataset in ("urldata", "phishtank")
    ) else []
    phishtank_records = []
    phishtank_details = None
    if "phishtank" in datasets:
        phishtank_records, phishtank_details = benchmark.read_phishtank_dataset(
            url_records
        )

    records_by_dataset = {
        "ceas_08": email_records,
        "urldata": url_records,
        "phishtank": phishtank_records,
    }
    cap = manifest.get("max_rows_per_dataset")
    for dataset in datasets:
        records = records_by_dataset[dataset]
        records_by_dataset[dataset] = benchmark.limit_rows(
            records, cap, manifest["seed"]
        )
    return records_by_dataset, phishtank_details


def select_examples(predictions: list[dict], count: int) -> dict:
    return {
        "correct": [row for row in predictions if row["correct"]][:count],
        "misclassified": [row for row in predictions if not row["correct"]][:count],
    }


def metric_match(actual: dict, reference: dict, tolerance: float = 1e-6) -> bool:
    keys = ("accuracy", "precision", "recall", "f1", "log_loss")
    return (
        actual["confusion_matrix"] == reference["confusion_matrix"]
        and all(abs(actual[key] - reference[key]) <= tolerance for key in keys)
    )


def main() -> int:
    cli = parse_args()
    benchmark_dir = cli.benchmark_dir.resolve()
    output_dir = cli.output_dir.resolve()
    reference_manifest, reference_entries = load_reference_run(
        benchmark_dir,
        cli.models or benchmark.MODELS,
        cli.datasets or benchmark.DATASETS,
    )
    models = cli.models or list(reference_manifest["models"])
    datasets = cli.datasets or list(reference_manifest["datasets"])
    for model in models:
        if model not in reference_manifest["models"]:
            raise ValueError(f"Model {model} is not present in the reference benchmark.")
    for dataset in datasets:
        if dataset not in reference_manifest["datasets"]:
            raise ValueError(
                f"Dataset {dataset} is not present in the reference benchmark."
            )
    reference_hash = sha256_file(benchmark_dir / "run_manifest.json")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_manifest_path = output_dir / "run_manifest.json"

    if cli.resume:
        if not output_manifest_path.is_file():
            raise FileNotFoundError(f"Cannot resume without {output_manifest_path}")
        output_manifest = json.loads(
            output_manifest_path.read_text(encoding="utf-8")
        )
        if (
            output_manifest.get("benchmark_manifest_sha256") != reference_hash
            or output_manifest.get("models") != models
            or output_manifest.get("datasets") != datasets
        ):
            raise ValueError(
                "Existing prediction output uses a different benchmark or selection."
            )
        output_manifest["status"] = "running"
    else:
        existing = list(output_dir.iterdir())
        if existing:
            raise FileExistsError(
                f"Prediction output directory is not empty: {output_dir}. "
                "Use --resume only for a matching interrupted run."
            )
        output_manifest = {
            "status": "running",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "benchmark_manifest_sha256": reference_hash,
            "benchmark_manifest": str(benchmark_dir / "run_manifest.json"),
            "seed": reference_manifest["seed"],
            "models": models,
            "datasets": datasets,
            "max_rows_per_dataset": reference_manifest["max_rows_per_dataset"],
            "split_method": reference_manifest["split_method"],
            "grouping": reference_manifest["grouping"],
            "positive_label": "phishing",
            "decision_threshold": 0.5,
            "prediction_fields": PREDICTION_FIELDS,
            "examples_per_type": cli.examples_per_type,
            "sample_ids_by_dataset": {},
            "results": [],
        }
    atomic_json(output_manifest_path, output_manifest)

    training_args = build_training_args(
        reference_manifest, reference_entries, benchmark_dir
    )
    training_args.cpu = cli.cpu or training_args.cpu
    benchmark.load_dependencies(models)
    records_by_dataset, phishtank_details = prepare_datasets(
        datasets, reference_manifest
    )
    output_manifest["phishtank_negative_sampling"] = phishtank_details
    atomic_json(output_manifest_path, output_manifest)

    failed = False
    for dataset in datasets:
        records = records_by_dataset[dataset]
        for model in models:
            result_path = output_dir / f"{dataset}__{model}.json"
            csv_path = output_dir / f"{dataset}__{model}.csv"
            prior = next(
                (
                    item for item in output_manifest["results"]
                    if item["dataset"] == dataset and item["model"] == model
                ),
                None,
            )
            if (
                cli.resume
                and prior
                and prior.get("status") == "completed"
                and result_path.is_file()
                and csv_path.is_file()
            ):
                print(f"Skipping completed {model} / {dataset}", flush=True)
                continue

            print(
                f"Generating {model} / {dataset} test predictions "
                f"({len(records)} sampled rows)",
                flush=True,
            )
            reference = json.loads(
                (
                    benchmark_dir
                    / reference_entries[(dataset, model)]["result_file"]
                ).read_text(encoding="utf-8")
            )
            try:
                benchmark_result = benchmark.train_one(
                    model,
                    dataset,
                    records,
                    phishtank_details if dataset == "phishtank" else None,
                    training_args,
                    include_predictions=True,
                )
                if benchmark_result["splits"] != reference["splits"]:
                    raise RuntimeError(
                        f"Recreated split for {dataset}/{model} differs from "
                        "the reference benchmark."
                    )
                predictions = benchmark_result["predictions"]
                sample_ids = [row["sample_id"] for row in predictions]
                expected_ids = output_manifest["sample_ids_by_dataset"].get(dataset)
                if expected_ids is not None and sample_ids != expected_ids:
                    raise RuntimeError(
                        f"Test sample IDs for {dataset}/{model} differ from "
                        "the other model outputs."
                    )
                output_manifest["sample_ids_by_dataset"][dataset] = sample_ids
                examples = select_examples(predictions, cli.examples_per_type)
                result_payload = {
                    "status": "completed",
                    "dataset": dataset,
                    "model": model,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "reference_benchmark": reference_entries[(dataset, model)][
                        "result_file"
                    ],
                    "reference_metrics": reference["metrics"],
                    "reproduced_metrics": benchmark_result["metrics"],
                    "reference_metrics_match": metric_match(
                        benchmark_result["metrics"], reference["metrics"]
                    ),
                    "dataset_rows": benchmark_result["dataset_rows"],
                    "test_split": benchmark_result["splits"]["test"],
                    "prediction_count": len(predictions),
                    "probability_fields": {
                        "probability_legitimate": "Predicted probability for legitimate class.",
                        "probability_phishing": "Predicted probability for phishing class.",
                        "predicted_probability": "Probability assigned to predicted_label.",
                        "confidence": "Maximum of the two class probabilities.",
                    },
                    "examples": examples,
                    "predictions": predictions,
                }
                atomic_csv(csv_path, predictions)
                atomic_json(result_path, result_payload)
                item = {
                    "dataset": dataset,
                    "model": model,
                    "status": "completed",
                    "json_file": result_path.name,
                    "csv_file": csv_path.name,
                    "prediction_count": len(predictions),
                    "reference_metrics_match": result_payload["reference_metrics_match"],
                    "metrics": benchmark_result["metrics"],
                }
                output_manifest["results"] = [
                    entry for entry in output_manifest["results"]
                    if not (entry["dataset"] == dataset and entry["model"] == model)
                ]
                output_manifest["results"].append(item)
                atomic_json(output_manifest_path, output_manifest)
                if not item["reference_metrics_match"]:
                    print(
                        f"Warning: reproduced metrics differ from reference for "
                        f"{model} / {dataset}.",
                        file=sys.stderr,
                        flush=True,
                    )
                print(
                    f"Saved {len(predictions)} predictions for {model} / {dataset}",
                    flush=True,
                )
            except Exception as error:
                failed = True
                failure = {
                    "dataset": dataset,
                    "model": model,
                    "status": "failed",
                    "error": f"{type(error).__name__}: {error}",
                    "traceback": traceback.format_exc(),
                }
                output_manifest["results"] = [
                    entry for entry in output_manifest["results"]
                    if not (entry["dataset"] == dataset and entry["model"] == model)
                ]
                output_manifest["results"].append(failure)
                atomic_json(output_manifest_path, output_manifest)
                print(failure["error"], file=sys.stderr, flush=True)

    expected_count = len(models) * len(datasets)
    completed = sum(
        entry["status"] == "completed"
        for entry in output_manifest["results"]
        if entry["dataset"] in datasets and entry["model"] in models
    )
    output_manifest["status"] = (
        "completed" if completed == expected_count and not failed
        else "completed_with_failures"
    )
    output_manifest["completed_combinations"] = completed
    output_manifest["failed_combinations"] = expected_count - completed
    output_manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
    write_summary(output_dir, output_manifest["results"])
    atomic_json(output_manifest_path, output_manifest)
    print(
        f"Finished: {completed}/{expected_count} combinations saved in {output_dir}",
        flush=True,
    )
    return 0 if output_manifest["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
