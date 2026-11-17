import sys
import warnings
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ml"))

import benchmark_models
import generate_predictions
import export_methodology
import plot_training_results
import export_cnn_evaluation


class ModelComparisonTests(unittest.TestCase):
    def test_hostname_normalization_groups_url_variants(self):
        self.assertEqual(
            benchmark_models.normalized_hostname("https://www.example.com/a?b=1"),
            benchmark_models.normalized_hostname("http://www.example.com/other"),
        )

    def test_phishtank_negatives_exclude_positive_hosts(self):
        clean_urls = [
            {"text": "https://known-phish.example/path", "label": 0, "group": "known-phish.example"},
            {"text": "https://clean.example/path", "label": 0, "group": "clean.example"},
            {"text": "https://bad.example/path", "label": 1, "group": "bad.example"},
        ]
        records, details = benchmark_models.read_phishtank_dataset_from_rows(
            positives=[
                {"text": "http://known-phish.example/login", "label": 1, "group": "known-phish.example"},
            ],
            clean_url_records=clean_urls,
        )

        self.assertEqual({row["text"] for row in records}, {
            "http://known-phish.example/login",
            "https://clean.example/path",
        })
        self.assertEqual(details["positive_rows"], 1)
        self.assertEqual(details["negative_rows"], 1)

    def test_grouped_split_has_no_group_overlap_and_preserves_classes(self):
        records = [
            {
                "text": f"example {label} {group}",
                "label": label,
                "group": f"{label}-{group}",
            }
            for label in (0, 1)
            for group in range(50)
        ]
        splits = benchmark_models.split_grouped(records, seed=7)
        groups = {
            name: {records[index]["group"] for index in indexes}
            for name, indexes in splits.items()
        }
        self.assertFalse(groups["train"] & groups["validation"])
        self.assertFalse(groups["train"] & groups["test"])
        self.assertFalse(groups["validation"] & groups["test"])
        for indexes in splits.values():
            self.assertEqual({records[index]["label"] for index in indexes}, {0, 1})

    def test_capped_sampling_is_reproducible_and_class_balanced(self):
        records = [
            {"text": f"record-{label}-{index}", "label": label, "group": f"{label}-{index}"}
            for label in (0, 1)
            for index in range(20)
        ]
        first = benchmark_models.limit_rows(records, limit=10, seed=11)
        second = benchmark_models.limit_rows(records, limit=10, seed=11)
        self.assertEqual(
            [row["text"] for row in first],
            [row["text"] for row in second],
        )
        self.assertEqual(sum(row["label"] == 0 for row in first), 5)
        self.assertEqual(sum(row["label"] == 1 for row in first), 5)

    def test_metrics_normalize_float32_probability_rounding(self):
        import numpy as np

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            metrics = benchmark_models.metric_bundle(
                [0, 1],
                np.asarray([[0.7, 0.29999998], [0.2, 0.79999995]], dtype=np.float32),
            )
        self.assertAlmostEqual(metrics["accuracy"], 1.0)
        self.assertFalse(caught)

    def test_prediction_examples_include_both_outcomes_when_present(self):
        rows = [
            {"sample_id": "correct-1", "correct": True},
            {"sample_id": "wrong-1", "correct": False},
            {"sample_id": "correct-2", "correct": True},
        ]
        examples = generate_predictions.select_examples(rows, count=1)
        self.assertEqual(examples["correct"], [rows[0]])
        self.assertEqual(examples["misclassified"], [rows[1]])

    def test_methodology_split_percentages_derive_from_saved_counts(self):
        splits = {
            "train": {
                "rows": 599,
                "groups": 400,
                "class_counts": {"legitimate": 300, "phishing": 299},
            },
            "validation": {
                "rows": 201,
                "groups": 150,
                "class_counts": {"legitimate": 100, "phishing": 101},
            },
            "test": {
                "rows": 200,
                "groups": 150,
                "class_counts": {"legitimate": 100, "phishing": 100},
            },
        }
        actual = export_methodology.split_statistics(splits, 1000)
        self.assertEqual(actual["train"]["percent_of_dataset"], 59.9)
        self.assertEqual(actual["validation"]["percent_of_dataset"], 20.1)
        self.assertEqual(actual["test"]["percent_of_dataset"], 20.0)

    def test_plot_diagnosis_is_cautious_with_single_epoch_and_boundary_gap(self):
        run = {
            "model": "cnn",
            "dataset": "urldata",
            "training_curve": [{
                "training_accuracy": 0.62,
                "validation_accuracy": 0.70,
                "training_loss": 0.68,
                "validation_loss": 0.65,
            }],
            "metrics": {"accuracy": 0.60},
        }
        diagnosis = plot_training_results.diagnose(run)
        self.assertIn("cannot be assessed", diagnosis["convergence"])
        self.assertIn("insufficient history", diagnosis["overfitting"])
        self.assertIn("notable gap", diagnosis["generalization"])

    def test_cnn_specificity_and_classification_metrics_from_confusion_matrix(self):
        metrics = export_cnn_evaluation.classification_metrics([[93, 7], [8, 92]])
        self.assertEqual(metrics["accuracy"], 0.925)
        self.assertEqual(metrics["precision"], 92 / 99)
        self.assertEqual(metrics["recall_sensitivity"], 0.92)
        self.assertEqual(metrics["specificity"], 0.93)
        self.assertEqual(metrics["f1_score"], 184 / 199)


if __name__ == "__main__":
    unittest.main()
