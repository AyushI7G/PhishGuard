#!/usr/bin/env python
"""Reproducible, grouped train/validation/test comparison for five text models."""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.metadata
import json
import math
import os
import random
import re
import sys
import time
import traceback
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = ROOT / "dataset"
RESULTS_DIR = ROOT / "results" / "model_comparison"
MODELS = ("xgboost", "bert", "roberta", "cnn", "lstm")
DATASETS = ("ceas_08", "urldata", "phishtank")
SEED = 42
LABEL_NAMES = ("legitimate", "phishing")
csv.field_size_limit(2**31 - 1)


def stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def normalized_hostname(value: str) -> str:
    candidate = value.strip()
    if not re.match(r"^[a-z][a-z0-9+.-]*://", candidate, re.IGNORECASE):
        candidate = "http://" + candidate
    try:
        return (urlsplit(candidate).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def normalized_email_text(row: dict[str, str]) -> str:
    sender = re.sub(r"\s+", " ", row.get("sender", "").lower()).strip()
    subject = re.sub(r"\s+", " ", row.get("subject", "").lower()).strip()
    body = re.sub(r"\s+", " ", row.get("body", "").lower()).strip()
    return f"{sender}\n{subject}\n{body}"


def read_email_dataset() -> list[dict]:
    path = DATASET_DIR / "CEAS_08.csv"
    records = []
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as stream:
        for row in csv.DictReader(stream):
            label = row.get("label", "").strip()
            if label not in {"0", "1"}:
                continue
            text = "\n".join(
                part for part in (
                    row.get("sender", ""),
                    row.get("subject", ""),
                    row.get("body", ""),
                    row.get("urls", ""),
                ) if part
            )
            group = stable_hash(normalized_email_text(row))
            records.append({
                "text": text,
                "label": int(label),
                "group": group,
                "source": "CEAS_08",
            })
    return records


def read_url_dataset() -> list[dict]:
    path = DATASET_DIR / "urldata.csv"
    records = []
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as stream:
        for row in csv.DictReader(stream):
            url = row.get("url", "").strip()
            label = row.get("label", "").strip().lower()
            if not url or label not in {"good", "bad"}:
                continue
            hostname = normalized_hostname(url)
            if not hostname:
                continue
            records.append({
                "text": url,
                "label": int(label == "bad"),
                "group": hostname,
                "source": "urldata",
            })
    return records


def read_phishtank_dataset(clean_url_records: list[dict]) -> tuple[list[dict], dict]:
    path = DATASET_DIR / "dataset_phishtank.csv"
    positives = []
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as stream:
        for row in csv.DictReader(stream):
            url = row.get("url", "").strip()
            if row.get("verified", "").strip().lower() != "yes":
                continue
            if row.get("online", "").strip().lower() != "yes":
                continue
            hostname = normalized_hostname(url)
            if url and hostname:
                positives.append({
                    "text": url,
                    "label": 1,
                    "group": hostname,
                    "source": "PhishTank",
                })

    return read_phishtank_dataset_from_rows(positives, clean_url_records)


def read_phishtank_dataset_from_rows(
    positives: list[dict], clean_url_records: list[dict]
) -> tuple[list[dict], dict]:
    positive_hosts = {row["group"] for row in positives}
    negatives_by_url = {}
    for row in clean_url_records:
        if row["label"] == 0 and row["group"] not in positive_hosts:
            negatives_by_url.setdefault(row["text"], {
                **row,
                "label": 0,
                "source": "urldata (good; PhishTank negatives)",
            })
    negatives = list(negatives_by_url.values())
    combined = positives + negatives
    details = {
        "positive_source": "dataset_phishtank.csv",
        "positive_filter": "verified=yes and online=yes",
        "negative_source": "urldata.csv rows labelled good",
        "phishing_hosts_excluded_from_negative_pool": len(positive_hosts),
        "positive_rows": len(positives),
        "negative_rows": len(negatives),
        "negative_policy": (
            "All distinct urldata good URLs whose hostname is not present in the "
            "PhishTank positive feed; URLs sharing a host are kept in the same split."
        ),
    }
    return combined, details


def limit_rows(records: list[dict], limit: int | None, seed: int) -> list[dict]:
    if limit is None or len(records) <= limit:
        return records
    rng = random.Random(seed)
    class_rows = {
        label: [row for row in records if row["label"] == label]
        for label in (0, 1)
    }
    if all(class_rows.values()):
        quotas = {0: limit // 2, 1: limit - limit // 2}
        selected = []
        for label, rows in class_rows.items():
            count = min(len(rows), quotas[label])
            selected.extend(rng.sample(rows, count))
        if len(selected) < limit:
            selected_ids = {id(row) for row in selected}
            unused = [row for row in records if id(row) not in selected_ids]
            selected.extend(rng.sample(unused, min(limit - len(selected), len(unused))))
    else:
        selected = rng.sample(records, limit)
    return selected


def split_grouped(records: list[dict], seed: int) -> dict[str, list[int]]:
    import numpy as np
    from sklearn.model_selection import StratifiedGroupKFold

    labels = np.asarray([row["label"] for row in records], dtype=np.int64)
    groups = np.asarray([row["group"] for row in records], dtype=object)
    indexes = np.arange(len(records))
    if len(set(labels.tolist())) != 2:
        raise ValueError("Train/validation/test metrics require both classes.")
    if len(set(groups.tolist())) < 5:
        raise ValueError("At least five distinct groups are required for grouped splits.")

    outer = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
    train_validation, test = next(outer.split(indexes, labels, groups))
    inner = StratifiedGroupKFold(n_splits=4, shuffle=True, random_state=seed + 1)
    train_local, validation_local = next(inner.split(
        train_validation,
        labels[train_validation],
        groups[train_validation],
    ))
    train = train_validation[train_local]
    validation = train_validation[validation_local]

    split_groups = {
        name: set(groups[split].tolist())
        for name, split in (("train", train), ("validation", validation), ("test", test))
    }
    if (
        split_groups["train"] & split_groups["validation"]
        or split_groups["train"] & split_groups["test"]
        or split_groups["validation"] & split_groups["test"]
    ):
        raise RuntimeError("Grouped split leakage detected.")
    return {"train": train, "validation": validation, "test": test}


def seed_everything(seed: int) -> None:
    random.seed(seed)
    try:
        import numpy as np
        np.random.seed(seed)
    except ImportError:
        pass
    try:
        import torch
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
        torch.use_deterministic_algorithms(True, warn_only=True)
    except ImportError:
        pass


def metric_bundle(y_true, probabilities) -> dict:
    import numpy as np
    from sklearn.metrics import (
        accuracy_score,
        confusion_matrix,
        f1_score,
        log_loss,
        precision_score,
        recall_score,
    )

    y_true = np.asarray(y_true, dtype=np.int64)
    probabilities = np.asarray(probabilities, dtype=np.float64)
    if probabilities.ndim != 2 or probabilities.shape != (len(y_true), 2):
        raise ValueError("Expected one two-class probability row per test example.")
    row_sums = probabilities.sum(axis=1, keepdims=True)
    if not np.all(np.isfinite(probabilities)) or np.any(row_sums <= 0):
        raise ValueError("Predicted class probabilities must be finite and non-zero.")
    probabilities = probabilities / row_sums
    predictions = (probabilities[:, 1] >= 0.5).astype(np.int64)
    return {
        "accuracy": float(accuracy_score(y_true, predictions)),
        "precision": float(precision_score(y_true, predictions, zero_division=0)),
        "recall": float(recall_score(y_true, predictions, zero_division=0)),
        "f1": float(f1_score(y_true, predictions, zero_division=0)),
        "log_loss": float(log_loss(y_true, probabilities, labels=[0, 1])),
        "confusion_matrix": confusion_matrix(y_true, predictions, labels=[0, 1]).tolist(),
    }


def split_description(records: list[dict], splits: dict[str, list[int]]) -> dict:
    result = {}
    for name, indexes in splits.items():
        counts = Counter(records[int(i)]["label"] for i in indexes)
        groups = {records[int(i)]["group"] for i in indexes}
        result[name] = {
            "rows": len(indexes),
            "groups": len(groups),
            "class_counts": {
                LABEL_NAMES[label]: counts.get(label, 0)
                for label in (0, 1)
            },
        }
    return result


def fit_xgboost(texts, labels, validation_texts, validation_labels, seed, args):
    import numpy as np
    from sklearn.feature_extraction.text import TfidfVectorizer
    from xgboost import XGBClassifier

    print("  fitting training-only TF-IDF vocabulary and XGBoost", flush=True)
    vectorizer = TfidfVectorizer(
        max_features=args.max_features,
        ngram_range=(1, 2),
        min_df=2,
        sublinear_tf=True,
        strip_accents="unicode",
        dtype=np.float32,
    )
    train_matrix = vectorizer.fit_transform(texts)
    validation_matrix = vectorizer.transform(validation_texts)
    model = XGBClassifier(
        n_estimators=args.xgb_estimators,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        objective="binary:logistic",
        scale_pos_weight=float(np.sum(labels == 0) / np.sum(labels == 1)),
        eval_metric=["error", "logloss"],
        tree_method="hist",
        n_jobs=args.threads,
        random_state=seed,
        early_stopping_rounds=args.patience,
    )
    model.fit(
        train_matrix,
        labels,
        eval_set=[(train_matrix, labels), (validation_matrix, validation_labels)],
        verbose=False,
    )
    raw_curve = model.evals_result()
    curve = []
    for epoch in range(len(raw_curve["validation_0"]["logloss"])):
        curve.append({
            "epoch": epoch + 1,
            "training_loss": float(raw_curve["validation_0"]["logloss"][epoch]),
            "training_accuracy": float(1 - raw_curve["validation_0"]["error"][epoch]),
            "validation_loss": float(raw_curve["validation_1"]["logloss"][epoch]),
            "validation_accuracy": float(1 - raw_curve["validation_1"]["error"][epoch]),
        })
    return model, vectorizer, curve


def make_neural_model(kind: str, vocab_size: int, max_length: int, classes: int = 2):
    import torch
    from torch import nn

    class SequenceClassifier(nn.Module):
        def __init__(self):
            super().__init__()
            self.embedding = nn.Embedding(vocab_size, 96, padding_idx=0)
            if kind == "cnn":
                self.convolutions = nn.ModuleList(
                    nn.Conv1d(96, 96, kernel_size=size, padding=size // 2)
                    for size in (3, 5, 7)
                )
                self.dropout = nn.Dropout(0.35)
                self.classifier = nn.Linear(96 * len(self.convolutions), classes)
            else:
                self.recurrent = nn.LSTM(
                    input_size=96,
                    hidden_size=96,
                    num_layers=1,
                    batch_first=True,
                    bidirectional=True,
                    dropout=0,
                )
                self.dropout = nn.Dropout(0.35)
                self.classifier = nn.Linear(192, classes)

        def forward(self, token_ids):
            embedded = self.embedding(token_ids)
            if kind == "cnn":
                channels = embedded.transpose(1, 2)
                pooled = [
                    torch.amax(torch.relu(conv(channels)), dim=2)
                    for conv in self.convolutions
                ]
                representation = torch.cat(pooled, dim=1)
            else:
                output, _ = self.recurrent(embedded)
                lengths = token_ids.ne(0).sum(dim=1).clamp(min=1)
                forward_state = output[
                    torch.arange(output.size(0), device=output.device),
                    lengths - 1,
                    :96,
                ]
                backward_state = output[:, 0, 96:]
                representation = torch.cat((forward_state, backward_state), dim=1)
            return self.classifier(self.dropout(representation))

    return SequenceClassifier()


def build_vocabulary(texts: list[str], maximum: int) -> dict[str, int]:
    counts = Counter()
    for text in texts:
        counts.update(re.findall(r"[\w]+|[^\w\s]", text.lower()))
    vocabulary = {"<pad>": 0, "<unk>": 1}
    for token, _ in counts.most_common(maximum - len(vocabulary)):
        vocabulary[token] = len(vocabulary)
    return vocabulary


def encode_texts(texts: list[str], vocabulary: dict[str, int], max_length: int):
    import numpy as np

    encoded = np.zeros((len(texts), max_length), dtype=np.int64)
    unknown = vocabulary["<unk>"]
    for row_index, text in enumerate(texts):
        tokens = re.findall(r"[\w]+|[^\w\s]", text.lower())[:max_length]
        if tokens:
            encoded[row_index, :len(tokens)] = [
                vocabulary.get(token, unknown) for token in tokens
            ]
    return encoded


def train_neural(kind, train_texts, train_labels, validation_texts, validation_labels, seed, args):
    import numpy as np
    import torch
    from torch import nn
    from torch.utils.data import DataLoader, TensorDataset
    from sklearn.utils.class_weight import compute_class_weight

    seed_everything(seed)
    device = torch.device("cuda" if torch.cuda.is_available() and not args.cpu else "cpu")
    vocabulary = build_vocabulary(train_texts, args.vocab_size)
    train_ids = encode_texts(train_texts, vocabulary, args.max_length)
    validation_ids = encode_texts(validation_texts, vocabulary, args.max_length)
    train_dataset = TensorDataset(
        torch.from_numpy(train_ids),
        torch.as_tensor(train_labels, dtype=torch.long),
    )
    generator = torch.Generator().manual_seed(seed)
    loader = DataLoader(
        train_dataset,
        batch_size=args.batch_size,
        shuffle=True,
        generator=generator,
        num_workers=0,
    )
    model = make_neural_model(kind, len(vocabulary), args.max_length).to(device)
    weights = compute_class_weight(
        class_weight="balanced",
        classes=np.asarray([0, 1]),
        y=np.asarray(train_labels),
    )
    criterion = nn.CrossEntropyLoss(
        weight=torch.as_tensor(weights, dtype=torch.float32, device=device)
    )
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.learning_rate)
    validation_loader = DataLoader(
        TensorDataset(
            torch.from_numpy(validation_ids),
            torch.as_tensor(validation_labels, dtype=torch.long),
        ),
        batch_size=args.batch_size,
        shuffle=False,
    )
    curve = []
    best_loss = math.inf
    best_state = None
    stale_epochs = 0

    for epoch in range(args.epochs):
        model.train()
        total_loss = 0.0
        correct = 0
        seen = 0
        for token_ids, targets in loader:
            token_ids = token_ids.to(device)
            targets = targets.to(device)
            optimizer.zero_grad(set_to_none=True)
            logits = model(token_ids)
            loss = criterion(logits, targets)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            batch_size = targets.size(0)
            total_loss += loss.item() * batch_size
            correct += (logits.argmax(dim=1) == targets).sum().item()
            seen += batch_size

        model.eval()
        validation_loss_total = 0.0
        validation_correct = 0
        validation_count = 0
        with torch.no_grad():
            for token_ids, targets in validation_loader:
                token_ids = token_ids.to(device)
                targets = targets.to(device)
                validation_logits = model(token_ids)
                validation_loss_total += criterion(validation_logits, targets).item() * len(targets)
                validation_correct += (
                    validation_logits.argmax(dim=1) == targets
                ).sum().item()
                validation_count += len(targets)
        validation_loss = validation_loss_total / max(validation_count, 1)
        validation_accuracy = validation_correct / max(validation_count, 1)
        curve.append({
            "epoch": epoch + 1,
            "training_loss": total_loss / max(seen, 1),
            "training_accuracy": correct / max(seen, 1),
            "validation_loss": validation_loss,
            "validation_accuracy": validation_accuracy,
        })
        print(
            f"  {kind} epoch {epoch + 1}/{args.epochs}: "
            f"train_loss={curve[-1]['training_loss']:.4f}, "
            f"val_loss={validation_loss:.4f}, "
            f"val_accuracy={validation_accuracy:.4f}",
            flush=True,
        )
        if validation_loss < best_loss:
            best_loss = validation_loss
            best_state = {
                key: value.detach().cpu().clone()
                for key, value in model.state_dict().items()
            }
            stale_epochs = 0
        else:
            stale_epochs += 1
            if stale_epochs >= args.patience:
                break

    if best_state is None:
        raise RuntimeError(f"{kind} did not produce a validation checkpoint.")
    model.load_state_dict(best_state)
    return model, vocabulary, curve, device


def train_transformer(
    kind, train_texts, train_labels, validation_texts, validation_labels, seed, args
):
    import numpy as np
    import torch
    from torch import nn
    from torch.utils.data import DataLoader, TensorDataset
    from sklearn.utils.class_weight import compute_class_weight
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    seed_everything(seed)
    model_name = args.bert_model if kind == "bert" else args.roberta_model
    revision = args.bert_revision if kind == "bert" else args.roberta_revision
    tokenizer = AutoTokenizer.from_pretrained(model_name, revision=revision)
    train_encoded = tokenizer(
        train_texts,
        truncation=True,
        padding="max_length",
        max_length=args.max_length,
        return_tensors="pt",
    )
    validation_encoded = tokenizer(
        validation_texts,
        truncation=True,
        padding="max_length",
        max_length=args.max_length,
        return_tensors="pt",
    )
    train_dataset = TensorDataset(
        train_encoded["input_ids"],
        train_encoded["attention_mask"],
        torch.as_tensor(train_labels, dtype=torch.long),
    )
    loader = DataLoader(
        train_dataset,
        batch_size=args.transformer_batch_size,
        shuffle=True,
        generator=torch.Generator().manual_seed(seed),
        num_workers=0,
    )
    device = torch.device("cuda" if torch.cuda.is_available() and not args.cpu else "cpu")
    model = AutoModelForSequenceClassification.from_pretrained(
        model_name,
        revision=revision,
        num_labels=2,
    )
    model.to(device)
    class_weights = compute_class_weight(
        class_weight="balanced",
        classes=np.asarray([0, 1]),
        y=np.asarray(train_labels),
    )
    criterion = nn.CrossEntropyLoss(
        weight=torch.as_tensor(class_weights, dtype=torch.float32, device=device)
    )
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.transformer_learning_rate)
    validation_ids = validation_encoded["input_ids"].to(device)
    validation_mask = validation_encoded["attention_mask"].to(device)
    validation_targets = torch.as_tensor(
        validation_labels, dtype=torch.long, device=device
    )
    curve = []
    best_loss = math.inf
    best_state = None
    stale_epochs = 0

    for epoch in range(args.epochs):
        model.train()
        total_loss = 0.0
        correct = 0
        seen = 0
        for input_ids, attention_mask, targets in loader:
            input_ids = input_ids.to(device)
            attention_mask = attention_mask.to(device)
            targets = targets.to(device)
            optimizer.zero_grad(set_to_none=True)
            logits = model(input_ids=input_ids, attention_mask=attention_mask).logits
            loss = criterion(logits, targets)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            batch_size = targets.size(0)
            total_loss += loss.item() * batch_size
            correct += (logits.argmax(dim=1) == targets).sum().item()
            seen += batch_size

        model.eval()
        validation_losses = []
        validation_correct = 0
        with torch.no_grad():
            for start in range(0, len(validation_targets), args.transformer_batch_size):
                end = start + args.transformer_batch_size
                logits = model(
                    input_ids=validation_ids[start:end],
                    attention_mask=validation_mask[start:end],
                ).logits
                targets = validation_targets[start:end]
                validation_losses.append(
                    criterion(logits, targets).item() * len(targets)
                )
                validation_correct += (
                    logits.argmax(dim=1) == targets
                ).sum().item()
        validation_loss = sum(validation_losses) / max(len(validation_targets), 1)
        validation_accuracy = validation_correct / max(len(validation_targets), 1)
        curve.append({
            "epoch": epoch + 1,
            "training_loss": total_loss / max(seen, 1),
            "training_accuracy": correct / max(seen, 1),
            "validation_loss": validation_loss,
            "validation_accuracy": validation_accuracy,
        })
        print(
            f"  {kind} epoch {epoch + 1}/{args.epochs}: "
            f"train_loss={curve[-1]['training_loss']:.4f}, "
            f"val_loss={validation_loss:.4f}, "
            f"val_accuracy={validation_accuracy:.4f}",
            flush=True,
        )
        if validation_loss < best_loss:
            best_loss = validation_loss
            best_state = {
                key: value.detach().cpu().clone()
                for key, value in model.state_dict().items()
            }
            stale_epochs = 0
        else:
            stale_epochs += 1
            if stale_epochs >= args.patience:
                break

    if best_state is None:
        raise RuntimeError(f"{kind} did not produce a validation checkpoint.")
    model.load_state_dict(best_state)
    resolved_revision = (
        getattr(model.config, "_commit_hash", None)
        or tokenizer.init_kwargs.get("_commit_hash")
    )
    return model, tokenizer, curve, device, resolved_revision


def predict(model, kind, texts, labels, processor, device, args):
    import numpy as np
    import torch
    from torch.utils.data import DataLoader, TensorDataset

    if kind == "xgboost":
        matrix = processor.transform(texts)
        return model.predict_proba(matrix)

    if kind in {"bert", "roberta"}:
        encoded = processor(
            texts,
            truncation=True,
            padding="max_length",
            max_length=args.max_length,
            return_tensors="pt",
        )
        dataset = TensorDataset(encoded["input_ids"], encoded["attention_mask"])
        loader = DataLoader(dataset, batch_size=args.transformer_batch_size)
        probabilities = []
        model.eval()
        with torch.no_grad():
            for input_ids, attention_mask in loader:
                logits = model(
                    input_ids=input_ids.to(device),
                    attention_mask=attention_mask.to(device),
                ).logits
                probabilities.extend(torch.softmax(logits, dim=1).cpu().numpy())
        return np.asarray(probabilities)

    encoded = encode_texts(texts, processor, args.max_length)
    loader = DataLoader(
        TensorDataset(torch.from_numpy(encoded)),
        batch_size=args.batch_size,
        shuffle=False,
    )
    probabilities = []
    model.eval()
    with torch.no_grad():
        for (token_ids,) in loader:
            logits = model(token_ids.to(device))
            probabilities.extend(torch.softmax(logits, dim=1).cpu().numpy())
    return np.asarray(probabilities)


def load_dependencies(models: list[str]) -> None:
    required = ["numpy", "sklearn"]
    if "xgboost" in models:
        required.append("xgboost")
    if any(model in models for model in ("bert", "roberta", "cnn", "lstm")):
        required.append("torch")
    if any(model in models for model in ("bert", "roberta")):
        required.append("transformers")
    missing = []
    for package in required:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)
    if missing:
        raise RuntimeError(
            "Missing ML dependencies: "
            + ", ".join(missing)
            + ". Install them with `python -m pip install -r ml/requirements.txt`."
        )


def train_one(
    model_kind,
    dataset_name,
    records,
    phishtank_details,
    args,
    include_predictions: bool = False,
):
    import numpy as np

    started = time.monotonic()
    seed = args.seed
    seed_everything(seed)
    splits = split_grouped(records, seed)
    split_info = split_description(records, splits)
    texts = [row["text"] for row in records]
    labels = np.asarray([row["label"] for row in records], dtype=np.int64)
    train_texts = [texts[int(i)] for i in splits["train"]]
    train_labels = labels[splits["train"]]
    validation_texts = [texts[int(i)] for i in splits["validation"]]
    validation_labels = labels[splits["validation"]]
    test_texts = [texts[int(i)] for i in splits["test"]]
    test_labels = labels[splits["test"]]

    if model_kind == "xgboost":
        model, processor, curve = fit_xgboost(
            train_texts, train_labels,
            validation_texts, validation_labels,
            seed, args,
        )
        device = "cpu"
    elif model_kind in {"bert", "roberta"}:
        model, processor, curve, torch_device, resolved_revision = train_transformer(
            model_kind,
            train_texts,
            train_labels,
            validation_texts,
            validation_labels,
            seed,
            args,
        )
        device = str(torch_device)
    else:
        resolved_revision = None
        model, processor, curve, torch_device = train_neural(
            model_kind,
            train_texts,
            train_labels,
            validation_texts,
            validation_labels,
            seed,
            args,
        )
        device = str(torch_device)

    probabilities = predict(
        model, model_kind, test_texts, test_labels, processor, device, args
    )
    metrics = metric_bundle(test_labels, probabilities)
    prediction_rows = []
    if include_predictions:
        predicted_labels = probabilities.argmax(axis=1)
        for position, raw_index in enumerate(splits["test"]):
            dataset_index = int(raw_index)
            record = records[dataset_index]
            actual_label = int(test_labels[position])
            predicted_label = int(predicted_labels[position])
            legitimate_probability = float(probabilities[position, 0])
            phishing_probability = float(probabilities[position, 1])
            prediction_rows.append({
                "sample_id": stable_hash(
                    f"{dataset_name}:{dataset_index}:{record['source']}:{record['text']}"
                ),
                "dataset_index": dataset_index,
                "source": record["source"],
                "actual_label": LABEL_NAMES[actual_label],
                "predicted_label": LABEL_NAMES[predicted_label],
                "actual_label_id": actual_label,
                "predicted_label_id": predicted_label,
                "probability_legitimate": legitimate_probability,
                "probability_phishing": phishing_probability,
                "predicted_probability": float(probabilities[position, predicted_label]),
                "confidence": float(max(legitimate_probability, phishing_probability)),
                "correct": actual_label == predicted_label,
                "text": record["text"],
            })
    if model_kind == "xgboost":
        hyperparameters = {
            "max_features": args.max_features,
            "ngram_range": [1, 2],
            "min_df": 2,
            "estimators": args.xgb_estimators,
            "max_depth": 6,
            "learning_rate": 0.08,
            "early_stopping_patience": args.patience,
            "scale_pos_weight": float(
                np.sum(train_labels == 0) / np.sum(train_labels == 1)
            ),
            "threads": args.threads,
        }
    elif model_kind in {"bert", "roberta"}:
        hyperparameters = {
            "checkpoint": args.bert_model if model_kind == "bert" else args.roberta_model,
            "resolved_revision": resolved_revision,
            "learning_rate": args.transformer_learning_rate,
            "batch_size": args.transformer_batch_size,
            "max_length": args.max_length,
            "class_weighting": "balanced",
        }
    else:
        hyperparameters = {
            "embedding_dim": 96,
            "batch_size": args.batch_size,
            "learning_rate": args.learning_rate,
            "vocab_size_limit": args.vocab_size,
            "max_length": args.max_length,
            "class_weighting": "balanced",
        }
    result = {
        "status": "completed",
        "model": model_kind,
        "dataset": dataset_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "positive_label": "phishing",
        "decision_threshold": 0.5,
        "confusion_matrix_label_order": ["legitimate", "phishing"],
        "seed": seed,
        "device": device,
        "hyperparameters": hyperparameters,
        "training_accuracy_method": (
            "Per-round training-set evaluation for XGBoost; in-batch pre-update "
            "predictions for neural models."
        ),
        "model_config": {
            "bert_checkpoint": args.bert_model if model_kind == "bert" else None,
            "roberta_checkpoint": args.roberta_model if model_kind == "roberta" else None,
            "max_length": args.max_length,
            "epochs_requested": args.epochs,
            "best_epoch": min(
                range(len(curve)),
                key=lambda index: curve[index]["validation_loss"],
            ) + 1,
        },
        "dataset_rows": len(records),
        "class_counts": {
            LABEL_NAMES[label]: int(np.sum(labels == label))
            for label in (0, 1)
        },
        "splits": split_info,
        "phishtank_negative_sampling": phishtank_details,
        "metrics": metrics,
        "training_curve": curve,
        "elapsed_seconds": time.monotonic() - started,
    }
    if include_predictions:
        result["predictions"] = prediction_rows
    return result


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models", nargs="+", choices=MODELS, default=list(MODELS))
    parser.add_argument("--datasets", nargs="+", choices=DATASETS, default=list(DATASETS))
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--patience", type=int, default=2)
    parser.add_argument("--max-rows", type=int, default=None)
    parser.add_argument("--max-length", type=int, default=128)
    parser.add_argument("--vocab-size", type=int, default=50000)
    parser.add_argument("--max-features", type=int, default=100000)
    parser.add_argument("--bert-model", default="google-bert/bert-base-uncased")
    parser.add_argument("--roberta-model", default="FacebookAI/roberta-base")
    parser.add_argument("--bert-revision", default=None)
    parser.add_argument("--roberta-revision", default=None)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--transformer-batch-size", type=int, default=16)
    parser.add_argument("--learning-rate", type=float, default=0.001)
    parser.add_argument("--transformer-learning-rate", type=float, default=2e-5)
    parser.add_argument("--xgb-estimators", type=int, default=500)
    parser.add_argument("--threads", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    parser.add_argument("--cpu", action="store_true", help="Force neural models to CPU.")
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Continue a compatible interrupted run without retraining completed combinations.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=RESULTS_DIR,
        help="Directory for JSON results, summary CSV, and run manifest.",
    )
    args = parser.parse_args()
    if args.epochs < 1 or args.patience < 1:
        parser.error("--epochs and --patience must be positive integers.")
    if args.max_rows is not None and args.max_rows < 10:
        parser.error("--max-rows must be at least 10.")
    return args


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    args = parse_args()
    seed_everything(args.seed)
    try:
        load_dependencies(args.models)
        email_records = read_email_dataset() if "ceas_08" in args.datasets else []
        url_records = read_url_dataset() if any(
            dataset in args.datasets for dataset in ("urldata", "phishtank")
        ) else []
        phishtank_records = []
        phishtank_details = None
        if "phishtank" in args.datasets:
            phishtank_records, phishtank_details = read_phishtank_dataset(url_records)

        datasets = {
            "ceas_08": email_records,
            "urldata": url_records,
            "phishtank": phishtank_records,
        }
        source_counts = {
            name: {
                LABEL_NAMES[label]: sum(row["label"] == label for row in records)
                for label in (0, 1)
            }
            for name, records in datasets.items()
            if name in args.datasets
        }
        started_at = datetime.now(timezone.utc).isoformat()
        manifest = {
            "status": "running",
            "started_at": started_at,
            "seed": args.seed,
            "python_version": sys.version,
            "models": args.models,
            "datasets": args.datasets,
            "max_rows_per_dataset": args.max_rows,
            "row_cap_policy": (
                "Deterministic class-balanced random sampling using the run seed."
                if args.max_rows is not None
                else "No row cap; use every valid dataset record."
            ),
            "requested_combinations": len(args.models) * len(args.datasets),
            "split_method": (
                "StratifiedGroupKFold: 5 folds for 20% test, then 4 folds on the "
                "remaining 80% for 60% train / 20% validation / 20% test."
            ),
            "metric_definition": {
                "positive_class": "phishing",
                "decision_threshold": 0.5,
                "confusion_matrix_order": ["legitimate", "phishing"],
                "test_loss": "Unweighted binary log loss.",
            },
            "grouping": {
                "ceas_08": "SHA-256 of normalized sender, subject, and body",
                "urldata": "URL hostname",
                "phishtank": "URL hostname across PhishTank positives and urldata negatives",
            },
            "phishtank_negative_policy": phishtank_details,
            "row_counts_before_optional_cap": source_counts,
            "dataset_sha256": {
                name: file_sha256(DATASET_DIR / filename)
                for name, filename in (
                    ("ceas_08", "CEAS_08.csv"),
                    ("urldata", "urldata.csv"),
                    ("phishtank", "dataset_phishtank.csv"),
                )
                if name in args.datasets
            },
            "benchmark_script_sha256": file_sha256(Path(__file__)),
            "dependency_versions": {
                package: importlib.metadata.version(package)
                for package in (
                    "numpy",
                    "scikit-learn",
                    "xgboost",
                    "torch",
                    "transformers",
                )
                if any(
                    distribution.metadata["Name"].lower().replace("_", "-")
                    == package
                    for distribution in importlib.metadata.distributions()
                )
            },
            "parameters": vars(args) | {"output_dir": str(args.output_dir)},
            "results": [],
        }
        args.output_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = args.output_dir / "run_manifest.json"
        if args.resume:
            if not manifest_path.is_file():
                raise FileNotFoundError(
                    f"Cannot resume: {manifest_path} does not exist."
                )
            previous_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            for key in ("seed", "max_rows_per_dataset"):
                if previous_manifest.get(key) != manifest[key]:
                    raise ValueError(
                        f"Cannot resume: run setting {key!r} does not match the saved manifest."
                    )
            for key in ("models", "datasets"):
                if not set(manifest[key]).issubset(previous_manifest.get(key, [])):
                    raise ValueError(
                        f"Cannot resume: requested {key} are not a subset of the saved run."
                    )
            previous_parameters = {
                key: value
                for key, value in previous_manifest.get("parameters", {}).items()
                if key not in {"output_dir", "models", "datasets"}
            }
            current_parameters = {
                key: value
                for key, value in manifest["parameters"].items()
                if key not in {"output_dir", "resume", "models", "datasets"}
            }
            if previous_parameters != current_parameters:
                raise ValueError(
                    "Cannot resume: model, split, or training parameters differ "
                    "from the saved manifest."
                )
            previous_hashes = previous_manifest.get("dataset_sha256", {})
            if any(
                previous_hashes.get(name) != manifest["dataset_sha256"].get(name)
                for name in manifest["datasets"]
            ):
                raise ValueError(
                    "Cannot resume: one or more dataset files changed since the saved run."
                )
            manifest = previous_manifest
            manifest["status"] = "running"
            manifest.setdefault("resume_events", []).append({
                "resumed_at": datetime.now(timezone.utc).isoformat(),
                "script_sha256": file_sha256(Path(__file__)),
            })
        else:
            write_json(manifest_path, manifest)

        for dataset_name in args.datasets:
            records = limit_rows(datasets[dataset_name], args.max_rows, args.seed)
            if len(records) < len(datasets[dataset_name]):
                manifest.setdefault("row_counts_after_cap", {})[dataset_name] = len(records)
                write_json(manifest_path, manifest)
            for model_kind in args.models:
                result_path = args.output_dir / f"{dataset_name}__{model_kind}.json"
                previous_result = next(
                    (
                        item for item in manifest["results"]
                        if item["dataset"] == dataset_name
                        and item["model"] == model_kind
                        and item["status"] == "completed"
                        and (args.output_dir / item["result_file"]).is_file()
                    ),
                    None,
                )
                if previous_result is not None:
                    print(
                        f"Skipping completed {model_kind} / {dataset_name}",
                        flush=True,
                    )
                    continue
                print(
                    f"[{datetime.now(timezone.utc).isoformat()}] "
                    f"Starting {model_kind} / {dataset_name} "
                    f"({len(records)} rows)",
                    flush=True,
                )
                try:
                    result = train_one(
                        model_kind,
                        dataset_name,
                        records,
                        phishtank_details if dataset_name == "phishtank" else None,
                        args,
                    )
                except Exception as error:
                    result = {
                        "status": "failed",
                        "model": model_kind,
                        "dataset": dataset_name,
                        "error": f"{type(error).__name__}: {error}",
                        "traceback": traceback.format_exc(),
                    }
                    manifest["results"].append({
                        "model": model_kind,
                        "dataset": dataset_name,
                        "status": "failed",
                        "result_file": result_path.name,
                    })
                    write_json(result_path, result)
                    write_json(manifest_path, manifest)
                    print(
                        f"Failed {model_kind} / {dataset_name}: {result['error']}",
                        file=sys.stderr,
                        flush=True,
                    )
                    continue
                write_json(result_path, result)
                manifest["results"].append({
                    "model": model_kind,
                    "dataset": dataset_name,
                    "status": "completed",
                    "result_file": result_path.name,
                    "metrics": result["metrics"],
                })
                write_json(manifest_path, manifest)
                print(
                    f"Completed {model_kind} / {dataset_name}: "
                    f"accuracy={result['metrics']['accuracy']:.4f}, "
                    f"F1={result['metrics']['f1']:.4f}",
                    flush=True,
                )

        summary_path = args.output_dir / "summary.csv"
        with summary_path.open("w", newline="", encoding="utf-8") as stream:
            fields = [
                "dataset", "model", "status", "accuracy", "precision",
                "recall", "f1", "log_loss", "confusion_matrix", "result_file",
            ]
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            for item in manifest["results"]:
                metrics = item.get("metrics", {})
                writer.writerow({
                    "dataset": item["dataset"],
                    "model": item["model"],
                    "status": item["status"],
                    "accuracy": metrics.get("accuracy", ""),
                    "precision": metrics.get("precision", ""),
                    "recall": metrics.get("recall", ""),
                    "f1": metrics.get("f1", ""),
                    "log_loss": metrics.get("log_loss", ""),
                    "confusion_matrix": json.dumps(metrics.get("confusion_matrix", "")),
                    "result_file": item["result_file"],
                })
        failed = sum(item["status"] != "completed" for item in manifest["results"])
        manifest["status"] = "completed" if failed == 0 else "completed_with_failures"
        manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
        manifest["completed_combinations"] = len(manifest["results"]) - failed
        manifest["failed_combinations"] = failed
        write_json(manifest_path, manifest)
        print(
            f"Finished: {manifest['completed_combinations']} completed, "
            f"{failed} failed. Results: {args.output_dir}",
            flush=True,
        )
        return 0 if failed == 0 else 1
    except Exception as error:
        print(f"Benchmark setup failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
