"""Train, checkpoint and evaluate classifiers and entropy probes."""

import json
import os
import random
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np
# Required for deterministic CUDA matrix multiplication; set before importing torch.
os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
import torch
from torch import nn
from torch.utils.data import DataLoader, Dataset

from .io import load_prepared, select_rows, sha256, write_csv, write_json
from .metrics import evaluate, macro_f1
from .models import CHANNELS, ByteplotCNN, EntropyProbe, masked_mse


@dataclass
class TrainConfig:
    channel: str = "C1"
    variants: tuple = ("V0", "V1")
    epochs: int = 10
    batch_size: int = 16
    lr: float = 0.001
    seed: int = 17
    fraction: float = 1.0
    benign_packed_keep: float = 1.0
    class_weight: bool = True
    balanced_pairs: bool = False
    device: str = "auto"
    threads: int = 2
    bootstrap: int = 500


def setup(config):
    if config.epochs < 1 or config.batch_size < 1 or config.lr <= 0 or config.threads < 1 or config.bootstrap < 0:
        raise ValueError("Invalid epochs, batch size, learning rate, threads or bootstrap count.")
    random.seed(config.seed)
    np.random.seed(config.seed)
    torch.manual_seed(config.seed)
    torch.set_num_threads(config.threads)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(config.seed)
    torch.backends.cudnn.benchmark = False
    torch.backends.cudnn.deterministic = True
    torch.use_deterministic_algorithms(True)
    name = "cuda" if torch.cuda.is_available() else "cpu"
    return torch.device(name if config.device == "auto" else config.device)


class FeatureDataset(Dataset):
    def __init__(self, rows, channel="C4", expected_shape=None):
        self.rows, self.channel, self.expected_shape = rows, channel, expected_shape

    def __len__(self):
        return len(self.rows)

    def __getitem__(self, index):
        row = self.rows[index]
        with np.load(row["_feature_path"], allow_pickle=False) as feature:
            x, mask = feature["x"].astype(np.float32), feature["mask"].astype(np.float32)
        if x.ndim != 3 or x.shape[0] != 3 or mask.shape != (1, *x.shape[1:]):
            raise ValueError("Feature arrays must have shapes (3,H,W) and (1,H,W).")
        if self.expected_shape is not None and list(x.shape) != list(self.expected_shape):
            raise ValueError("Feature size differs from the training dataset/checkpoint.")
        if not np.isfinite(x).all() or not np.isin(mask, [0, 1]).all() or mask.sum() == 0:
            raise ValueError("Invalid feature values or valid-byte mask.")
        return (torch.from_numpy(x[CHANNELS[self.channel]]), torch.from_numpy(mask),
                int(row["label"]), index)


def loader(rows, config, shuffle=False, channel=None, shape=None):
    return DataLoader(FeatureDataset(rows, channel or config.channel, shape), batch_size=config.batch_size,
                      shuffle=shuffle, num_workers=0, generator=torch.Generator().manual_seed(config.seed))


def predict_rows(model, rows, config, device, shape):
    model.eval()
    predictions = []
    with torch.no_grad():
        for x, mask, _, indices in loader(rows, config, shape=shape):
            probabilities = model(x.to(device), mask.to(device)).softmax(1)[:, 1].cpu().tolist()
            for index, probability in zip(indices.tolist(), probabilities):
                row = rows[index]
                predictions.append({k: row.get(k, "") for k in (
                    "sha256", "parent_sha256", "label", "variant", "split", "family", "synthetic")} |
                    {"probability_malware": probability, "prediction": int(probability >= 0.5)})
    return predictions


def _training_context(manifest, out, config):
    rows = load_prepared(manifest)
    out = Path(out)
    if (out / "checkpoint.pt").exists():
        raise ValueError(f"Checkpoint exists at {out}; choose a new run directory.")
    train = select_rows(rows, "train", config.variants, config.fraction, config.seed, config.benign_packed_keep, config.balanced_pairs)
    # Packed-benign scarcity is a training intervention, never a holdout change.
    val = select_rows(rows, "val", config.variants, 1.0, config.seed, 1.0, config.balanced_pairs)
    test = [r for r in rows if r["split"] == "test"]
    for name, subset in (("train", train), ("val", val), ("test", test)):
        if {int(r["label"]) for r in subset} != {0, 1}:
            raise ValueError(f"{name} must contain both labels after filtering.")
    with np.load(train[0]["_feature_path"], allow_pickle=False) as feature:
        shape = list(feature["x"].shape)
    dataset_config_path = Path(manifest).resolve().parent / "dataset.json"
    representation = json.loads(dataset_config_path.read_text(encoding="utf-8"))
    metadata = {"config": asdict(config), "feature_shape": shape, "representation": representation,
                "manifest_sha256": sha256(Path(manifest).read_bytes()), "torch_version": str(torch.__version__),
                "synthetic": all(r.get("synthetic") == "1" for r in rows),
                "train_samples": len(train), "val_samples": len(val), "test_samples": len(test),
                "pooling_mask": "valid-byte weighted final pooling; convolution still sees padding boundaries"}
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "run.json", metadata)
    write_csv(out / "selected_train.csv", train)
    write_csv(out / "selected_val.csv", val)
    return rows, train, val, test, shape, metadata


def fit_classifier(manifest, out, config):
    device = setup(config)
    _, train, val, test, shape, metadata = _training_context(manifest, out, config)
    model = ByteplotCNN(len(CHANNELS[config.channel])).to(device)
    counts = np.bincount([int(r["label"]) for r in train], minlength=2)
    weights = torch.tensor(len(train) / (2 * counts), dtype=torch.float32, device=device) if config.class_weight else None
    loss_fn = nn.CrossEntropyLoss(weight=weights)
    optimizer = torch.optim.Adam(model.parameters(), lr=config.lr)
    batches = loader(train, config, shuffle=True, shape=shape)
    best, history = -1.0, []
    for epoch in range(1, config.epochs + 1):
        model.train()
        total, count = 0.0, 0
        for x, mask, y, _ in batches:
            optimizer.zero_grad(set_to_none=True)
            loss = loss_fn(model(x.to(device), mask.to(device)), y.to(device))
            loss.backward()
            optimizer.step()
            total += loss.item() * len(y)
            count += len(y)
        predictions = predict_rows(model, val, config, device, shape)
        score = macro_f1([int(r["label"]) for r in predictions], [r["prediction"] for r in predictions])
        history.append({"epoch": epoch, "train_loss": total / count, "val_macro_f1": score})
        print(f"  {Path(out).name} epoch {epoch}/{config.epochs}: loss={total / count:.4f}, val F1={score:.4f}", flush=True)
        if score > best:
            best = score
            torch.save({"state_dict": model.state_dict(), "metadata": metadata, "kind": "classifier",
                        "best_epoch": epoch}, Path(out) / "checkpoint.pt")
    checkpoint = torch.load(Path(out) / "checkpoint.pt", map_location=device, weights_only=True)
    model.load_state_dict(checkpoint["state_dict"])
    predictions = predict_rows(model, test, config, device, shape)
    metrics = evaluate(predictions, config.bootstrap, config.seed)
    metrics.update(best_epoch=checkpoint["best_epoch"], best_val_macro_f1=best, synthetic=metadata["synthetic"])
    write_csv(Path(out) / "history.csv", history)
    write_csv(Path(out) / "predictions.csv", predictions)
    write_json(Path(out) / "metrics.json", metrics)
    print(f"{Path(out).name}: val F1={best:.4f}; test n={len(test)}", flush=True)
    return metrics


def _probe_eval(model, rows, config, device, shape):
    model.eval()
    n = squared = sx = sy = sxx = syy = sxy = 0.0
    with torch.no_grad():
        for x, mask, _, _ in loader(rows, config, channel="C4", shape=shape):
            pred = model(x[:, :1].to(device)).cpu().numpy()
            target = x[:, 1:2].numpy()
            valid = mask.numpy().astype(bool)
            a, b = pred[valid].astype(np.float64), target[valid].astype(np.float64)
            n += len(a)
            squared += float(np.square(a - b).sum())
            sx += float(a.sum()); sy += float(b.sum())
            sxx += float(np.square(a).sum()); syy += float(np.square(b).sum()); sxy += float((a * b).sum())
    denominator = max(0.0, (n * sxx - sx * sx) * (n * syy - sy * sy)) ** 0.5
    return {"valid_pixels": int(n), "mse_normalized": squared / n, "mse_entropy_bits": squared / n * 64,
            "pearson_r": float(np.clip((n * sxy - sx * sy) / denominator, -1, 1)) if denominator > 1e-12 else None}


def fit_probe(manifest, out, config):
    device = setup(config)
    _, train, val, test, shape, metadata = _training_context(manifest, out, config)
    model = EntropyProbe().to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=config.lr)
    best, history = float("inf"), []
    for epoch in range(1, config.epochs + 1):
        model.train()
        total = pixels = 0.0
        for x, mask, _, _ in loader(train, config, shuffle=True, channel="C4", shape=shape):
            x, mask = x.to(device), mask.to(device)
            optimizer.zero_grad(set_to_none=True)
            loss = masked_mse(model(x[:, :1]), x[:, 1:2], mask)
            loss.backward()
            optimizer.step()
            total += loss.item() * mask.sum().item()
            pixels += mask.sum().item()
        val_metrics = _probe_eval(model, val, config, device, shape)
        history.append({"epoch": epoch, "train_mse": total / pixels, "val_mse": val_metrics["mse_normalized"]})
        print(f"  {Path(out).name} epoch {epoch}/{config.epochs}: val MSE={val_metrics['mse_normalized']:.5f}", flush=True)
        if val_metrics["mse_normalized"] < best:
            best = val_metrics["mse_normalized"]
            torch.save({"state_dict": model.state_dict(), "metadata": metadata, "kind": "probe",
                        "best_epoch": epoch}, Path(out) / "checkpoint.pt")
    checkpoint = torch.load(Path(out) / "checkpoint.pt", map_location=device, weights_only=True)
    model.load_state_dict(checkpoint["state_dict"])
    metrics = {"all": _probe_eval(model, test, config, device, shape),
               "by_variant": {v: _probe_eval(model, [r for r in test if r["variant"] == v], config, device, shape)
                              for v in sorted({r["variant"] for r in test})},
               "synthetic": metadata["synthetic"], "best_epoch": checkpoint["best_epoch"]}
    write_csv(Path(out) / "history.csv", history)
    write_json(Path(out) / "metrics.json", metrics)
    print(f"{Path(out).name}: test probe MSE={metrics['all']['mse_normalized']:.5f}", flush=True)
    return metrics


def predict_checkpoint(checkpoint_path, manifest, out, split="test", device="auto"):
    checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=True)
    if checkpoint["kind"] != "classifier":
        raise ValueError("predict expects a classifier checkpoint.")
    metadata = checkpoint["metadata"]
    config = TrainConfig(**metadata["config"])
    config.device = device
    device_obj = setup(config)
    rows = [r for r in load_prepared(manifest) if r["split"] == split]
    if not rows:
        raise ValueError("Requested split is empty.")
    current = json.loads((Path(manifest).resolve().parent / "dataset.json").read_text(encoding="utf-8"))
    for field in ("height", "width", "entropy_window", "entropy_step", "normalization", "synthetic"):
        if current[field] != metadata["representation"][field]:
            raise ValueError(f"Representation mismatch: {field}")
    model = ByteplotCNN(len(CHANNELS[config.channel])).to(device_obj)
    model.load_state_dict(checkpoint["state_dict"])
    predictions = predict_rows(model, rows, config, device_obj, metadata["feature_shape"])
    write_csv(out, predictions)
    return predictions
