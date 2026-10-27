import argparse
from pathlib import Path


def training_args(parser):
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--lr", type=float, default=0.001)
    parser.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--bootstrap", type=int, default=500)
    parser.add_argument("--no-class-weight", action="store_true")


def config_from(args):
    from .engine import TrainConfig
    return TrainConfig(epochs=args.epochs, batch_size=args.batch_size, lr=args.lr, device=args.device,
                       threads=args.threads, bootstrap=args.bootstrap, class_weight=not args.no_class_weight)


def main():
    parser = argparse.ArgumentParser(description="G6 static byteplot experiments; demo uses non-executable synthetic data.")
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo", help="Run E0-E5 on clearly marked synthetic data (no real PE/UPX).")
    demo.add_argument("--out", default="demo-output")
    demo.add_argument("--parents-per-class", type=int, default=20)
    demo.add_argument("--epochs", type=int, default=1)
    demo.add_argument("--seed", type=int, default=17)

    synthetic = sub.add_parser("synthetic", help="Generate non-executable byte fixtures.")
    synthetic.add_argument("--out", required=True)
    synthetic.add_argument("--parents-per-class", type=int, default=20)
    synthetic.add_argument("--seed", type=int, default=17)

    index = sub.add_parser("index", help="VM only: index originals and inspect using DiE CLI.")
    index.add_argument("--benign", required=True)
    index.add_argument("--malware", required=True)
    index.add_argument("--out", required=True)
    index.add_argument("--die", required=True, help="Path to diec/diec.exe, not the sample.")
    index.add_argument("--metadata", help="Optional BODMAS metadata CSV (sha/sha256, family).")

    variants = sub.add_parser("variants", help="VM only: make V1/V1u using UPX; optionally import external V2.")
    variants.add_argument("--manifest", required=True)
    variants.add_argument("--out", required=True)
    variants.add_argument("--upx", required=True)
    variants.add_argument("--die", required=True)
    variants.add_argument("--v2-dir", help="External V2 directory with <parent_sha256>.bin files.")
    variants.add_argument("--v2-packer", default="external")

    prepare = sub.add_parser("prepare", help="Extract aligned image channels from a binary manifest.")
    prepare.add_argument("--manifest", required=True)
    prepare.add_argument("--out", required=True)
    prepare.add_argument("--height", type=int, default=256)
    prepare.add_argument("--width", type=int, default=256)
    prepare.add_argument("--window", type=int, default=256)
    prepare.add_argument("--step", type=int, default=64)
    prepare.add_argument("--seed", type=int, default=17)
    prepare.add_argument("--val-fraction", type=float, default=0.15)
    prepare.add_argument("--test-fraction", type=float, default=0.15)

    for command in ("train", "probe", "suite"):
        p = sub.add_parser(command, help={"train": "Train one C1-C4 classifier.", "probe": "Train entropy reconstruction probe.",
                                          "suite": "Run research E0-E5 recipes with multiple seeds."}[command])
        p.add_argument("--manifest", required=True, help="Path to prepared.csv (not raw manifest).")
        p.add_argument("--out", required=True)
        training_args(p)
        if command == "suite":
            p.add_argument("--seeds", nargs="+", type=int, default=[17, 37, 73])
            p.add_argument("--fractions", nargs="+", type=float, default=[0.1, 0.25, 0.5, 1.0])
            p.add_argument("--experiments", nargs="+", choices=[f"E{i}" for i in range(6)], default=[f"E{i}" for i in range(6)])
            p.add_argument("--source-manifest", help="Raw variants manifest, for failure-rate auditing.")
        else:
            p.add_argument("--seed", type=int, default=17)
            p.add_argument("--variants", nargs="+", choices=["V0", "V1", "V1u", "V2"], default=["V0", "V1"])
            p.add_argument("--fraction", type=float, default=1.0)
            if command == "train":
                p.add_argument("--channel", choices=["C1", "C2", "C3", "C4"], default="C1")
                p.add_argument("--benign-packed-keep", type=float, default=1.0)

    predict = sub.add_parser("predict", help="Predict a prepared split with a saved classifier.")
    predict.add_argument("--checkpoint", required=True)
    predict.add_argument("--manifest", required=True)
    predict.add_argument("--out", required=True)
    predict.add_argument("--split", choices=["train", "val", "test"], default="test")
    predict.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")

    audit = sub.add_parser("audit", help="Validate splits and run the E0 artifact baseline.")
    audit.add_argument("--manifest", required=True)
    audit.add_argument("--out", required=True)
    audit.add_argument("--source-manifest")
    audit.add_argument("--bootstrap", type=int, default=500)

    pe_audit = sub.add_parser("audit-pe", help="VM only: read-only PE audit of existing candidates.")
    pe_audit.add_argument("--manifest", required=True, help="Existing candidate CSV; never modified.")
    pe_audit.add_argument("--binary-root", required=True, help="Directory containing extracted sample paths.")
    pe_audit.add_argument("--out", required=True, help="New output CSV outside binary-root; never overwritten.")
    pe_audit.add_argument("--path-column", default="zip_member")
    pe_audit.add_argument("--height", type=int, default=256)
    pe_audit.add_argument("--width", type=int, default=256)
    pe_audit.add_argument("--die", help="Optional trusted diec executable outside binary-root.")
    pe_audit.add_argument("--timeout", type=float, default=120.0)
    pe_audit.add_argument("--die-db-id", default="", help="Optional user-recorded DiE database version/commit.")

    view = sub.add_parser("visualize", help="Write channel visualizations as PNG.")
    view.add_argument("--manifest", required=True)
    view.add_argument("--out", required=True)
    view.add_argument("--limit", type=int, default=4)

    args = parser.parse_args()
    try:
        if args.command == "demo":
            from .synthetic import make_synthetic
            from .representation import prepare
            from .engine import TrainConfig
            from .experiments import run_suite
            root = Path(args.out)
            raw = make_synthetic(root / "synthetic", args.parents_per_class, args.seed)
            manifest = prepare(raw, root / "prepared", height=64, width=64, seed=args.seed)
            config = TrainConfig(epochs=args.epochs, bootstrap=30, device="cpu")
            report = run_suite(manifest, root / "runs", config, seeds=[args.seed], fractions=[0.5, 1.0], source_manifest=raw)
            print(f"\nSYNTHETIC DEMO ONLY. Open {report.resolve()}")
        elif args.command == "synthetic":
            from .synthetic import make_synthetic
            print(make_synthetic(args.out, args.parents_per_class, args.seed))
        elif args.command == "index":
            from .vm_tools import index_originals
            index_originals(args.benign, args.malware, args.out, args.die, args.metadata)
        elif args.command == "variants":
            from .vm_tools import build_variants
            build_variants(args.manifest, args.out, args.upx, args.die, args.v2_dir, args.v2_packer)
        elif args.command == "prepare":
            from .representation import prepare
            prepare(args.manifest, args.out, args.height, args.width, args.window, args.step, args.seed,
                    args.val_fraction, args.test_fraction)
        elif args.command in ("train", "probe", "suite"):
            from .engine import fit_classifier, fit_probe
            config = config_from(args)
            if args.command == "suite":
                from .experiments import run_suite
                run_suite(args.manifest, args.out, config, args.seeds, args.fractions, args.experiments, args.source_manifest)
            else:
                config.seed, config.variants, config.fraction = args.seed, tuple(args.variants), args.fraction
                if args.command == "train":
                    config.channel, config.benign_packed_keep = args.channel, args.benign_packed_keep
                    fit_classifier(args.manifest, args.out, config)
                else:
                    fit_probe(args.manifest, args.out, config)
        elif args.command == "predict":
            from .engine import predict_checkpoint
            predictions = predict_checkpoint(args.checkpoint, args.manifest, args.out, args.split, args.device)
            print(f"Saved {len(predictions)} predictions -> {args.out}")
        elif args.command == "audit":
            from .experiments import audit
            audit(args.manifest, args.out, args.source_manifest, args.bootstrap)
        elif args.command == "audit-pe":
            from .pe_audit import audit_pe
            try:
                audit_pe(args.manifest, args.binary_root, args.out, args.height, args.width,
                         args.die, args.timeout, args.path_column, args.die_db_id)
            except OSError as exc:
                parser.exit(2, f"Error: {exc}\n")
        elif args.command == "visualize":
            from .io import load_prepared
            from .report import visualize
            visualize(load_prepared(args.manifest), args.out, args.limit)
    except (ValueError, FileNotFoundError) as exc:
        parser.exit(2, f"Error: {exc}\n")
