# Verification and Evidence Review

This publication separates software verification, saved research aggregates and future research. Its source was assembled from the local interview workspace on **18 November 2026**. The core `byteplot/` modules and six core test files are unchanged from the inspected official source; documentation, portable runners and evidence packaging were refreshed.

## Software verification

The sanitized [verification record](verification/RESULTS.json) records **71 passed / one skipped** across the six core pytest files. The skipped test requires host symlink capability. The CPU synthetic workflow used 24 parents / 96 variants, exercised E0–E5, trained 17 classifier runs and one entropy probe, and checked 85 metric groups. Synthetic checkpoint replay produced 24 predictions for six parents with unchanged labels and maximum probability difference zero.

Reproduce these checks with [RUNNING.md](RUNNING.md). Generated reports, feature arrays and checkpoints are local outputs and are not linked as though they were committed evidence. The dated record describes the local verification; [publication validation](verification/PUBLICATION_VALIDATION.json) records checks rerun on this publication snapshot.

## Research evidence

- [Static audit CSV](audit_182/Static182_audit_redacted.csv): 182 ordinal records, 182 parsed, DiE 102 clean / 58 packed / 22 unknown, 145 exceeding the 64 KiB image prefix. The [export receipt](audit_182/STATIC182_REDACTED_EXPORT_RECEIPT.json) binds the CSV checksum. This metadata export is not a new PE-analysis run.
- [E5 per-run results](results_e5_summary/E5_RESULTS.csv) and [summary](results_e5_summary/E5_CHANNEL_SUMMARY.csv): 12 configuration/seed jobs on the same ten independent test parents, including two benign. Saved confusion matrices reproduce Macro-F1 and FPR; channel means and sample SDs are consistent.
- [E5 verification scope](results_e5_summary/E5_VERIFICATION.json): no private checkpoint or parent-prediction replay, and no independent bootstrap-CI reconstruction. The published data is sufficient for aggregate consistency checks, not full real-training reproduction.

The research receipts are retained with their original historical scope. In particular, the older VM audit receipt says a per-file CSV was missing at that hand-in, while the later redacted export supplies it here; the 2 November E0 narrative predates the completed E5 pilot. [Audit notes](audit_182/README.md) and [E5 evidence notes](results_e5_summary/README.md) explain these distinctions.

## Limits and future work

The full research question remains open. A source/toolchain-matched cohort, expanded independent evaluation and external holdout remain incomplete. The E5 pilot does not remove packing-compatibility selection bias, prefix truncation or source/compiler/linker confounding. Seed repetitions are not additional independent samples. See the [README limitations](README.md) and [requirements status](results_e5_summary/TEACHER_REQUIREMENTS_STATUS.json).

## Publication hygiene

Only reviewed code, documentation, an empty schema template, redacted audit records, aggregate result tables/plot and verification metadata are published. Private runtime settings, identity manifests, raw PE binaries, real feature arrays, model files and source archives are excluded. The original working directory in the verification record was replaced with `.`. Historical device-specific archive locations in the numeric metadata helper were replaced with paths relative to its private input directory; checksum gates remain intact.
