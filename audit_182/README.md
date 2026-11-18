# Redacted Static Audit Evidence

The current export is [Static182_audit_redacted.csv](Static182_audit_redacted.csv), bound to [STATIC182_REDACTED_EXPORT_RECEIPT.json](STATIC182_REDACTED_EXPORT_RECEIPT.json). It contains 182 ordinal audit records; no identity-bearing sample manifest is distributed. Recount and checksum verification are available through `workspace_tools/verify_artifacts.py audit` from the repository root.

The [VM receipt](VM_STATIC182_RECEIPT.json) is historical: its `dataset_complete` flag applies only to the selected 182-record inventory, not the entire BODMAS dataset. Its note about a missing per-file CSV describes that earlier hand-in; the later redacted CSV is now included.

[E0_ANALYSIS_REPORT.md](E0_ANALYSIS_REPORT.md) is the original Vietnamese narrative dated 2 November 2026. Its statement that E5 had not run is historical, superseded by the [completed E5 pilot evidence](../results_e5_summary/README.md). Its references to private UPX/source-control packets are provenance labels, not bundled inputs or reproducible links.

The 182 audit records must not be added to the pilot's ten test parents. DiE clean is not proof of unpacked status or safety. The 145 records exceeding 64 KiB identify representation truncation, not physical PE corruption. Source/toolchain confounding and packer compatibility selection remain unresolved.
