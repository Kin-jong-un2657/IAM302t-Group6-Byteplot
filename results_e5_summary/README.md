# E5: Conditional UPX-to-MPRESS Pilot

The released [per-run CSV](E5_RESULTS.csv), [channel summary](E5_CHANNEL_SUMMARY.csv), [plot](E5_MACRO_F1.png) and [protocol/status](E5_STATUS.json) describe C1–C4 with seeds 17, 37 and 73. All 12 jobs evaluate the same ten independent test parents (eight malware, two benign), not 30 independent observations. Source/toolchain confounding remains unresolved.

[E5_VERIFICATION.json](E5_VERIFICATION.json) and [VERIFICATION.json](VERIFICATION.json) explain the aggregate checks and their limits. [PAIRED_CORRECTNESS.json](PAIRED_CORRECTNESS.json) contains contingency counts without parent identities. [E5_INTERPRETATION_VI.txt](E5_INTERPRETATION_VI.txt) is the original detailed Vietnamese interpretation. [TEACHER_REQUIREMENTS_STATUS.json](TEACHER_REQUIREMENTS_STATUS.json) separates this completed pilot from the incomplete matched-cohort work.

Archive/checksum receipts retain their historical provenance; source ZIPs, private manifests and unrelated research packets named by those receipts are intentionally not distributed. [PUBLICATION_SHA256.json](PUBLICATION_SHA256.json) gives checksums of files actually included in this directory. Historical `FILES_SHA256.json` and `SAFE_CHECKSUMS.json` refer to original export bytes and are not a promise that every original archive member is bundled here.

Run `python workspace_tools/verify_artifacts.py e5` from the repository root to recompute aggregate point metrics and seed mean/sample SD. No real model checkpoint, individual prediction file or feature packet is published, so this does not independently rerun training or reconstruct bootstrap intervals.
