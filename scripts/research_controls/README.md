# Auxiliary Metadata Research Controls

These helpers support metadata screening, compiler/linker controls, prospective matching, bounded intake and resumable static auditing. They are separate from the core `byteplot` CLI and its six-file test suite.

Run their fixture-only tests with:

```bash
python -m pytest scripts/research_controls -q
```

Private numeric caches, family/sample identity tables, approved input manifests and checksum-pinned historical kits are not distributed. Names containing `PRIVATE` in the source describe required inputs or outputs; no such identity-bearing artifact is bundled. VM/Colab entrypoints preserve their historical scope/checksum restrictions and are not intended to run from a public source-only checkout. The numeric screener's legacy archive inputs are relative to its `BODMAS_NUMERIC_PRIVATE` input directory.

Prospective candidates and metadata matches are not verified V0 samples, admitted training parents or proof of a completed source-matched cohort. Use the published [requirements status](../../results_e5_summary/TEACHER_REQUIREMENTS_STATUS.json) for research completion claims.
