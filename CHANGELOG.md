# Changelog

## 0.2.3 — supplementary security candidate

- P2-NEW-01: reject prepended ZIP record signatures (`PK` local, central, EOCD) with controlled `PREPENDED_ZIP_RECORDS`; ordinary opaque prefixes remain admitted and disclosed to preserve frozen X24.
- N22-03: more than 1000 CLI arguments now returns controlled argument usage exit 2, not a traceback.
- N22-06: clarified license-scope wording; licensing applicability and public release still require the copyright holder's explicit approval.
- New `ORACLE_V0.3_SECURITY_CASES.json` and nine new tests, locally authored before the source patch without independent timestamp evidence; pre-existing 25+44 tests and frozen 32-case oracle remain unchanged.
- Retains known limitations around file comments/extra metadata, historic status constants, host Unicode version, no nested content validation and trusted-origin evidence.

## 0.2.2

- F-P1-01: preserve typed controlled ZIP rejections and isolate ordinary per-input errors so hostile input does not discard a batch report.
- F-P1-02: validate complete raw member streams, local/central fields, exact size/CRC and descriptors; refuse prefix-only inventories.
- F-P2-01: reject lone JSON surrogates and safely escape filesystem labels in output JSON.
- F-P2-02: fixed 4,300-digit lexical integer budget; no process-global limit mutation; bounded chunk conversion independent of host setting.
- F-P2-03: reject directory entries carrying compressed/uncompressed bytes.
- F-P2-04: preserve original oracle and runner, add a separately predeclared 44-case regression set including meaningful no-execution/trust-injection probes.
- Narrow ZIP profile explicitly excludes ZIP64, alternate-name extra fields, hidden gaps and nonzero-size directory entries; valid signed/unsigned data descriptors supported.
- Notes: disclose archive offset/content-validation scope and dated governance constants; restore runtime/CLI documentation; bounded actual file reads and fstat identity checks.
- Packaging: clean version/name, LICENSE/NOTICE/CITATION and scope files, separate supplementary-record metadata draft in external handoff. No Analyzer integration or Program Lang state change.

The substantial ZIP parsing changes require fresh independent review; this is not just a version-bump patch. No claim that all possible security issues are fixed.
