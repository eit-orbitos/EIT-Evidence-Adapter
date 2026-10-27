# Changelog

## 0.2.4 — documentary and bounded ZIP reason-code candidate

- N23-01: align historical V0.3 expectation chronology with existing oracle metadata; no historical preregistration claimed.
- N23-02: classify ZIP64 end-of-central-directory locators as `UNSUPPORTED_ZIP64` before prepended-record checks; add new Y10 supplemental test.
- N23-03: make direct test discovery and imports robust by inserting project-root path in V0.2.3 boundary tests.
- Align authored documentation and company attribution with EITNetworks LLC and the author-applied licenses.
- The frozen oracle, its historical test-file SHA, original 25 baseline tests, original 44 supplementary tests, and original 9 V0.3 expectations are retained unchanged. A separate V0.2.4 test-SHA addendum records the updated V0.2.3 boundary test file.
- Local candidate only: tests and independent verification have not been performed by this builder.

## 0.2.3 — supplementary security candidate

- P2-NEW-01: reject prepended ZIP record signatures (`PK` local, central, EOCD) with controlled `PREPENDED_ZIP_RECORDS`; ordinary opaque prefixes remain admitted and disclosed to preserve frozen X24.
- N22-03: more than 1000 CLI arguments now returns controlled argument usage exit 2, not a traceback.
- N22-06: clarified license-scope wording; licensing applicability and public release still require the copyright holder's explicit approval.
- New `ORACLE_V0.3_SECURITY_CASES.json` and nine new tests, locally prepared; the V0.3 oracle explicitly records expectations_created_before_source_patch=false and was frozen after the source patch, without independent timestamp evidence; pre-existing 25+44 tests and frozen 32-case oracle remain unchanged.
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
