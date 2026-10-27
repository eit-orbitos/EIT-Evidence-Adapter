# EIT Analyzer Lambda — Evidence Adapter

**Software version: 0.2.4. Python 3.12+; standard library only.**

Standalone, local, read-only inspection of JSON, text and a bounded ZIP profile. The adapter writes a new documentary JSON report. It does not load or run payloads, does not invoke Analyzer V4.2.1, Bridge, Genius or Program Lang, and never awards scientific PASS or closes a governance gate.

“V5C” in historical review files refers to the documentary V5.0-C evidence context, **not Analyzer V5**. This tool is a supplement, not an integrated replacement or upgrade of Analyzer V4.2.1.

## Run

```sh
python -B evidence_adapter.py input.json --output new_report.json
python -B evidence_adapter.py input.zip --expected-sha256 <64-lowercase-hex> --output new_report.json
python -B evidence_adapter.py good.json suspect.zip --output batch_report.json
```

An expected digest is supported for exactly one input. A matching digest establishes agreement with that reference, not the authenticity of the reference. Output must be a fresh path and may not overwrite an input. Parent directories may be created. Exit 0 means a completed documentary inspection, **not a security PASS**; exit 2 means a completed BLOCKED report (or CLI usage error); exit 1 means an output/system failure. One bad input normally becomes a BLOCKED row without dropping the other inputs. More than 1000 CLI inputs trigger a controlled usage error (exit 2). Unexpected ordinary exceptions become `INTERNAL_ERROR:<type>`, not expected rejections. Process termination, resource exhaustion and OS failures are not promised to be recoverable.

## Exact JSON policy

Strict UTF-8, object top-level by default; duplicate keys, non-finite numeric values and lone surrogates are rejected. Finite exponent underflow follows Python float semantics (`1e-400` becomes `0.0`); this reader does not claim lossless numeric semantics. Maximum JSON size 1 MiB, depth 20 (keys count as a descent), node count 200,000. Integer lexemes are limited to **4,300 digits excluding sign**, independently of the host's integer-conversion setting. The adapter never changes that setting; bounded chunk conversion preserves acceptance at 4,300 even on a stricter host.

## Exact ZIP policy

Read-only, no extraction, no recursive archive or content execution. Input bytes are bounded to 35,554,432; at most 256 central entries, 8 MiB per member and 32 MiB total uncompressed data. Only classic single-disk STORED/DEFLATED members are supported. The complete central directory, local headers, sizes, CRCs, member spans and optional 12/16-byte data descriptors are checked. DEFLATE must reach EOF exactly, without unused or truncated stream bytes. The SHA-256 is of the complete verified member, never an accepted prefix.

NFC-equivalent paths, traversal/absolute/backslash/NUL paths, symlinks/special files, encryption and unsupported flags/methods are rejected. ZIP64, alternate Unicode-path extra fields, undocumented inter-record gaps and central-directory signature extensions are outside this bounded profile and are rejected. Directory entries require zero compressed and uncompressed size; even an empty **deflated** directory is intentionally outside the profile. Empty STORED directories are counted separately. This is a documented compatibility restriction, not a claim that every rejected archive violates general ZIP standards.

Opaque prepended bytes are reported as `archive_offset` / `prepended_bytes`, not executed. **Any prepended bytes containing ZIP local-header, central-directory or end-of-directory signatures are rejected** (`PREPENDED_ZIP_RECORDS`) to prevent the documented reader-differential double-archive case. This is a conservative signature check, not formal consensus across all ZIP readers; an opaque prefix without those signatures remains admitted under the historical X24 contract. Case-only, NFKC-only and file-vs-directory naming collisions are permitted because nothing is extracted; this policy must be reconsidered before extraction could ever be added. ZIP member payloads are inventoried, **not recursively JSON/schema validated** (`content_validation=NOT_PERFORMED`). Text `.txt` containing JSON is not JSON-validated, and unknown extensions remain byte inventories.

## Trust and limitations

Reports separate integrity, origin, execution and semantic claims. Self-signed labels, hashes, DOI strings or reviewer names supplied by an input do not become verified authority. Historical governance constants are explicitly dated `2026-10-26` and labelled not-live/non-authoritative; they do not refresh or modify any project ledger. No C3-E enforcement, S1/N-1 fix, scientific validation, formal proof, malware scanning or full ZIP interoperability is claimed.

Regular input files are opened without following a final symlink where supported, checked with fstat and read with a hard byte ceiling. Ancestor-directory custody and concurrent in-place mutation are not authenticated. Output uses exclusive creation; it is not a crash-consistent transaction or a network/filesystem rollback guarantee. The tool is not a hardened service for arbitrary remote uploads.

## Tests

```sh
python -B -m unittest discover -s tests -v
python -B tools/run_frozen_oracle.py --source evidence_adapter.py --expected-source-sha256 <exact-source-sha256> --output new_oracle_receipt.json
python -B tools/run_bounded_stress.py --source evidence_adapter.py --expected-source-sha256 <exact-source-sha256> --output new_stress_receipt.json
```

The original 25 unit tests and original 32-case V0.1 oracle/runner remain unchanged. `test_release_regressions.py` contains the 44 preserved supplemental cases; `test_v023_boundary.py` adds 9 further expectations recorded separately in `ORACLE_V0.3_SECURITY_CASES.json` (locally prepared and frozen after the v0.2.3 source patch, without independent timestamp attestation); `ORACLE_V0.2_PREDECLARED.json` binds their intent and exact test bytes. Tests X10/X11 cover integer configuration; X26 replaces the old weak no-execution assertion with a sentinel check; X27 exercises supplied false trust/gate claims and matching/mismatching hash references. The original weak K22/K32 cases are retained as historical regression checks, not promoted as complete proofs.

Independent review status and test transcripts belong to a separate evidence handoff. Passing tests does not authorize publication. See LICENSE/NOTICE and LICENSE-SCOPE.md. The publisher personally uploads any final release; no automatic publication code is included.
