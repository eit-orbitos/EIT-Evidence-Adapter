"""EIT Analyzer Lambda — Evidence Adapter (standalone supplementary tool).

Read-only static evidence inspection. Does not import or execute Analyzer,
Bridge, Genius, or Program Lang code. No signature, experiment, or gate PASS.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import math
import os
import struct
import sys
import zlib
from pathlib import Path, PurePosixPath
import stat
import unicodedata
import zipfile

ADAPTER_VERSION = "0.2.3"
PRODUCT_NAME = "EIT Analyzer Lambda — Evidence Adapter"
STATUS_CONSTANTS_AS_OF = "2026-10-26"
MAX_JSON_INTEGER_DIGITS = 4300
MAX_JSON = 1_048_576
MAX_ZIP_ENTRIES = 256
MAX_ZIP_MEMBER = 8_388_608
MAX_ZIP_TOTAL = 33_554_432
MAX_JSON_DEPTH = 20
MAX_AUDIT_RECORDS = 1000
MAX_INPUT_BYTES = MAX_ZIP_TOTAL + 2_000_000

class EvidenceError(ValueError):
    """Input rejected as unsuitable for bounded documentary inspection."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reject_constant(token: str):
    raise EvidenceError(f"NON_FINITE_JSON_CONSTANT:{token}")


def _parse_finite_float(token: str) -> float:
    """Reject valid JSON numeric lexemes that overflow the host float range."""
    parsed = float(token)
    if not math.isfinite(parsed):
        raise EvidenceError("NON_FINITE_JSON_NUMBER")
    return parsed


def _parse_bounded_int(token: str) -> int:
    """Own lexical budget, independent of PYTHONINTMAXSTRDIGITS; no global edits.

    Nine-digit chunks avoid the host's configurable decimal-conversion ceiling.
    This is bounded conversion, not permission for arbitrarily large integers.
    """
    negative = token.startswith("-")
    digits = token[1:] if negative else token
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        # Preserve the frozen K07 rejection contract.
        raise EvidenceError("INVALID_JSON")
    value = 0
    for offset in range(0, len(digits), 9):
        chunk = digits[offset:offset + 9]
        value = value * (10 ** len(chunk)) + int(chunk)
    return -value if negative else value


def _object_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise EvidenceError("DUPLICATE_JSON_KEY")
        obj[key] = value
    return obj


def _walk_depth(value, depth=0, visits=None):
    if depth > MAX_JSON_DEPTH:
        raise EvidenceError("JSON_DEPTH_LIMIT")
    if visits is None:
        visits = [0]
    visits[0] += 1
    if visits[0] > 200000:
        raise EvidenceError("JSON_NODE_LIMIT")
    if isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise EvidenceError("JSON_INVALID_UNICODE") from exc
    if isinstance(value, dict):
        for k, v in value.items():
            _walk_depth(k, depth + 1, visits)
            _walk_depth(v, depth + 1, visits)
    elif isinstance(value, list):
        for v in value:
            _walk_depth(v, depth + 1, visits)


def strict_json(data: bytes, require_object=True):
    if len(data) > MAX_JSON:
        raise EvidenceError("JSON_BYTE_LIMIT")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as e:
        raise EvidenceError("INVALID_UTF8") from e
    try:
        obj = json.loads(text, object_pairs_hook=_object_pairs,
                         parse_constant=_reject_constant,
                         parse_float=_parse_finite_float,
                         parse_int=_parse_bounded_int)
    except EvidenceError:
        # Preserve precise duplicate-key, constant and finite-number reasons.
        raise
    except (json.JSONDecodeError, RecursionError, ValueError, OverflowError) as e:
        # Includes CPython's bounded decimal-integer conversion failure;
        # never change the process-global int conversion limit.
        raise EvidenceError("INVALID_JSON") from e
    if require_object and not isinstance(obj, dict):
        raise EvidenceError("EXPECTED_JSON_OBJECT")
    _walk_depth(obj)
    return obj


def normalize_member_path(name: str) -> str:
    if not name or "\\" in name or "\x00" in name:
        raise EvidenceError("UNSAFE_ZIP_MEMBER_PATH")
    p = PurePosixPath(name)
    if name.startswith("/") or any(x in ("..", ".") for x in name.split("/")):
        raise EvidenceError("UNSAFE_ZIP_MEMBER_PATH")
    if any(not x for x in name.rstrip("/").split("/")):
        raise EvidenceError("UNSAFE_ZIP_MEMBER_PATH")
    if p.is_absolute() or ":" in name.split("/")[0]:
        raise EvidenceError("UNSAFE_ZIP_MEMBER_PATH")
    return unicodedata.normalize("NFC", name.rstrip("/"))


def _check_zip_extra(extra: bytes) -> None:
    """Bounded structural parsing only; ZIP64 and name overrides are out of scope."""
    pos = 0
    seen = set()
    while pos < len(extra):
        if pos + 4 > len(extra):
            raise EvidenceError("UNREADABLE_ZIP")
        tag, size = struct.unpack_from("<HH", extra, pos)
        pos += 4
        if pos + size > len(extra) or tag in seen:
            raise EvidenceError("UNREADABLE_ZIP")
        seen.add(tag)
        if tag == 0x0001:
            raise EvidenceError("UNSUPPORTED_ZIP64")
        if tag == 0x7075:
            # Do not let another reader select an unvalidated alternate path.
            raise EvidenceError("UNSUPPORTED_ZIP_NAME_OVERRIDE")
        pos += size


def _zip_directory_layout(data: bytes):
    """Preflight the bounded, single-disk classic ZIP central directory.

    This deliberately supports a narrower profile than general ZIP software.
    Metadata count/size is checked before ZipFile allocates its entry objects.
    """
    if not isinstance(data, bytes):
        raise EvidenceError("INVALID_ZIP_INPUT")
    if len(data) > MAX_INPUT_BYTES:
        raise EvidenceError("INPUT_BYTE_LIMIT")
    end = data.rfind(b"PK\x05\x06", max(0, len(data) - 65_557))
    if end < 0 or end + 22 > len(data):
        raise EvidenceError("UNREADABLE_ZIP")
    (_, disk, cd_disk, disk_count, count, cd_size, cd_offset, comment_size) = struct.unpack_from("<4s4H2IH", data, end)
    if end + 22 + comment_size != len(data):
        raise EvidenceError("UNREADABLE_ZIP")
    if disk or cd_disk or disk_count != count:
        raise EvidenceError("UNSUPPORTED_MULTIDISK_ZIP")
    if count == 0xffff or cd_size == 0xffffffff or cd_offset == 0xffffffff:
        raise EvidenceError("UNSUPPORTED_ZIP64")
    if count > MAX_ZIP_ENTRIES:
        raise EvidenceError("ZIP_ENTRY_LIMIT")
    cd_start = end - cd_size
    archive_offset = cd_start - cd_offset
    if cd_start < 0 or archive_offset < 0:
        raise EvidenceError("UNREADABLE_ZIP")
    # An archived ZIP hidden inside the prefix can make streaming ZIP readers
    # extract one set of members while end-directory readers inventory another.
    # An opaque non-ZIP prefix remains allowed/disclosed by the frozen X24 test.
    # Reject ZIP structural signatures in the prefix, even if their occurrence
    # is not a provably valid archive: this documentary profile is fail-closed.
    prefix = data[:archive_offset]
    if any(signature in prefix for signature in
           (b"PK\x03\x04", b"PK\x01\x02", b"PK\x05\x06")):
        raise EvidenceError("PREPENDED_ZIP_RECORDS")
    records = []
    pos = cd_start
    for _ in range(count):
        if pos + 46 > end:
            raise EvidenceError("UNREADABLE_ZIP")
        fields = struct.unpack_from("<4s6H3I5H2I", data, pos)
        if fields[0] != b"PK\x01\x02":
            raise EvidenceError("UNREADABLE_ZIP")
        name_len, extra_len, note_len = fields[10:13]
        next_pos = pos + 46 + name_len + extra_len + note_len
        if next_pos > end or fields[13] != 0:
            raise EvidenceError("UNREADABLE_ZIP")
        if any(fields[i] == 0xffffffff for i in (8, 9, 16)):
            raise EvidenceError("UNSUPPORTED_ZIP64")
        name = data[pos + 46:pos + 46 + name_len]
        extra = data[pos + 46 + name_len:pos + 46 + name_len + extra_len]
        _check_zip_extra(extra)
        records.append((fields, name, archive_offset + fields[16]))
        pos = next_pos
    if pos != end:
        raise EvidenceError("UNREADABLE_ZIP")
    return cd_start, archive_offset, records


def _read_complete_zip_member(data: bytes, info, record, boundary: int) -> bytes:
    """Read raw member span, not ZipExtFile's declared-uncompressed-size prefix.

    Verify matching local metadata, optional data descriptor, exact DEFLATE EOF,
    no unused/truncated stream data, actual length, and CRC over the whole member.
    No extraction, private ZipExtFile state, or unbounded decompress() is used.
    """
    central, raw_name, start = record
    if start < 0 or start + 30 > boundary:
        raise EvidenceError("UNREADABLE_ZIP")
    local = struct.unpack_from("<4s5H3I2H", data, start)
    if local[0] != b"PK\x03\x04":
        raise EvidenceError("UNREADABLE_ZIP")
    name_len, extra_len = local[9:11]
    payload_start = start + 30 + name_len + extra_len
    if payload_start > boundary:
        raise EvidenceError("UNREADABLE_ZIP")
    if data[start + 30:start + 30 + name_len] != raw_name:
        raise EvidenceError("UNREADABLE_ZIP")
    _check_zip_extra(data[start + 30 + name_len:payload_start])
    if local[1] != central[2] or local[2] != info.flag_bits or local[3] != info.compress_type:
        raise EvidenceError("UNREADABLE_ZIP")
    if local[1] > 20:
        raise EvidenceError("UNSUPPORTED_ZIP_VERSION")
    expected = (info.CRC, info.compress_size, info.file_size)
    actual_local = local[6:9]
    descriptor = bool(info.flag_bits & 8)
    if descriptor:
        if any(value not in (0, wanted) for value, wanted in zip(actual_local, expected)):
            raise EvidenceError("UNREADABLE_ZIP")
    elif tuple(actual_local) != expected:
        raise EvidenceError("UNREADABLE_ZIP")
    end = payload_start + info.compress_size
    if end > boundary:
        raise EvidenceError("UNREADABLE_ZIP")
    if descriptor:
        tail = data[end:boundary]
        if len(tail) == 16 and tail[:4] == b"PK\x07\x08":
            tail = tail[4:]
        if len(tail) != 12 or struct.unpack("<3I", tail) != expected:
            raise EvidenceError("UNREADABLE_ZIP")
    elif end != boundary:
        # Reject unreferenced local records and hidden member padding.
        raise EvidenceError("UNREADABLE_ZIP")
    compressed = data[payload_start:end]
    if info.compress_type == zipfile.ZIP_STORED:
        if info.compress_size != info.file_size:
            raise EvidenceError("ZIP_SIZE_MISMATCH")
        member = compressed
    else:
        dec = zlib.decompressobj(-15)
        member = dec.decompress(compressed, min(info.file_size, MAX_ZIP_MEMBER) + 1)
        if len(member) != info.file_size:
            raise EvidenceError("ZIP_SIZE_MISMATCH")
        if not dec.eof or dec.unused_data or dec.unconsumed_tail:
            raise EvidenceError("UNREADABLE_ZIP")
    if len(member) != info.file_size:
        raise EvidenceError("ZIP_SIZE_MISMATCH")
    if zlib.crc32(member) != info.CRC:
        # Frozen K21 requires this controlled error, not BadZipFile leakage.
        raise EvidenceError("UNREADABLE_ZIP")
    return member


def inspect_zip(data: bytes):
    entries, seen, total = [], set(), 0
    directories = 0
    try:
        cd_start, archive_offset, records = _zip_directory_layout(data)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) != len(records):
                raise EvidenceError("UNREADABLE_ZIP")
            starts = sorted(record[2] for record in records)
            if len(set(starts)) != len(starts):
                raise EvidenceError("UNREADABLE_ZIP")
            if starts and (starts[0] != archive_offset or starts[-1] >= cd_start):
                raise EvidenceError("UNREADABLE_ZIP")
            boundaries = dict(zip(starts, starts[1:] + [cd_start]))
            metadata = []
            # Admission of the whole metadata set happens before decompression.
            for info, record in zip(infos, records):
                if info.header_offset != record[2]:
                    raise EvidenceError("UNREADABLE_ZIP")
                safe = normalize_member_path(info.orig_filename)
                if safe in seen:
                    raise EvidenceError("DUPLICATE_ZIP_MEMBER_PATH")
                seen.add(safe)
                if info.flag_bits & 1:
                    raise EvidenceError("ENCRYPTED_ZIP_MEMBER")
                if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise EvidenceError("UNSUPPORTED_ZIP_COMPRESSION")
                allowed_flags = 0x0808 | (0x0006 if info.compress_type == zipfile.ZIP_DEFLATED else 0)
                if info.flag_bits & ~allowed_flags:
                    raise EvidenceError("UNSUPPORTED_ZIP_FLAGS")
                mode = (info.external_attr >> 16) & 0xffff
                ftype = stat.S_IFMT(mode)
                if ftype not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise EvidenceError("UNSAFE_ZIP_MEMBER_TYPE")
                if info.file_size > MAX_ZIP_MEMBER:
                    raise EvidenceError("ZIP_MEMBER_LIMIT")
                total += info.file_size
                if total > MAX_ZIP_TOTAL:
                    raise EvidenceError("ZIP_TOTAL_LIMIT")
                if info.is_dir():
                    if ftype == stat.S_IFREG or info.file_size or info.compress_size:
                        raise EvidenceError("INVALID_ZIP_DIRECTORY")
                    directories += 1
                elif ftype == stat.S_IFDIR:
                    raise EvidenceError("INVALID_ZIP_FILE_TYPE")
                metadata.append((info, record, safe))
            for info, record, safe in metadata:
                member = _read_complete_zip_member(data, info, record, boundaries[record[2]])
                if not info.is_dir():
                    entries.append({"path": safe, "byte_length": len(member),
                                    "sha256": sha256(member), "crc_checked": True,
                                    "complete_member_stream_checked": True})
    except EvidenceError:
        raise
    except (zipfile.BadZipFile, zlib.error, ValueError, struct.error, EOFError,
            OSError, RuntimeError, NotImplementedError, OverflowError) as exc:
        raise EvidenceError("UNREADABLE_ZIP") from exc
    return {"member_count": len(entries), "directory_count": directories,
            "uncompressed_bytes": total, "members": entries,
            "archive_offset": archive_offset, "prepended_bytes": archive_offset,
            "content_validation": "NOT_PERFORMED",
            "archive_authenticity": "NOT_ESTABLISHED"}


def _read_bounded_regular_file(path: Path) -> bytes:
    """No final-component symlink follow where supported; bound the actual read.

    Parent-directory custody and concurrent in-place file mutation remain outside
    this local reader's assurance. This is not a deployment trust-root verifier.
    """
    try:
        entry = path.lstat()
    except OSError as exc:
        raise EvidenceError("INPUT_NOT_REGULAR_FILE") from exc
    if not stat.S_ISREG(entry.st_mode):
        raise EvidenceError("INPUT_NOT_REGULAR_FILE")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = None
    try:
        fd = os.open(path, flags)
        actual = os.fstat(fd)
        if not stat.S_ISREG(actual.st_mode) or (actual.st_dev, actual.st_ino) != (entry.st_dev, entry.st_ino):
            raise EvidenceError("INPUT_NOT_REGULAR_FILE")
        if actual.st_size > MAX_INPUT_BYTES:
            raise EvidenceError("INPUT_BYTE_LIMIT")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            raw = stream.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise EvidenceError("INPUT_BYTE_LIMIT")
        return raw
    finally:
        if fd is not None:
            os.close(fd)


def inspect_file(path: Path, expected_digest=None, kind=None):
    raw = _read_bounded_regular_file(path)
    digest = sha256(raw)
    result = {"filename": path.name, "byte_length": len(raw),
              "sha256_local_recomputed": digest, "origin_authenticity": "UNKNOWN",
              "execution_attestation": "NO_EVIDENCE"}
    if expected_digest is None:
        result["integrity"] = "NO_REFERENCE"
    else:
        if not isinstance(expected_digest, str) or len(expected_digest) != 64 or any(c not in '0123456789abcdef' for c in expected_digest):
            raise EvidenceError("INVALID_EXPECTED_SHA256")
        result["reference_sha256"] = expected_digest
        result["integrity"] = "MATCH" if digest == expected_digest else "MISMATCH"
    suffix = (kind or path.suffix.lstrip('.')).lower()
    if suffix == 'zip':
        result["static_zip_inventory"] = inspect_zip(raw)
    elif suffix == 'json':
        result["json_top_level_keys"] = sorted(strict_json(raw).keys())
    elif suffix in ('txt', 'md', 'csv'):
        if len(raw) > MAX_JSON:
            raise EvidenceError("TEXT_BYTE_LIMIT")
        try: raw.decode('utf-8', errors='strict')
        except UnicodeDecodeError as e: raise EvidenceError('INVALID_UTF8') from e
    else:
        result["uninterpreted_file_type"] = suffix
    return result


def create_report(inputs, source_label='LOCAL_CAPTURED_BYTES'):
    if len(inputs) > MAX_AUDIT_RECORDS:
        raise EvidenceError('AUDIT_RECORD_LIMIT')
    rows = []
    for path, digest, kind in inputs:
        try:
            result = inspect_file(Path(path), digest, kind)
            result['status'] = 'INSPECTED'
        except EvidenceError as exc:
            result = {"filename": Path(path).name, "status": "BLOCKED",
                      "reason": str(exc), "error_category": "CONTROLLED_INPUT_REJECTION"}
        except OSError as exc:
            result = {"filename": Path(path).name, "status": "BLOCKED",
                      "reason": "INPUT_READ_ERROR:" + type(exc).__name__, "error_category": "IO_ERROR"}
        except Exception as exc:
            # A programming/unclassified input failure is not an expected rejection
            # or security PASS. Preserve the blocked row and continue the batch.
            result = {"filename": Path(path).name, "status": "BLOCKED",
                      "reason": "INTERNAL_ERROR:" + type(exc).__name__, "error_category": "INTERNAL_ERROR"}
        rows.append(result)
    return {
        "contract_version": ADAPTER_VERSION,
        "report_kind": "DOCUMENTARY_AUDIT_ONLY",
        "source_observation": source_label,
        "status_constants_as_of": STATUS_CONSTANTS_AS_OF,
        "status_constants_authority": "HISTORICAL_REPORTED_SNAPSHOT_NOT_LIVE",
        "evidence_inventory": rows,
        "bridge_findings": {f'BR-{i:02}': 'OPEN' for i in range(1, 6)},
        "kimi_findings": {f'KB-{i:02}': 'OPEN' for i in range(1, 8)},
        "genius_review_recommendations": {"G1":"PENDING", "G2":"PENDING",
            "G3":"UNRESOLVED", "G4":"UNRESOLVED", "G5":"NOT_TESTABLE_CURRENT_EVIDENCE"},
        "genius_g4_vs_program_lang_gate4": "DISTINCT_UNRELATED_NAMESPACES",
        "program_lang_reference": {"provenance":"AUTHOR_SUPPLIED_NOT_RERATIFIED",
            "V0.3":"QUALIFIED_RATIFIED", "N1":"OPEN_BLOCKING", "B4":"NOT_CLOSED",
            "RG6":"OPEN", "GATE4":"NOT_SATISFIED"},
        "eureka_validation": "NOT_PROVEN",
        "implementation_approval": "NO",
        "project_runtime": "NOT_RUN",
        "final_adapter_assessment": ('BLOCKED' if any(r['status']=='BLOCKED' or r.get('integrity')=='MISMATCH' for r in rows) else 'DOCUMENTARY_INSPECTION_ONLY'),
        "limitations": ["Hashes demonstrate byte agreement, not authenticity, execution, physical claims or scientific validity.",
            "No native Analyzer functions, Program Lang code, or Bridge programs were run.",
            "No G1-G5 result or release gate is changed by this report."]
    }


def main(argv=None):
    p = argparse.ArgumentParser(description='Static, local-only evidence reader')
    p.add_argument('files', nargs='+', help='Local input files to inspect (no source execution)')
    p.add_argument('--expected-sha256', help='Expected digest for a single file')
    p.add_argument('--output', required=True, help='Fresh report filename; must not exist')
    args = p.parse_args(argv)
    if args.expected_sha256 and len(args.files) != 1:
        p.error('--expected-sha256 only valid with one input')
    if len(args.files) > MAX_AUDIT_RECORDS:
        p.error('AUDIT_RECORD_LIMIT: too many input files')
    out = Path(args.output)
    if out.exists() or out.is_symlink():
        p.error('output already exists: refusing overwrite')
    inputs = [(f, args.expected_sha256 if i == 0 else None, None) for i,f in enumerate(args.files)]
    if any(Path(f).resolve() == out.resolve() for f in args.files):
        p.error('input and output must differ')
    report = create_report(inputs)
    # Escape unencodable filesystem labels safely; strict input JSON still rejects
    # surrogates. This is no-overwrite output, not a crash-safe transaction.
    try:
        encoded = (json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)+'\n').encode('utf-8')
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open('xb') as f:
            f.write(encoded)
    except (OSError, ValueError, UnicodeError) as exc:
        print('REPORT_WRITE_FAILED:' + type(exc).__name__, file=sys.stderr)
        return 1
    print('REPORT_CREATED', out, sha256(encoded), report['final_adapter_assessment'])
    return 0 if report['final_adapter_assessment'] != 'BLOCKED' else 2

if __name__ == '__main__':
    raise SystemExit(main())
