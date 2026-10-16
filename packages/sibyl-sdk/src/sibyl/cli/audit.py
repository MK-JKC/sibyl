"""Offline audit-chain verification: ``sibyl audit verify`` (R33, ADR-12).

Verifies an exported audit chain (``sibyl.audit_export/1`` JSONL from ``POST /audit/exports``)
with no server access, against signed anchors and the public ``audit_anchor`` key set:

1. every row's envelope and detail are re-canonicalised (RFC 8785) and re-hashed:
   ``hash = sha256(prev_hash ‖ sha256(JCS(envelope)) ‖ sha256(JCS(detail)))``;
2. rows are contiguous (``gap``), each ``prev_hash`` is the previous row's ``hash``
   (``prev_mismatch``; ``seq`` 0 starts from 32 zero bytes), the stored envelope / detail
   digests match (``content_mismatch``) and so does the row hash (``hash_mismatch``);
3. every anchor (``--anchor`` files, else the export's own ``anchor`` lines) is Ed25519-signed
   over ``JCS(anchor document)`` by a key in the key set (``anchor_signature``; a
   ``compromised`` key never verifies), names the export's tenant (``anchor_tenant``) and its
   ``head_hash`` equals the row hash at its ``seq_to`` (``anchor_mismatch``);
4. the rows end at an anchor: rows after the highest verified anchor are not attested
   (``unanchored_tail``), and an export with no usable anchor fails (``no_anchor``).

Exit status: 0 the chain verifies, 1 a break (reported with its ``seq`` and kind), 2 unusable
input (unreadable file, malformed JSON, unknown key). The formats, field lists and break kinds
come from ``sibyl_schemas`` (``audit_chain``, ``ChainBreakKind``), the one definition the control
plane writes exports with; this module is Apache-2 and imports nothing from the control plane.

The verifier deliberately hashes and signs exactly what the file holds: it uses the strict
``audit_chain.envelope_strict`` / ``anchor_document_of_strict`` (no type coercion, which would,
e.g., accept an upper-case UUID or a string ``seq_from`` that was never signed) and the digests
with ``allow_floats=False``.
"""

from __future__ import annotations

import binascii
import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from sibyl_schemas.audit_chain import (
    EXPORT_FORMAT,
    GENESIS_HASH,
    anchor_document_of_strict,
    b64url_decode,
    detail_sha256,
    envelope_sha256,
    envelope_strict,
)
from sibyl_schemas.canonical import CanonicalizationError, canonicalize, parse_json_strict
from sibyl_schemas.values import ChainBreakKind

MAX_LINE_BYTES = 1 << 20
GAP: Final = ChainBreakKind.GAP.value
PREV_MISMATCH: Final = ChainBreakKind.PREV_MISMATCH.value
CONTENT_MISMATCH: Final = ChainBreakKind.CONTENT_MISMATCH.value
HASH_MISMATCH: Final = ChainBreakKind.HASH_MISMATCH.value
ANCHOR_MISMATCH: Final = ChainBreakKind.ANCHOR_MISMATCH.value
ANCHOR_SIGNATURE: Final = ChainBreakKind.ANCHOR_SIGNATURE.value
# Offline-only verdicts (``OFFLINE_CHAIN_BREAK_KINDS``: no server-side ``sibyl.audit_verify``
# counterpart): an anchor of another tenant, no usable anchor, rows past the last anchor.
ANCHOR_TENANT: Final = ChainBreakKind.ANCHOR_TENANT.value
NO_ANCHOR: Final = ChainBreakKind.NO_ANCHOR.value
UNANCHORED_TAIL: Final = ChainBreakKind.UNANCHORED_TAIL.value


class InputError(ValueError):
    """The input cannot be verified at all (exit 2)."""


@dataclass(frozen=True)
class PublicKey:
    kid: str | None
    raw: bytes
    state: str = "active"


@dataclass
class Report:
    ok: bool
    rows: int = 0
    from_seq: int | None = None
    to_seq: int | None = None
    anchors_checked: int = 0
    first_break_seq: int | None = None
    kind: str | None = None
    detail: str | None = None
    tenant_id: str | None = None
    anchored_to: int | None = None
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "rows": self.rows,
            "from_seq": self.from_seq,
            "to_seq": self.to_seq,
            "anchors_checked": self.anchors_checked,
            "anchored_to": self.anchored_to,
            "first_break_seq": self.first_break_seq,
            "kind": self.kind,
            "detail": self.detail,
            "tenant_id": self.tenant_id,
            "warnings": list(self.warnings),
        }


class _Break(Exception):
    def __init__(self, seq: int | None, kind: str, detail: str) -> None:
        super().__init__(detail)
        self.seq = seq
        self.kind = kind
        self.detail = detail


# --- parsing --------------------------------------------------------------------------------


def parse_lines(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = parse_json_strict(line, max_bytes=MAX_LINE_BYTES)
        except CanonicalizationError as exc:
            raise InputError(f"line {number}: {exc}") from exc
        if not isinstance(value, dict):
            raise InputError(f"line {number}: not a JSON object")
        out.append(value)
    return out


def _key_from_entry(entry: Mapping[str, Any]) -> PublicKey:
    material = entry.get("public_key", entry.get("x"))
    if not isinstance(material, str):
        raise InputError("a key-set entry has no public_key")
    try:
        raw = b64url_decode(material)
    except (ValueError, binascii.Error) as exc:
        raise InputError("a key-set public_key is not base64url") from exc
    if len(raw) != 32:
        raise InputError("an Ed25519 public key is 32 bytes")
    kid = entry.get("kid")
    state = entry.get("state", entry.get("status", "active"))
    return PublicKey(kid if isinstance(kid, str) else None, raw, str(state))


def _key_entries(doc: Any) -> list[Mapping[str, Any]]:
    if isinstance(doc, list):
        return [e for e in doc if isinstance(e, Mapping)]
    if isinstance(doc, Mapping):
        for name in ("data", "keys"):
            if isinstance(doc.get(name), list):
                return [e for e in doc[name] if isinstance(e, Mapping)]
        body = doc.get("body")
        if isinstance(body, Mapping) and isinstance(body.get("keys"), list):
            return [e for e in body["keys"] if isinstance(e, Mapping)]
        if "public_key" in doc or "x" in doc:
            return [doc]
    raise InputError("unrecognised public key set")


def load_public_keys(data: bytes) -> list[PublicKey]:
    """A PEM key, a raw/base64url 32-byte key, or a JSON key set (``/audit/signing-keys``
    ``{data: [...]}``, a JWKS-style ``{keys: [...]}``, a signed key set ``{body: {keys}}`` or a
    bare list)."""
    stripped = data.strip()
    if stripped.startswith(b"-----BEGIN"):
        key = load_pem_public_key(stripped)
        if not isinstance(key, Ed25519PublicKey):
            raise InputError("the public key must be Ed25519")
        return [PublicKey(None, key.public_bytes_raw())]
    if len(data) == 32:
        return [PublicKey(None, data)]
    if stripped[:1] in (b"{", b"["):
        try:
            doc = parse_json_strict(stripped)
        except CanonicalizationError as exc:
            raise InputError(f"key set: {exc}") from exc
        return [_key_from_entry(e) for e in _key_entries(doc)]
    try:
        raw = b64url_decode(stripped.decode("ascii"))
    except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
        raise InputError("unreadable public key") from exc
    if len(raw) != 32:
        raise InputError("an Ed25519 public key is 32 bytes")
    return [PublicKey(None, raw)]


def load_anchor_file(data: bytes) -> list[dict[str, Any]]:
    """One anchor object, a list of them, ``{data: [...]}`` (``GET /audit/anchors``) or JSONL."""
    text = data.decode("utf-8", errors="strict")
    try:
        doc = parse_json_strict(text)
    except CanonicalizationError:
        return [a for a in parse_lines(text) if a.get("type", "anchor") == "anchor"]
    if isinstance(doc, list):
        return [a for a in doc if isinstance(a, dict)]
    if isinstance(doc, dict) and isinstance(doc.get("data"), list):
        return [a for a in doc["data"] if isinstance(a, dict)]
    if isinstance(doc, dict):
        return [doc]
    raise InputError("unrecognised anchor file")


# --- hashing --------------------------------------------------------------------------------


def _jcs(value: Any) -> bytes:
    return canonicalize(value, allow_floats=False)


def _hex32(value: Any, what: str, seq: int | None) -> bytes:
    try:
        raw = bytes.fromhex(value) if isinstance(value, str) else b""
    except ValueError:
        raw = b""
    if len(raw) != 32:
        raise _Break(seq, CONTENT_MISMATCH, f"{what} is not a 32-byte hex digest")
    return raw


def row_digests(event: Mapping[str, Any]) -> tuple[bytes, bytes]:
    """→ (sha256(JCS(envelope)), sha256(JCS(detail))) recomputed from the row's content."""
    detail = event.get("detail")
    if not isinstance(detail, Mapping):
        raise CanonicalizationError("detail is not an object")
    return (
        envelope_sha256(envelope_strict(event), allow_floats=False),
        detail_sha256(detail, allow_floats=False),
    )


def _signature_ok(anchor: Mapping[str, Any], key: PublicKey) -> bool:
    try:
        signature = b64url_decode(str(anchor.get("signature", "")))
        Ed25519PublicKey.from_public_bytes(key.raw).verify(
            signature, _jcs(anchor_document_of_strict(anchor))
        )
    except (InvalidSignature, ValueError, binascii.Error, CanonicalizationError):
        return False
    return len(signature) == 64


# --- verification ---------------------------------------------------------------------------


def _check_rows(events: Sequence[Mapping[str, Any]], tenant: str | None) -> dict[int, bytes]:
    hashes: dict[int, bytes] = {}
    first = events[0].get("seq")
    if not isinstance(first, int) or isinstance(first, bool) or first < 0:
        raise _Break(None, CONTENT_MISMATCH, "the first row has no integer seq")
    running: bytes | None = GENESIS_HASH if first == 0 else None
    for offset, event in enumerate(events):
        expected = first + offset
        seq = event.get("seq")
        if seq != expected:
            raise _Break(expected, GAP, f"row {expected} is missing (found {seq!r})")
        if tenant is not None and event.get("tenant_id") != tenant:
            raise _Break(expected, CONTENT_MISMATCH, "row belongs to another tenant")
        prev = _hex32(event.get("prev_hash"), "prev_hash", expected)
        if running is not None and prev != running:
            raise _Break(expected, PREV_MISMATCH, "prev_hash is not the previous row's hash")
        try:
            env_sha, detail_sha = row_digests(event)
        except CanonicalizationError as exc:
            raise _Break(expected, CONTENT_MISMATCH, f"row is not canonical JSON: {exc}") from exc
        if env_sha != _hex32(event.get("envelope_sha256"), "envelope_sha256", expected) or (
            detail_sha != _hex32(event.get("detail_sha256"), "detail_sha256", expected)
        ):
            raise _Break(expected, CONTENT_MISMATCH, "envelope or detail differs from its digest")
        stored = _hex32(event.get("hash"), "hash", expected)
        if hashlib.sha256(prev + env_sha + detail_sha).digest() != stored:
            raise _Break(expected, HASH_MISMATCH, "row hash does not recompute")
        running = stored
        hashes[expected] = stored
    return hashes


def _check_anchors(
    anchors: Iterable[Mapping[str, Any]],
    keys: Sequence[PublicKey],
    hashes: Mapping[int, bytes],
    tenant: str | None,
    report: Report,
) -> int | None:
    """→ the highest verified anchor ``seq_to`` (None when no anchor covers the rows)."""
    by_kid = {k.kid: k for k in keys if k.kid is not None}
    highest: int | None = None
    for anchor in sorted(anchors, key=lambda a: int(a.get("seq_to", -1))):
        seq_to = anchor.get("seq_to")
        if not isinstance(seq_to, int) or isinstance(seq_to, bool):
            raise _Break(None, ANCHOR_SIGNATURE, "an anchor has no integer seq_to")
        if tenant is not None and anchor.get("tenant_id") != tenant:
            raise _Break(seq_to, ANCHOR_TENANT, "the anchor names another tenant")
        kid = anchor.get("signing_kid")
        candidates = [by_kid[kid]] if kid in by_kid else [k for k in keys if k.kid is None]
        if not candidates:
            raise InputError(f"no public key for signing kid {kid!r}")
        if not any(k.state != "compromised" and _signature_ok(anchor, k) for k in candidates):
            raise _Break(
                seq_to, ANCHOR_SIGNATURE, f"anchor {anchor.get('id')} is not validly signed"
            )
        if seq_to not in hashes:
            report.warnings.append(
                f"anchor {anchor.get('id')} at seq {seq_to} is outside the export"
            )
            continue
        try:
            head = bytes.fromhex(str(anchor.get("head_hash")))
        except ValueError:
            head = b""
        if head != hashes[seq_to]:
            raise _Break(seq_to, ANCHOR_MISMATCH, "the anchor's head_hash differs from the row")
        report.anchors_checked += 1
        highest = seq_to if highest is None else max(highest, seq_to)
    return highest


def verify_export(
    lines: Sequence[Mapping[str, Any]],
    keys: Sequence[PublicKey],
    *,
    anchors: Sequence[Mapping[str, Any]] | None = None,
    expected_to_seq: int | None = None,
    expected_head_hash: str | None = None,
) -> Report:
    if expected_to_seq is not None and (
        not isinstance(expected_to_seq, int)
        or isinstance(expected_to_seq, bool)
        or expected_to_seq < 0
    ):
        raise InputError("expected_to_seq must be a non-negative integer")
    if expected_head_hash is not None and (
        not isinstance(expected_head_hash, str)
        or len(expected_head_hash) != 64
        or any(c not in "0123456789abcdefABCDEF" for c in expected_head_hash)
    ):
        raise InputError("expected_head_hash must be a 64-digit hexadecimal SHA-256")
    header = next((ln for ln in lines if ln.get("type") == "header"), None)
    if header is not None and header.get("format") != EXPORT_FORMAT:
        raise InputError(f"unsupported export format {header.get('format')!r}")
    events = [ln for ln in lines if ln.get("type", "event") == "event"]
    if not events:
        raise InputError("the export holds no audit rows")
    tenant = (header or {}).get("tenant_id") or events[0].get("tenant_id")
    report = Report(ok=False, tenant_id=tenant)
    report.from_seq = events[0].get("seq") if isinstance(events[0].get("seq"), int) else None
    chosen = list(anchors) if anchors else [ln for ln in lines if ln.get("type") == "anchor"]
    try:
        # A valid earlier anchor must not make an incomplete export appear complete.
        # This checks consistency with the declared range, not completeness against
        # the server: independent latest-anchor pinning is still required.
        if header is not None:
            for field, observed in (
                ("from_seq", events[0].get("seq")),
                ("to_seq", events[-1].get("seq")),
            ):
                declared = header.get(field)
                if (
                    not isinstance(declared, int)
                    or isinstance(declared, bool)
                    or declared != observed
                ):
                    raise _Break(
                        (
                            observed
                            if isinstance(observed, int) and not isinstance(observed, bool)
                            else None
                        ),
                        GAP,
                        f"export header {field} does not match included events",
                    )
        hashes = _check_rows(events, tenant)
        report.rows = len(hashes)
        report.to_seq = max(hashes)
        # Unlike the export's own header, these expectations are supplied by the
        # auditor from a separately trusted source (e.g. pinned latest anchor).
        if expected_to_seq is not None and report.to_seq != expected_to_seq:
            raise _Break(
                expected_to_seq,
                GAP,
                "export does not reach the independently expected terminal sequence",
            )
        if expected_head_hash is not None and (
            hashes[report.to_seq].hex() != expected_head_hash.lower()
        ):
            raise _Break(
                report.to_seq,
                ANCHOR_MISMATCH,
                "export head differs from the independently expected terminal hash",
            )
        if not chosen:
            raise _Break(None, NO_ANCHOR, "no anchor was given or found in the export")
        highest = _check_anchors(chosen, keys, hashes, tenant, report)
        if highest is None:
            raise _Break(None, NO_ANCHOR, "no anchor covers the exported rows")
        report.anchored_to = highest
        if highest < report.to_seq:
            raise _Break(
                highest + 1, UNANCHORED_TAIL, "rows after the last anchor are not attested"
            )
    except _Break as brk:
        report.first_break_seq = brk.seq
        report.kind = brk.kind
        report.detail = brk.detail
        return report
    report.ok = True
    return report


def verify_files(
    export_path: Path,
    key_paths: Sequence[Path],
    anchor_paths: Sequence[Path] = (),
    *,
    expected_to_seq: int | None = None,
    expected_head_hash: str | None = None,
) -> Report:
    try:
        lines = parse_lines(export_path.read_text("utf-8"))
        keys = [k for p in key_paths for k in load_public_keys(p.read_bytes())]
        anchors = [a for p in anchor_paths for a in load_anchor_file(p.read_bytes())]
    except (OSError, UnicodeDecodeError) as exc:
        raise InputError(str(exc)) from exc
    if not keys:
        raise InputError("at least one --public-key is required")
    return verify_export(
        lines,
        keys,
        anchors=anchors or None,
        expected_to_seq=expected_to_seq,
        expected_head_hash=expected_head_hash,
    )


def render(report: Report) -> str:
    return json.dumps(report.as_dict(), sort_keys=True)
