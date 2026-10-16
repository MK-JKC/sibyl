"""``sibyl audit verify``: offline chain + anchor verification (R33), pure SDK.

The chains here are built independently of the verifier (hashlib + the shared JCS); the
end-to-end check against a real database export lives in the control-plane suite
(``services/control/tests/api/governance/test_e2e_governance.py``).
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sibyl.cli import EXIT_BREAK, EXIT_INPUT, EXIT_OK, main
from sibyl.cli.audit import InputError, load_public_keys, parse_lines, verify_export
from sibyl_schemas.canonical import canonicalize

TENANT = "01927000-0000-7000-8000-00000000000a"
OTHER = "01927000-0000-7000-8000-00000000000b"
KID = "anchor-k1"


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jcs(value: Any) -> bytes:
    return canonicalize(value, allow_floats=False)


def _envelope(row: dict[str, Any]) -> dict[str, Any]:
    names = (
        "action actor_id actor_key_id actor_session_id actor_type chain_version occurred_at reason"
        " recorded_at request_id resource_id resource_ref resource_type seq tenant_id"
    ).split()
    return {n: row[n] for n in names}


def rehash(rows: list[dict[str, Any]], start: int = 0) -> None:
    """Recompute digests and hashes from ``start`` on (what a forger with DB write would do)."""
    prev = bytes.fromhex(rows[start]["prev_hash"])
    for row in rows[start:]:
        row["prev_hash"] = prev.hex()
        env = hashlib.sha256(jcs(_envelope(row))).digest()
        det = hashlib.sha256(jcs(row["detail"])).digest()
        row["envelope_sha256"] = env.hex()
        row["detail_sha256"] = det.hex()
        prev = hashlib.sha256(prev + env + det).digest()
        row["hash"] = prev.hex()


def chain(n: int, *, start: int = 0, tenant: str = TENANT) -> list[dict[str, Any]]:
    rows = []
    for seq in range(start, start + n):
        rows.append(
            {
                "type": "event",
                "seq": seq,
                "tenant_id": tenant,
                "action": "audit.genesis" if seq == 0 else "config.changed",
                "actor_type": "system" if seq == 0 else "human",
                "actor_id": None if seq == 0 else "01927000-0000-7000-8000-0000000000c1",
                "actor_key_id": None,
                "actor_session_id": None,
                "resource_type": "tenant",
                "resource_id": tenant,
                "resource_ref": None,
                "reason": None if seq == 0 else f"change {seq} — ünïcode ✓",
                "occurred_at": None,
                "recorded_at": f"2026-10-11T10:00:{seq % 60:02d}.000123Z",
                "request_id": None,
                "chain_version": 1,
                "severity": "info",
                "is_evidence": True,
                "detail": {"field": f"f{seq}", "after": seq, "nested": {"b": [1, "x"], "a": None}},
                "prev_hash": "00" * 32,
            }
        )
    if start > 0:
        rows[0]["prev_hash"] = hashlib.sha256(b"earlier rows").hexdigest()
    rehash(rows)
    return rows


def anchor(
    rows: list[dict[str, Any]],
    key: Ed25519PrivateKey,
    *,
    seq_to: int | None = None,
    tenant: str = TENANT,
    kid: str = KID,
) -> dict[str, Any]:
    target = rows[-1]["seq"] if seq_to is None else seq_to
    head = next(r for r in rows if r["seq"] == target)["hash"]
    doc = {
        "format": "sibyl.audit_anchor/1",
        "id": "01927000-0000-7000-8000-0000000000e1",
        "tenant_id": tenant,
        "kind": "export",
        "seq_from": rows[0]["seq"],
        "seq_to": target,
        "head_hash": head,
        "prev_anchor_id": None,
        "signing_kid": kid,
        "anchored_at": "2026-10-11T11:00:00.000001Z",
    }
    signature = key.sign(jcs(doc))
    return {
        "type": "anchor",
        **{k: v for k, v in doc.items() if k != "format"},
        "signature": b64(signature),
    }


def raw_pub(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def key_set(key: Ed25519PrivateKey, state: str = "active", kid: str = KID) -> list[Any]:
    return load_public_keys(
        json.dumps(
            {"data": [{"kid": kid, "public_key": b64(raw_pub(key)), "state": state}]}
        ).encode()
    )


def export(rows: list[dict[str, Any]], anchors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    header = {
        "type": "header",
        "format": "sibyl.audit_export/1",
        "tenant_id": rows[0]["tenant_id"],
        "from_seq": rows[0]["seq"],
        "to_seq": rows[-1]["seq"],
    }
    return [header, *rows, *anchors]


@pytest.fixture
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def test_intact_export_verifies(key: Ed25519PrivateKey) -> None:
    rows = chain(6)
    report = verify_export(export(rows, [anchor(rows, key)]), key_set(key))
    assert report.ok, report.as_dict()
    assert (report.rows, report.from_seq, report.to_seq, report.anchors_checked) == (6, 0, 5, 1)


def test_export_that_starts_mid_chain_verifies(key: Ed25519PrivateKey) -> None:
    rows = chain(4, start=40)
    report = verify_export(export(rows, [anchor(rows, key)]), key_set(key))
    assert report.ok, report.as_dict()


@pytest.mark.parametrize("field", ["detail", "reason", "action", "recorded_at", "actor_id"])
def test_tampering_one_row_reports_that_seq(key: Ed25519PrivateKey, field: str) -> None:
    rows = chain(6)
    signed = anchor(rows, key)
    forged = copy.deepcopy(rows)
    forged[3][field] = {"field": "rewritten"} if field == "detail" else "rewritten-value"
    report = verify_export(export(forged, [signed]), key_set(key))
    assert not report.ok
    assert (report.first_break_seq, report.kind) == (3, "content_mismatch")


def test_rehashed_forgery_is_caught_by_the_anchor(key: Ed25519PrivateKey) -> None:
    rows = chain(6)
    signed = anchor(rows, key)
    forged = copy.deepcopy(rows)
    forged[2]["detail"] = {"field": "rewritten"}
    rehash(forged, 2)
    report = verify_export(export(forged, [signed]), key_set(key))
    assert (report.ok, report.first_break_seq, report.kind) == (False, 5, "anchor_mismatch")


def test_missing_row_is_a_gap(key: Ed25519PrivateKey) -> None:
    rows = chain(6)
    signed = anchor(rows, key)
    report = verify_export(export(rows[:2] + rows[3:], [signed]), key_set(key))
    assert (report.first_break_seq, report.kind) == (2, "gap")


def test_broken_link_is_prev_mismatch(key: Ed25519PrivateKey) -> None:
    rows = chain(6)
    signed = anchor(rows, key)
    rows[4]["prev_hash"] = "11" * 32
    report = verify_export(export(rows, [signed]), key_set(key))
    assert (report.first_break_seq, report.kind) == (4, "prev_mismatch")


def test_stored_hash_tamper_is_hash_mismatch(key: Ed25519PrivateKey) -> None:
    rows = chain(3)
    signed = anchor(rows, key)
    rows[1]["hash"] = "22" * 32
    report = verify_export(export(rows, [signed]), key_set(key))
    assert (report.first_break_seq, report.kind) == (1, "hash_mismatch")


def test_genesis_must_start_from_zero_hash(key: Ed25519PrivateKey) -> None:
    rows = chain(3)
    rows[0]["prev_hash"] = "33" * 32
    rehash(rows)
    report = verify_export(export(rows, [anchor(rows, key)]), key_set(key))
    assert (report.first_break_seq, report.kind) == (0, "prev_mismatch")


def test_anchor_signed_by_another_key_fails(key: Ed25519PrivateKey) -> None:
    rows = chain(4)
    signed = anchor(rows, Ed25519PrivateKey.generate())
    report = verify_export(export(rows, [signed]), key_set(key))
    assert (report.ok, report.kind, report.first_break_seq) == (False, "anchor_signature", 3)


def test_anchor_fields_are_bound_by_the_signature(key: Ed25519PrivateKey) -> None:
    rows = chain(4)
    signed = anchor(rows, key)
    signed["kind"] = "hourly"
    report = verify_export(export(rows, [signed]), key_set(key))
    assert report.kind == "anchor_signature"


def test_compromised_key_never_verifies(key: Ed25519PrivateKey) -> None:
    rows = chain(4)
    report = verify_export(export(rows, [anchor(rows, key)]), key_set(key, state="compromised"))
    assert report.kind == "anchor_signature"


def test_anchor_of_another_tenant_is_refused(key: Ed25519PrivateKey) -> None:
    rows = chain(4)
    report = verify_export(export(rows, [anchor(rows, key, tenant=OTHER)]), key_set(key))
    assert report.kind == "anchor_tenant"


def test_rows_after_the_last_anchor_are_not_attested(key: Ed25519PrivateKey) -> None:
    rows = chain(6)
    report = verify_export(export(rows, [anchor(rows, key, seq_to=3)]), key_set(key))
    assert (report.ok, report.first_break_seq, report.kind) == (False, 4, "unanchored_tail")
    assert report.anchored_to == 3


def test_export_without_anchor_fails(key: Ed25519PrivateKey) -> None:
    rows = chain(3)
    report = verify_export(export(rows, []), key_set(key))
    assert report.kind == "no_anchor"


def test_unknown_kid_is_an_input_error(key: Ed25519PrivateKey) -> None:
    rows = chain(3)
    with pytest.raises(InputError):
        verify_export(export(rows, [anchor(rows, key, kid="other")]), key_set(key))


def test_key_formats(key: Ed25519PrivateKey) -> None:
    raw = raw_pub(key)
    pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    signed_set = {
        "kid": KID,
        "alg": "Ed25519",
        "sig": "x",
        "body": {"keys": [{"kid": KID, "public_key": b64(raw)}]},
    }
    for data in (pem, raw, b64(raw).encode(), json.dumps(signed_set).encode()):
        assert load_public_keys(data)[0].raw == raw
    with pytest.raises(InputError):
        load_public_keys(b"not a key")


def test_duplicate_member_names_are_refused() -> None:
    with pytest.raises(InputError):
        parse_lines('{"type": "event", "seq": 1, "seq": 2}\n')


def _write(
    tmp: Path, rows: list[dict[str, Any]], anchors: list[dict[str, Any]], key: Ed25519PrivateKey
) -> tuple[Path, Path]:
    export_path = tmp / "export.jsonl"
    export_path.write_text("".join(json.dumps(line) + "\n" for line in export(rows, anchors)))
    key_path = tmp / "keys.json"
    key_path.write_text(json.dumps({"data": [{"kid": KID, "public_key": b64(raw_pub(key))}]}))
    return export_path, key_path


def test_cli_exit_codes(
    tmp_path: Path, key: Ed25519PrivateKey, capsys: pytest.CaptureFixture[str]
) -> None:
    rows = chain(5)
    signed = anchor(rows, key)
    export_path, key_path = _write(tmp_path, rows, [signed], key)
    assert main(["audit", "verify", str(export_path), "--public-key", str(key_path)]) == EXIT_OK
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True and out["anchors_checked"] == 1

    rows[2]["detail"] = {"field": "tampered"}
    export_path, key_path = _write(tmp_path, rows, [], key)
    anchor_path = tmp_path / "anchor.json"
    anchor_path.write_text(json.dumps(signed))
    code = main(
        [
            "audit",
            "verify",
            str(export_path),
            "--anchor",
            str(anchor_path),
            "--public-key",
            str(key_path),
        ]
    )
    assert code == EXIT_BREAK
    out = json.loads(capsys.readouterr().out)
    assert (out["first_break_seq"], out["kind"]) == (2, "content_mismatch")

    export_path.write_text("{not json}\n")
    assert main(["audit", "verify", str(export_path), "--public-key", str(key_path)]) == EXIT_INPUT
    assert (
        main(["audit", "verify", str(tmp_path / "missing"), "--public-key", str(key_path)])
        == EXIT_INPUT
    )


def test_header_must_match_first_and_last_event(key: Ed25519PrivateKey) -> None:
    """A claimed export range must correspond to the included audit rows."""
    rows = chain(6)
    signed = anchor(rows, key)
    for field, value in (
        ("from_seq", 1),
        ("to_seq", 4),
        ("from_seq", True),
        ("to_seq", "5"),
        ("from_seq", None),
        ("to_seq", None),
    ):
        document = export(rows, [signed])
        document[0][field] = value
        report = verify_export(document, key_set(key))
        assert (report.ok, report.kind) == (False, "gap"), (field, value, report.as_dict())


def test_valid_older_anchor_cannot_mask_truncated_export(
    key: Ed25519PrivateKey,
) -> None:
    """An earlier valid signature does not cover the header's omitted later rows."""
    rows = chain(6)
    older_anchor = anchor(rows, key, seq_to=2)
    document = export(rows, [older_anchor])
    truncated = [document[0], *rows[:3], older_anchor]
    report = verify_export(truncated, key_set(key))
    assert not report.ok
    assert report.kind == "gap"


def test_independent_expected_terminal_sequence_detects_consistent_truncation(
    key: Ed25519PrivateKey,
) -> None:
    rows = chain(6)
    earlier = anchor(rows, key, seq_to=2)
    truncated = export(rows[:3], [earlier])
    # The truncated export has an internally consistent header and valid anchor.
    assert verify_export(truncated, key_set(key)).ok
    report = verify_export(truncated, key_set(key), expected_to_seq=5)
    assert (report.ok, report.kind) == (False, "gap")


def test_independent_pinned_head_hash_detects_rewritten_export(
    key: Ed25519PrivateKey,
) -> None:
    rows = chain(5)
    signed = anchor(rows, key)
    assert verify_export(
        export(rows, [signed]),
        key_set(key),
        expected_to_seq=4,
        expected_head_hash=rows[-1]["hash"],
    ).ok
    report = verify_export(
        export(rows, [signed]),
        key_set(key),
        expected_head_hash="ee" * 32,
    )
    assert (report.ok, report.kind) == (False, "anchor_mismatch")


def test_cli_accepts_independent_terminal_pin(
    tmp_path: Path,
    key: Ed25519PrivateKey,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rows = chain(5)
    export_path, key_path = _write(tmp_path, rows, [anchor(rows, key)], key)
    args = [
        "audit",
        "verify",
        str(export_path),
        "--public-key",
        str(key_path),
        "--expected-to-seq",
        "4",
        "--expected-head-hash",
        rows[-1]["hash"],
    ]
    assert main(args) == EXIT_OK
    capsys.readouterr()

    wrong_seq_args = [
        "audit",
        "verify",
        str(export_path),
        "--public-key",
        str(key_path),
        "--expected-to-seq",
        "7",
    ]
    assert main(wrong_seq_args) == EXIT_BREAK
    capsys.readouterr()

    bad_hash_args = [
        "audit",
        "verify",
        str(export_path),
        "--public-key",
        str(key_path),
        "--expected-head-hash",
        "not-a-hash",
    ]
    assert main(bad_hash_args) == EXIT_INPUT
