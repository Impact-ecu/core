"""SPEC-005 R72, R76: the reproduction script against `core` on generated exports, and its JCS and Ed25519 against
the third-party `rfc8785` and `cryptography`. Any disagreement fails CI.

Exports are built by `core.provenance` from Hypothesis scenarios (synthetic bytes only); the core-side verdict
uses only the core's public API, and the script never sees the core.
"""

import copy
import json
from dataclasses import dataclass
from typing import Any

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given
from hypothesis import strategies as st

import reproduce
from core.kernel import (
    Dump,
    KernelError,
    LayoutMemory,
    Memory,
    MemoryLayout,
    Patch,
    Region,
    Version,
    apply,
    apply_checksum_patches,
    canonical_order,
    image_hash,
    layout_hash,
    version_hash,
)
from core.provenance import (
    ExportInputs,
    ProvenanceError,
    ReportContext,
    Versions,
    check_report_file,
    export_provenance,
    export_report,
    issue_report,
)
from tests.properties.strategies import calibration_slots, patch_in, scenarios
from tests.reproduce.bundles import BUNDLE_SCHEMA, sha
from tests.unit.provenance_scenario import DEFINITION_HASH, IMAGE_BUILD, LOCK_BUILD, input_report
from tests.unit.provenance_support import SERVER, TENANT, VERIFIER, _plain, add, import_payload, next_meta, start

type Bundle = dict[str, Any]


def _patch_json(patch: Patch) -> Bundle:
    return {
        "memory_id": patch.memory_id,
        "offset": patch.offset,
        "length": patch.length,
        "before": patch.before.hex(),
        "after": patch.after.hex(),
    }


@dataclass(frozen=True)
class Export:
    bundle: Bundle
    reproducibility: str


@st.composite
def exports(draw: st.DrawFn) -> Export:
    """A `no findings` export built by the core, with checksum patches in distinct checksum regions."""
    scenario = draw(scenarios(max_patches=5))
    slots = calibration_slots(scenario.layout, "checksum")
    chosen = draw(st.lists(st.sampled_from(slots), unique=True, max_size=3)) if slots else []
    checksum = tuple(draw(patch_in(memory_id, region, scenario.expected[memory_id])) for memory_id, region in chosen)
    build = draw(st.sampled_from((IMAGE_BUILD, LOCK_BUILD)))
    gate: dict[str, Any] = {
        "schema": "synthetic.gate-report.v0",
        "verdict": "no findings",
        "findings": [],
        "subject": {
            "definition_hash": DEFINITION_HASH,
            "layout_hash": layout_hash(scenario.layout),
            "references": [],
            "signed_regions": [],
        },
    }
    versions = Versions("0.1.0", (), "rules-1", ())
    inputs = ExportInputs(
        scenario.dump,
        scenario.version,
        scenario.layout,
        checksum,
        DEFINITION_HASH,
        versions,
        gate,
        input_report("no findings", "ok"),
        build,
    )
    chain = [start()]
    add(chain, "import", import_payload(image_hash(scenario.dump)))
    record = export_provenance(inputs, alert_ack=None, suspect_ack=None, chain=chain)
    context = ReportContext(TENANT, chain[0].hash, SERVER.public_key)
    report = export_report(context, inputs, record, map_ids={}, import_event=chain[1])
    issued = issue_report(report, head=chain[-1], meta=next_meta(chain[-1].seq + 1), signer=SERVER)
    bundle = {
        "schema": BUNDLE_SCHEMA,
        "report_file": json.loads(json.dumps(_plain(issued.to_json()))),
        "original": {
            "dump_kind": scenario.dump.dump_kind,
            "memories": [
                {"memory_id": m.memory_id, "base_address": m.base_address, "data": m.data.hex()}
                for m in scenario.dump.memories
            ],
        },
        "layout": {
            "memories": [
                {
                    "memory_id": m.memory_id,
                    "base_address": m.base_address,
                    "size": m.size,
                    "regions": [{"kind": r.kind, "start": r.start, "end": r.end, "name": r.name} for r in m.regions],
                }
                for m in scenario.layout.memories
            ]
        },
        "patches": [_patch_json(p) for p in scenario.version.patches],
        "overlaps": [list(pair) for pair in scenario.version.overlaps],
        "checksum_patches": [_patch_json(p) for p in checksum],
        "gate_report": gate,
    }
    return Export(bundle, "full" if build.kind == "image" else "best_effort")


def _core_patch(value: Bundle) -> Patch:
    before, after = bytes.fromhex(value["before"]), bytes.fromhex(value["after"])
    return Patch(value["memory_id"], value["offset"], value["length"], before, after)


def core_reproduces(bundle: Bundle) -> bool:
    """SPEC-005 R73 with the core's public API: R61, then SPEC-001 R62, R63, R25, R64, apply, R40, and the gate
    report hash (third-party JCS)."""
    try:
        checked = check_report_file(bundle["report_file"], VERIFIER)
        record = bundle["report_file"]["report"]["record"]
        original = bundle["original"]
        dump = Dump(
            original["dump_kind"],
            tuple(Memory(m["memory_id"], m["base_address"], bytes.fromhex(m["data"])) for m in original["memories"]),
        )
        layout = MemoryLayout(
            tuple(
                LayoutMemory(
                    m["memory_id"],
                    m["base_address"],
                    m["size"],
                    tuple(Region(r["kind"], r["start"], r["end"], r["name"]) for r in m["regions"]),
                )
                for m in bundle["layout"]["memories"]
            )
        )
        overlaps = tuple((a, b) for a, b in bundle["overlaps"])
        version = Version(
            image_hash(dump), layout_hash(layout), tuple(_core_patch(p) for p in bundle["patches"]), overlaps
        )
        checksum = sorted((_core_patch(p) for p in bundle["checksum_patches"]), key=lambda p: (p.memory_id, p.offset))
        applied = apply(dump, version, layout)
        released = apply_checksum_patches(applied, checksum, layout)
    except (KernelError, ProvenanceError):
        return False
    return checked.report.kind == "export" and [
        record["image_hash_original"],
        record["layout_hash"],
        record["patch_hashes"],
        record["overlaps"],
        record["version_hash"],
        record["image_hash_apply"],
        record["checksum_patch_hashes"],
        record["image_hash_release"],
        record["gate_report_hash"],
    ] == [
        image_hash(dump),
        layout_hash(layout),
        [p.patch_hash for p in canonical_order(version)],
        sorted([a, b] for a, b in overlaps),
        version_hash(version),
        applied.image_hash,
        [p.patch_hash for p in checksum],
        released.image_hash,
        sha(bundle["gate_report"]),
    ]


def _flip(hex_text: str, index: int) -> str:
    data = bytearray.fromhex(hex_text)
    data[index % len(data)] ^= 0x01
    return data.hex()


MUTATIONS = (
    "none",
    "original_byte",
    "patch_after",
    "drop_patch",
    "drop_checksum",
    "reverse_overlap",
    "region_name",
    "gate_report",
    "signature",
    "record",
)


def mutate(bundle: Bundle, kind: str, index: int) -> None:
    """One change a tampered or careless bundle could carry; some are no-ops on some bundles."""
    patches, checksum, overlaps = bundle["patches"], bundle["checksum_patches"], bundle["overlaps"]
    if kind == "original_byte":
        memory = bundle["original"]["memories"][index % len(bundle["original"]["memories"])]
        memory["data"] = _flip(memory["data"], index)
    elif kind == "patch_after" and patches:
        target = patches[index % len(patches)]
        target["after"] = _flip(target["after"], index)
    elif kind == "drop_patch" and patches:
        del patches[index % len(patches)]
    elif kind == "drop_checksum" and checksum:
        del checksum[index % len(checksum)]
    elif kind == "reverse_overlap" and overlaps:
        overlaps[index % len(overlaps)].reverse()
    elif kind == "region_name":
        memory = bundle["layout"]["memories"][index % len(bundle["layout"]["memories"])]
        memory["regions"][0]["name"] += "x"
    elif kind == "gate_report":
        bundle["gate_report"]["verdict"] = "warn"
    elif kind == "signature":
        payload = bundle["report_file"]["event"]["payload"]
        payload["signature"] = _flip(payload["signature"], index)
    elif kind == "record":
        bundle["report_file"]["report"]["record"]["reproducibility"] = "best_effort"


# SPEC-005 R73, R74, R76: on every generated export, intact or changed, the script and the core agree.
@given(exports(), st.sampled_from(MUTATIONS), st.integers(0, 2**16))
def test_script_agrees_with_core(export: Export, kind: str, index: int) -> None:
    bundle = copy.deepcopy(export.bundle)
    mutate(bundle, kind, index)
    expected = core_reproduces(bundle)
    result = reproduce.reproduce(rfc8785.dumps(bundle))
    assert result["status"] == ("reproduced" if expected else "not_reproduced"), result["mismatches"]
    if kind == "none":
        assert expected
        assert result["reproducibility"] == export.reproducibility


JSON_SCALARS = st.none() | st.booleans() | st.integers(-(2**53) + 1, 2**53 - 1) | st.text(st.characters(codec="utf-8"))
JSON_VALUES = st.recursive(
    JSON_SCALARS,
    lambda inner: (
        st.lists(inner, max_size=4) | st.dictionaries(st.text(st.characters(max_codepoint=127)), inner, max_size=4)
    ),
    max_leaves=12,
)


# SPEC-005 R72: the stdlib canonical JSON equals RFC 8785 on every object R1 and R4 allow.
@given(JSON_VALUES)
def test_canonical_json_is_rfc8785(value: bool | int | str | list[Any] | dict[str, Any] | None) -> None:
    assert reproduce.canonical(value) == rfc8785.dumps(value)


# SPEC-005 R72: the script's RFC 8032 verification agrees with `cryptography` on valid and altered signatures.
@given(st.binary(min_size=32, max_size=32), st.binary(max_size=64), st.integers(0, 64 * 8 - 1))
def test_ed25519_agrees_with_cryptography(seed: bytes, message: bytes, bit: int) -> None:
    key = Ed25519PrivateKey.from_private_bytes(seed)
    public = key.public_key().public_bytes_raw()
    signature = key.sign(message)
    assert reproduce.ed25519_verify(public, message, signature)
    altered = bytearray(signature)
    altered[bit // 8] ^= 1 << (bit % 8)
    assert not reproduce.ed25519_verify(public, message, bytes(altered))
    with pytest.raises(InvalidSignature):
        key.public_key().verify(bytes(altered), message)
