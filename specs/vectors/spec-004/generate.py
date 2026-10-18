"""Generate SPEC-004 test vectors.

Independent of the core: JCS comes from the third-party `rfc8785` package (pinned in requirements.txt),
SHA-256 from hashlib. Every expected finding, tested entry and not-tested entry below is written by hand per
case; this script never evaluates a rule. It only assembles the hand-written expectations into reports and
hashes them. Physical values are exact rationals in the canonical string form of SPEC-004 R30.
Run: python -I generate.py > vectors.json   then   python -I crosscheck.py vectors.json
"""
from __future__ import annotations

import copy
import hashlib
import importlib.metadata
import json
import sys
from fractions import Fraction

import rfc8785

DISCLAIMER = (
    "This gate verifies file integrity and cell-by-cell plausibility. "
    "It does not verify the combination between maps, firmware behavior, or the real engine."
)
UNREVIEWED_TEXT = "you edited a map whose meaning has not been confirmed"
UNMAPPED_TEXT = "you edited bytes that belong to no known map"
CORE_VERSION = "0.0.0"


def h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def jcs_hash(obj: object) -> str:
    return h(rfc8785.dumps(obj))


def sh(label: str) -> str:
    """Synthetic 64-hex value standing in for a hash of an object this spec does not build."""
    return h(("spec-004 synthetic " + label).encode("utf-8"))


def q(value: int | str) -> str:
    """Canonical rational string; asserts the hand-written literal is already canonical."""
    text = str(value)
    f = Fraction(text)
    canon = str(f.numerator) if f.denominator == 1 else f"{f.numerator}/{f.denominator}"
    assert canon == text, (text, canon)
    return text


def grid(rows: list[list[int | str]]) -> list[list[str]]:
    return [[q(v) for v in row] for row in rows]


def axis(unit: str, values: list[int | str]) -> dict[str, object]:
    return {"unit": unit, "values": [v if v == "non_finite" else q(v) for v in values]}


def key(category: str, map_type: str, combustion: str, fuel: str | None, unit: str) -> dict[str, object]:
    return {"category": category, "combustion": combustion, "fuel": fuel, "map_type": map_type, "unit": unit}


def rule(rule_id: str, kind: str, severity: str, k: dict[str, object], params: dict[str, str], text: str) -> dict[str, object]:
    return {"key": k, "kind": kind, "params": params, "rule_id": rule_id, "rule_version": 1, "severity": severity, "text": text}


SI_GAS = ("SI", "gasoline")
IGN_KEY = key("ignition", "base", "SI", "gasoline", "deg_crank")
SYN_KEY = key("test_synthetic", "base", "SI", "gasoline", "test_unit")

# Rules from SPEC-000 §Verification gate (line 194), the only ranges SPEC-000 gives.
SPEC000_RULES = [
    rule("ign.si.gasoline.base.range", "range", "warn", IGN_KEY, {"max": q(45), "min": q(-10)},
         "ignition advance outside -10 to 45 deg"),
    rule("ign.si.gasoline.base.boost_cap", "conditional_cap", "warn", IGN_KEY,
         {"above": q(50), "axis_unit": "kPa_rel", "max": q(30)},
         "ignition advance above 30 deg in a cell above 50 kPa relative boost"),
    rule("lambda.si.gasoline.base.range", "range", "warn", key("lambda", "base", "SI", "gasoline", "lambda"),
         {"max": q("23/20"), "min": q("3/4")}, "lambda outside 0.75 to 1.15"),
    rule("lambda.ci.diesel.base.range", "range", "warn", key("lambda", "base", "CI", "diesel", "lambda"),
         {"min": q("23/20")}, "lambda below 1.15"),
]
# Synthetic rules: category `test_synthetic` exists only in vectors, to exercise rule kinds SPEC-000 gives no values for.
SYNTHETIC_RULES = [
    rule("test.smooth", "smoothness", "warn", SYN_KEY, {"max_step": q(10)}, "synthetic smoothness step exceeded"),
    rule("test.sensor", "sensor_range", "block", SYN_KEY, {"max": q(250), "min": q(0)}, "synthetic sensor range exceeded"),
    rule("test.amplitude", "relative_amplitude", "warn", key("test_synthetic", "correction", "SI", "gasoline", "test_ratio"),
         {"max_deviation": q("1/4"), "neutral": q(1)}, "synthetic correction amplitude exceeded"),
]


def table(table_id: str, version: str, rules: list[dict[str, object]]) -> dict[str, object]:
    return {
        "identify_min_confidence": 800,  # synthetic value in thousandths: SPEC-000 sets no threshold (SPEC-004 open question 2)
        "rules": sorted(rules, key=lambda r: str(r["rule_id"])),
        "table_id": table_id,
        "version": version,
    }


T1 = table("spec-004-vectors", "1.0.0", SPEC000_RULES + SYNTHETIC_RULES)
_t2_rules = copy.deepcopy(SPEC000_RULES + SYNTHETIC_RULES)
for r in _t2_rules:
    if r["rule_id"] == "ign.si.gasoline.base.range":
        r["severity"] = "info"
T2 = table("spec-004-vectors", "2.0.0", _t2_rules)
T3 = table(
    "spec-004-vectors-nofuel",
    "1.0.0",
    SPEC000_RULES + [rule("test.nofuel", "range", "warn", key("test_synthetic", "base", "SI", None, "test_unit"),
                          {"max": q(1), "min": q(0)}, "synthetic rule without fuel")],
)
TABLES = {"T1": T1, "T2": T2, "T3": T3}


def table_ref(name: str | None) -> dict[str, object] | None:
    if name is None:
        return None
    t = TABLES[name]
    return {"hash": jcs_hash(t), "table_id": t["table_id"], "version": t["version"]}


def mapv(map_id: str, category: str, map_type: str, unit: str, values: list[list[int | str]],
         x: dict[str, object] | None, y: dict[str, object] | None, label_state: str = "reviewed",
         edited: bool = True, bind_error: bool = False) -> dict[str, object]:
    return {"bind_error": bind_error, "category": category, "edited": edited, "label_state": label_state, "map_id": map_id,
            "map_type": map_type, "unit": unit, "values": grid(values), "x_axis": x, "y_axis": y}


def finding(rule_id: str, severity: str, text: str, map_id: str | None = None, cells: list[list[int]] | None = None,
            axis_name: str | None = None, breakpoints: list[int] | None = None, incident: str | None = None,
            runs: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {"axis": axis_name, "breakpoints": breakpoints or [], "cells": cells or [], "incident": incident,
            "map_id": map_id, "rule_id": rule_id, "rule_version": 1, "runs": runs or [], "severity": severity, "text": text}


def t(kind: str, map_id: str | None = None, rule_id: str | None = None) -> dict[str, object]:
    return {"kind": kind, "map_id": map_id, "rule_id": rule_id}


def nt(kind: str, reason: str, map_id: str | None = None, rule_id: str | None = None) -> dict[str, object]:
    return {"kind": kind, "map_id": map_id, "reason": reason, "rule_id": rule_id}


def out_subject(combustion: str | None, fuel: str | None,
                input_verify: str = "ok", signed_regions: list[dict[str, str]] | None = None) -> dict[str, object]:
    """The value each step would produce (SPEC-004 R45 sources); R45 nulls the fields of steps that did not run."""
    return {
        "checksum_variant_id": "synthetic_variant_1",
        "conformance_report_hash": sh("conformance report"),
        "definition_hash": sh("definition"),
        "engine": {"combustion": combustion, "fuel": fuel},
        "input_report_hash": sh("input report"),
        "input_verify": input_verify,
        "layout_hash": sh("layout"),
        "original_image_hash": sh("original"),
        "plugin": {"family": "synthetic.family", "version": "0.0.0"},
        "references": [],
        "release_candidate_hash": sh("release candidate"),
        "signed_regions": signed_regions or [],
        "unverified_image_hash": sh("unverified image"),
        "version_hash": sh("version"),
    }


# Integrity outcomes of steps 2-7 (SPEC-004 R20) are inputs: they need images, which these vectors do not build.
INTEGRITY_OK = {"binding": "ok", "checksum_resolution": "ok", "dual": "agree", "input_state": "ok", "plugin_available": True,
                "verify_status": "ok"}
ADMITTED = ["synthetic_variant_1"]  # stands for the conformance report's admitted set (SPEC-004 R15)
SIGNED_TEXT = "signed region: its signature cannot be verified, and an edit may invalidate it"
INPUT_SIGNED_TEXT = "signed region: its signature cannot be verified"
BINDING_TEXT = "image, version, layout, plugin or input check do not match"
PROTECTED_TEXT = "a patch touches a region that is not calibration"
SIGNED_REGION = {"memory_id": "pflash", "name": "sig_block"}  # a ChecksumRegion of kind signed (SPEC-004 §6)


def integ(**kw: object) -> dict[str, object]:
    return dict(INTEGRITY_OK, **kw)


TESTED_INTEGRITY = [t("binding"), t("checksum_step"), t("dual_checksum"), t("input_state"), t("kernel_invariants"), t("verify")]
AFTER_AVAILABILITY = ("binding", "checksum_step", "dual_checksum", "input_state", "kernel_invariants", "map_rules", "verify")
UNAVAILABLE_NT = [nt(k, "gate_unavailable") for k in AFTER_AVAILABILITY]
EARLIER_BLOCK_NT = [nt(k, "earlier_block") for k in AFTER_AVAILABILITY if k != "binding"]

RPM3 = axis("rpm", [1000, 2000, 3000])
BOOST_0_40_60 = axis("kPa_rel", [0, 40, 60])
IGN_OK = [[10, 20, 30], [15, 25, 35], [20, 28, 30]]


def ign_main(values: list[list[int | str]], x: dict[str, object] = RPM3, y: dict[str, object] = BOOST_0_40_60,
             edited: bool = True) -> dict[str, object]:
    return mapv("ign_main", "ignition", "base", "deg_crank", values, x, y, edited=edited)


IGN_MAIN_TESTED = [
    t("axis_monotonic", "ign_main", "G-AXIS-MONOTONIC"),
    t("physical_range", "ign_main", "ign.si.gasoline.base.boost_cap"),
    t("physical_range", "ign_main", "ign.si.gasoline.base.range"),
]
IGN_MAIN_NT = [nt("smoothness", "no_rule", "ign_main")]
RANGE_FINDING = finding("ign.si.gasoline.base.range", "warn", "ignition advance outside -10 to 45 deg", "ign_main",
                        [[0, 2], [1, 0]])
IGN_RANGE_VALUES = [[10, 20, 46], [-11, 25, 35], [20, 28, 30]]

def sort_findings(items: list[dict[str, object]]) -> list[dict[str, object]]:
    """SPEC-004 R42 order. Sorting is assembly, not evaluation: the entries themselves are hand-written."""
    return sorted(items, key=lambda f: (f["rule_id"], f["map_id"] or "", f["axis"] or ""))


def sort_tested(items: list[dict[str, object]]) -> list[dict[str, object]]:
    return sorted(items, key=lambda e: (e["kind"], e["map_id"] or "", e["rule_id"] or ""))


def sort_not_tested(items: list[dict[str, object]]) -> list[dict[str, object]]:
    return sorted(items, key=lambda e: (e["kind"], e["map_id"] or "", e["rule_id"] or "", e["reason"]))


# Each case: inputs, then the hand-written expected findings, information, silenced, tested and not_tested lists.
CASES: list[dict[str, object]] = []


def case(name: str, rules: list[str], *, maps: list[dict[str, object]], findings: list[dict[str, object]],
         tested: list[dict[str, object]], not_tested: list[dict[str, object]], verdict: str,
         table_name: str | None = "T1", context: tuple[str | None, str | None] = SI_GAS,
         integrity: dict[str, object] | None = None, silences: list[dict[str, object]] | None = None,
         silenced: list[dict[str, object]] | None = None, information: list[dict[str, object]] | None = None,
         unmapped_runs: list[dict[str, object]] | None = None, nulls: tuple[str, ...] = (),
         input_verify: str = "ok", admitted: list[str] = ADMITTED,
         signed_regions: list[dict[str, str]] | None = None) -> None:
    combustion, fuel = context
    inputs = {
        "admitted_variants": admitted,
        "context": {"combustion": combustion, "fuel": fuel},
        "integrity": integrity or INTEGRITY_OK,
        "maps": maps,
        "rule_table": table_name,
        "silences": silences or [],
        "sources": out_subject(combustion, fuel, input_verify, signed_regions),
        "unmapped_runs": unmapped_runs or [],
    }
    findings = sort_findings(findings)
    report = {
        "disclaimer": DISCLAIMER,
        "findings": findings,
        "gate": {"core_version": CORE_VERSION, "rule_table": table_ref(table_name), "spec": "SPEC-004"},
        "information": sort_findings(information or []),
        "not_tested": sort_not_tested(not_tested),
        "silenced": sort_findings(silenced or []),
        "stage": "output",
        "subject": {k: (None if k in nulls else v) for k, v in inputs["sources"].items()},  # hand-written nulls (R45)
        "tested": sort_tested(tested),
        "verdict": verdict,
    }
    CASES.append({"name": name, "rules": rules, "input": inputs, "expected": {
        "report": report, "report_hash": jcs_hash(report), "verdict": verdict,
        "finding_ids": [jcs_hash(f) for f in findings],  # R43, in report order
    }})


case("C01_ignition_in_range", ["R4", "R8", "R31", "R32", "R34", "R37", "R40", "R41", "R42", "R43", "R70"],
     maps=[ign_main(IGN_OK)], findings=[], tested=TESTED_INTEGRITY + IGN_MAIN_TESTED, not_tested=IGN_MAIN_NT,
     verdict="no findings")
case("C02_ignition_range_warn", ["R4", "R6", "R37", "R70"],
     maps=[ign_main(IGN_RANGE_VALUES)], findings=[RANGE_FINDING], tested=TESTED_INTEGRITY + IGN_MAIN_TESTED,
     not_tested=IGN_MAIN_NT, verdict="warn")
case("C03_ignition_boost_cap_boundaries", ["R37", "R70"],
     maps=[ign_main([[10, 20, 30], [15, 25, 45], [30, 31, 29]], y=axis("kPa_rel", [0, 50, 60]))],
     findings=[finding("ign.si.gasoline.base.boost_cap", "warn",
                       "ignition advance above 30 deg in a cell above 50 kPa relative boost", "ign_main", [[2, 1]])],
     tested=TESTED_INTEGRITY + IGN_MAIN_TESTED, not_tested=IGN_MAIN_NT, verdict="warn")
case("C04_lambda_si_gasoline", ["R37", "R38", "R70"],
     maps=[mapv("lam_base", "lambda", "base", "lambda", [["3/4", "23/20"], ["37/50", "117/100"]],
                axis("rpm", [1000, 2000]), axis("percent", [20, 80]))],
     findings=[finding("lambda.si.gasoline.base.range", "warn", "lambda outside 0.75 to 1.15", "lam_base", [[1, 0], [1, 1]])],
     tested=TESTED_INTEGRITY + [t("axis_monotonic", "lam_base", "G-AXIS-MONOTONIC"),
                                t("physical_range", "lam_base", "lambda.si.gasoline.base.range")],
     not_tested=[nt("smoothness", "no_rule", "lam_base")], verdict="warn")
case("C05_lambda_ci_diesel", ["R34", "R37", "R38", "R70"], context=("CI", "diesel"),
     maps=[mapv("lam_ci", "lambda", "base", "lambda", [["23/20", "6/5", "1"]], RPM3, None)],
     findings=[finding("lambda.ci.diesel.base.range", "warn", "lambda below 1.15", "lam_ci", [[0, 2]])],
     tested=TESTED_INTEGRITY + [t("axis_monotonic", "lam_ci", "G-AXIS-MONOTONIC"),
                                t("physical_range", "lam_ci", "lambda.ci.diesel.base.range")],
     not_tested=[nt("smoothness", "shape", "lam_ci")], verdict="warn")
case("C06_axis_not_monotonic_blocks", ["R4", "R5", "R39"],
     maps=[ign_main(IGN_OK, x=axis("rpm", [1000, 3000, 2000]))],
     findings=[finding("G-AXIS-MONOTONIC", "block", "axis is not strictly monotonic", "ign_main", axis_name="x",
                       breakpoints=[1])],
     tested=TESTED_INTEGRITY + IGN_MAIN_TESTED, not_tested=IGN_MAIN_NT, verdict="block")
case("C07_unreviewed_category", ["R35", "R38"],
     maps=[mapv("unk_1", "ignition", "base", "deg_crank", [[90, 10], [20, 30]], axis("rpm", [1000, 2000]),
                axis("kPa_rel", [0, 60]), label_state="proposed")],
     findings=[finding("G-UNREVIEWED", "warn", UNREVIEWED_TEXT, "unk_1")],
     tested=TESTED_INTEGRITY + [t("axis_monotonic", "unk_1", "G-AXIS-MONOTONIC")],
     not_tested=[nt("physical_range", "category_not_reviewed", "unk_1"), nt("smoothness", "no_rule", "unk_1")],
     verdict="warn")
case("C08_fuel_not_declared", ["R34"], context=("SI", None),
     maps=[ign_main([[90, 20, 30], [15, 25, 35], [20, 28, 30]])], findings=[],
     tested=TESTED_INTEGRITY + [t("axis_monotonic", "ign_main", "G-AXIS-MONOTONIC")],
     not_tested=[nt("physical_range", "fuel_not_declared", "ign_main"), nt("smoothness", "fuel_not_declared", "ign_main")],
     verdict="no findings")
case("C09_correction_map_no_range", ["R36", "R38"],
     maps=[mapv("ign_corr", "ignition", "correction", "deg_crank", [[-20, 50], [0, 0]], axis("rpm", [1000, 2000]),
                axis("kPa_rel", [0, 60]))],
     findings=[],
     tested=TESTED_INTEGRITY + [t("axis_monotonic", "ign_corr", "G-AXIS-MONOTONIC")],
     not_tested=[nt("physical_range", "map_type_correction", "ign_corr"), nt("relative_amplitude", "no_rule", "ign_corr"),
                 nt("smoothness", "no_rule", "ign_corr")],
     verdict="no findings")
case("C10_flag_map_no_range_binary", ["R36", "R38"],
     maps=[mapv("flag_1", "test_synthetic", "flag", "test_unit", [[0, 1], [1, 0]], axis("test_axis", [1, 2]), None)],
     findings=[], tested=TESTED_INTEGRITY + [t("axis_monotonic", "flag_1", "G-AXIS-MONOTONIC")],
     not_tested=[nt("physical_range", "map_type_flag", "flag_1"), nt("smoothness", "binary", "flag_1")],
     verdict="no findings")
case("C11_injector_duty_blocks", ["R5", "R39"],
     maps=[mapv("inj_duty", "injector_duty", "base", "percent", [[100, "201/2"]], axis("rpm", [1000, 2000]), None)],
     findings=[finding("G-INJECTOR-DUTY", "block", "injector duty above 100%", "inj_duty", [[0, 1]])],
     tested=TESTED_INTEGRITY + [t("axis_monotonic", "inj_duty", "G-AXIS-MONOTONIC"),
                                t("physical_range", "inj_duty", "G-INJECTOR-DUTY")],
     not_tested=[nt("smoothness", "shape", "inj_duty")], verdict="block")
case("C12_rule_table_unavailable", ["R21", "R45"], table_name=None, nulls=("input_verify", "layout_hash", "release_candidate_hash"),
     maps=[ign_main(IGN_OK)],
     findings=[finding("G-UNAVAILABLE-RULES", "block", "rule table unavailable; export blocked")],
     tested=[], not_tested=UNAVAILABLE_NT, verdict="block")
# Dual availability is evaluated only when the plugin is available and the variant admitted (R21), so a missing
# plugin yields G-UNAVAILABLE-PLUGIN alone even though the reference is also absent.
case("C13_plugin_unavailable", ["R21", "R45"], nulls=("checksum_variant_id", "conformance_report_hash", "input_verify", "layout_hash", "plugin", "release_candidate_hash"),
     integrity=integ(dual="unavailable", plugin_available=False, verify_status=None),
     maps=[ign_main(IGN_OK)],
     findings=[finding("G-UNAVAILABLE-PLUGIN", "block", "plugin unavailable; export blocked")],
     tested=[], not_tested=UNAVAILABLE_NT, verdict="block")
# rule_silence payload per SPEC-005 R36; the commitment stands for SPEC-005 R82 over the justification text.
SILENCE = {"event_id": "evt-0002", "justification_commitment": sh("justification commitment"),
           "rule_id": "ign.si.gasoline.base.range"}
case("C14_silenced_warn", ["R60", "R61"],
     maps=[ign_main(IGN_RANGE_VALUES)], silences=[SILENCE], findings=[],
     silenced=[dict(RANGE_FINDING, silence_event_id="evt-0002")],
     tested=TESTED_INTEGRITY + IGN_MAIN_TESTED, not_tested=IGN_MAIN_NT, verdict="no findings")
case("C15_silence_without_justification_ignored", ["R60", "R61"],
     maps=[ign_main(IGN_RANGE_VALUES)], silences=[dict(SILENCE, justification_commitment=None)], findings=[RANGE_FINDING],
     tested=TESTED_INTEGRITY + IGN_MAIN_TESTED, not_tested=IGN_MAIN_NT, verdict="warn")
case("C16_block_dominates_warn", ["R4", "R26", "R39"], signed_regions=[SIGNED_REGION],
     integrity=integ(verify_status="signature_unverifiable"),
     maps=[mapv("inj_duty", "injector_duty", "base", "percent", [[100, "201/2"]], axis("rpm", [1000, 2000]), None)],
     findings=[finding("G-INJECTOR-DUTY", "block", "injector duty above 100%", "inj_duty", [[0, 1]]),
               finding("G-VERIFY-SIGNED", "warn", SIGNED_TEXT)],
     tested=TESTED_INTEGRITY + [t("axis_monotonic", "inj_duty", "G-AXIS-MONOTONIC"),
                                t("physical_range", "inj_duty", "G-INJECTOR-DUTY")],
     not_tested=[nt("smoothness", "shape", "inj_duty")], verdict="block")
case("C17_verify_bypassed_blocks", ["R26"],
     integrity=integ(verify_status="bypassed"),
     maps=[ign_main(IGN_OK)],
     findings=[finding("G-VERIFY", "block", "checksum verify returned bypassed after the checksum step")],
     tested=TESTED_INTEGRITY + IGN_MAIN_TESTED, not_tested=IGN_MAIN_NT, verdict="block")
case("C18_dual_divergence_s1", ["R27"],
     integrity=integ(dual="diverge"),
     maps=[ign_main(IGN_OK)],
     findings=[finding("G-DUAL-DIVERGENCE", "block", "checksum implementations disagree", incident="S1")],
     tested=TESTED_INTEGRITY + IGN_MAIN_TESTED, not_tested=IGN_MAIN_NT, verdict="block")
case("C19_reference_none_blocks", ["R21", "R27", "R45"], nulls=("input_verify", "layout_hash", "release_candidate_hash"),
     integrity=integ(dual="reference_none"),
     maps=[ign_main(IGN_OK)],
     findings=[finding("G-UNAVAILABLE-DUAL", "block", "reference checksum implementation unavailable; export blocked")],
     tested=[], not_tested=UNAVAILABLE_NT, verdict="block")
case("C20_downgraded_rule_is_information", ["R3", "R63"], table_name="T2",
     maps=[ign_main(IGN_RANGE_VALUES)], findings=[],
     information=[dict(RANGE_FINDING, severity="info")],
     tested=TESTED_INTEGRITY + IGN_MAIN_TESTED, not_tested=IGN_MAIN_NT, verdict="no findings")
case("C21_unedited_map_not_tested", ["R31", "R41"],
     maps=[ign_main([[90, 20, 30], [15, 25, 35], [20, 28, 30]], edited=False)], findings=[],
     tested=TESTED_INTEGRITY, not_tested=[nt("map_rules", "not_edited", "ign_main")], verdict="no findings")
case("C22_synthetic_smoothness", ["R38"],
     maps=[mapv("syn_1", "test_synthetic", "base", "test_unit", [[0, 5, 30], [5, 10, 15]], axis("test_axis", [1, 2, 3]),
                axis("test_axis", [1, 2]))],
     findings=[finding("test.smooth", "warn", "synthetic smoothness step exceeded", "syn_1", [[0, 1], [0, 2], [1, 2]])],
     tested=TESTED_INTEGRITY + [t("axis_monotonic", "syn_1", "G-AXIS-MONOTONIC"),
                                t("physical_range", "syn_1", "test.sensor"), t("smoothness", "syn_1", "test.smooth")],
     not_tested=[], verdict="warn")
case("C23_synthetic_sensor_range_blocks", ["R5", "R33", "R37"],
     maps=[mapv("syn_2", "test_synthetic", "base", "test_unit", [[-1, 250]], axis("test_axis", [1, 2]), None)],
     findings=[finding("test.sensor", "block", "synthetic sensor range exceeded", "syn_2", [[0, 0]])],
     tested=TESTED_INTEGRITY + [t("axis_monotonic", "syn_2", "G-AXIS-MONOTONIC"), t("physical_range", "syn_2", "test.sensor")],
     not_tested=[nt("smoothness", "shape", "syn_2")], verdict="block")
case("C24_synthetic_relative_amplitude", ["R36", "R37"],
     maps=[mapv("syn_corr", "test_synthetic", "correction", "test_ratio", [["3/4", "5/4"], ["1", "13/10"]],
                axis("test_axis", [1, 2]), axis("test_axis", [1, 2]))],
     findings=[finding("test.amplitude", "warn", "synthetic correction amplitude exceeded", "syn_corr", [[1, 1]])],
     tested=TESTED_INTEGRITY + [t("axis_monotonic", "syn_corr", "G-AXIS-MONOTONIC"),
                                t("relative_amplitude", "syn_corr", "test.amplitude")],
     not_tested=[nt("physical_range", "map_type_correction", "syn_corr"), nt("smoothness", "no_rule", "syn_corr")],
     verdict="warn")
case("C25_rule_without_fuel_does_not_run", ["R34"], table_name="T3",
     maps=[ign_main(IGN_OK)], findings=[], tested=TESTED_INTEGRITY + IGN_MAIN_TESTED,
     not_tested=[nt("physical_range", "rule_without_fuel", None, "test.nofuel")] + IGN_MAIN_NT, verdict="no findings")
case("C26_unmapped_edit", ["R31"],
     maps=[ign_main(IGN_OK)], unmapped_runs=[{"length": 2, "memory_id": "pflash", "offset": 32}],
     findings=[finding("G-UNMAPPED", "warn", UNMAPPED_TEXT, runs=[{"length": 2, "memory_id": "pflash", "offset": 32}])],
     tested=TESTED_INTEGRITY + IGN_MAIN_TESTED, not_tested=IGN_MAIN_NT, verdict="warn")
case("C27_cap_axis_unit_absent", ["R37", "R41"],
     maps=[mapv("ign_load", "ignition", "base", "deg_crank", [[10, 40], [20, 44]], axis("rpm", [1000, 2000]),
                axis("percent", [20, 80]))],
     findings=[],
     tested=TESTED_INTEGRITY + [t("axis_monotonic", "ign_load", "G-AXIS-MONOTONIC"),
                                t("physical_range", "ign_load", "ign.si.gasoline.base.range")],
     not_tested=[nt("physical_range", "axis_unit_absent", "ign_load", "ign.si.gasoline.base.boost_cap"),
                 nt("smoothness", "no_rule", "ign_load")],
     verdict="no findings")
case("C28_combustion_not_declared", ["R34"], context=(None, None),
     maps=[ign_main(IGN_OK)], findings=[],
     tested=TESTED_INTEGRITY + [t("axis_monotonic", "ign_main", "G-AXIS-MONOTONIC")],
     not_tested=[nt("physical_range", "combustion_not_declared", "ign_main"),
                 nt("smoothness", "combustion_not_declared", "ign_main")],
     verdict="no findings")

case("C29_signed_only_variant", ["R6", "R26", "R27", "R41"], signed_regions=[SIGNED_REGION],
     integrity=integ(dual="signed_only", verify_status="signature_unverifiable"),
     maps=[ign_main(IGN_OK)],
     findings=[finding("G-VERIFY-SIGNED", "warn", SIGNED_TEXT)],
     tested=[e for e in TESTED_INTEGRITY if e["kind"] != "dual_checksum"] + IGN_MAIN_TESTED,
     not_tested=[nt("dual_checksum", "signed_only")] + IGN_MAIN_NT, verdict="warn")
case("C30_input_not_bound_blocks", ["R20", "R23", "R45"], nulls=("input_verify", "release_candidate_hash"),
     integrity=integ(binding="mismatch"),
     maps=[ign_main(IGN_OK)],
     findings=[finding("G-BINDING", "block", BINDING_TEXT)],
     tested=[t("binding")], not_tested=EARLIER_BLOCK_NT, verdict="block")
case("C31_input_suspect_unacknowledged", ["R20", "R22"],
     integrity=integ(input_state="unacknowledged"),
     maps=[ign_main(IGN_OK)],
     findings=[finding("G-INPUT-SUSPECT", "block", "input artifact is suspect and was not acknowledged")],
     tested=TESTED_INTEGRITY + IGN_MAIN_TESTED, not_tested=IGN_MAIN_NT, verdict="block")
case("C32_input_suspect_acknowledged", ["R14", "R22"], input_verify="failed_acknowledged",
     integrity=integ(input_state="acknowledged"),
     maps=[ign_main(IGN_OK)], findings=[],
     tested=TESTED_INTEGRITY + IGN_MAIN_TESTED, not_tested=IGN_MAIN_NT, verdict="no findings")
case("C33_nonfinite_breakpoint_blocks", ["R30", "R39"],
     maps=[ign_main(IGN_OK, x=axis("rpm", [1000, "non_finite", 3000]))],
     findings=[finding("G-NONFINITE", "block", "map value is not a finite number", "ign_main", axis_name="x",
                       breakpoints=[1])],
     tested=TESTED_INTEGRITY + [e for e in IGN_MAIN_TESTED if e["kind"] != "axis_monotonic"],
     not_tested=[nt("axis_monotonic", "non_finite", "ign_main")] + IGN_MAIN_NT, verdict="block")
case("C34_reviewed_state_without_unit", ["R35"],
     maps=[mapv("ign_nounit", "ignition", "base", None, [[10, 20], [15, 25]], axis("rpm", [1000, 2000]),
                axis("kPa_rel", [0, 60]))],
     findings=[finding("G-UNREVIEWED", "warn", UNREVIEWED_TEXT, "ign_nounit")],
     tested=TESTED_INTEGRITY + [t("axis_monotonic", "ign_nounit", "G-AXIS-MONOTONIC")],
     not_tested=[nt("physical_range", "category_not_reviewed", "ign_nounit"), nt("smoothness", "no_rule", "ign_nounit")],
     verdict="warn")
# The same conformance report applies at input (R23), where R13/R15 already blocked: the input was acknowledged.
case("C35_variant_not_admitted_blocks", ["R15", "R25", "R26", "R27", "R45"], admitted=[], nulls=("release_candidate_hash",),
     input_verify="failed_acknowledged", integrity=integ(input_state="acknowledged"),
     maps=[ign_main(IGN_OK)],
     findings=[finding("G-VERIFY", "block", "checksum verify returned not_applicable after the checksum step")],
     tested=[e for e in TESTED_INTEGRITY if e["kind"] not in ("checksum_step", "dual_checksum")] + IGN_MAIN_TESTED,
     not_tested=[nt("checksum_step", "unknown_variant"), nt("dual_checksum", "unknown_variant")] + IGN_MAIN_NT,
     verdict="block")
case("C36_checksum_resolution_blocks", ["R20", "R25", "R45"], nulls=("release_candidate_hash",),
     integrity=integ(checksum_resolution="failed"),
     maps=[ign_main(IGN_OK)],
     findings=[finding("G-CHECKSUM-RESOLUTION", "block", "checksum coverage could not be resolved on this file")],
     tested=[t("binding"), t("checksum_step"), t("input_state"), t("kernel_invariants")],
     not_tested=[nt(k, "earlier_block") for k in ("dual_checksum", "map_rules", "verify")], verdict="block")
case("C37_definition_does_not_fit_blocks", ["R28", "R31"],
     maps=[ign_main(IGN_OK), mapv("stale_map", "ignition", "base", "deg_crank", [[10, 20]], axis("rpm", [1000, 2000]), None,
                                  bind_error=True)],
     findings=[finding("G-DEFINITION", "block", "a map of the definition does not fit this file", "stale_map")],
     tested=TESTED_INTEGRITY + IGN_MAIN_TESTED,
     not_tested=[nt("map_rules", "definition_bind", "stale_map")] + IGN_MAIN_NT, verdict="block")

case("C38_dual_unavailable", ["R21", "R45"], nulls=("input_verify", "layout_hash", "release_candidate_hash"),
     integrity=integ(dual="unavailable"),
     maps=[ign_main(IGN_OK)],
     findings=[finding("G-UNAVAILABLE-DUAL", "block", "reference checksum implementation unavailable; export blocked")],
     tested=[], not_tested=UNAVAILABLE_NT, verdict="block")
PROTECTED_RUNS = [{"length": 4, "memory_id": "pflash", "offset": 448}]
case("C39_patch_in_protected_region_blocks", ["R20", "R23", "R24", "R45"], nulls=("input_verify", "release_candidate_hash"),
     integrity=integ(binding="containment", protected_runs=PROTECTED_RUNS),
     maps=[ign_main(IGN_OK)],
     findings=[finding("G-PROTECTED", "block", PROTECTED_TEXT, runs=PROTECTED_RUNS)],
     tested=[t("binding")], not_tested=EARLIER_BLOCK_NT, verdict="block")

# Input gate cases (SPEC-004 §3).
INPUT_CASES: list[dict[str, object]] = []
GOOD_SHA = sh("received file")
INPUT_IMAGE = sh("input image")
PLUGIN = {"family": "synthetic.family", "version": "0.0.0"}


def ident(confidence: int) -> dict[str, object]:
    return {"checksum_variant_id": "synthetic_variant_1", "confidence": confidence, "hw_id": "SYN-HW-1", "sw_id": "SYN-SW-1"}


def confirmation(event_id: str, **override: object) -> dict[str, object]:
    """An identification_confirmed event (SPEC-005 R36); the gate reads event_id, project_id, type, payload."""
    payload = {"artifact_sha256": GOOD_SHA, "checksum_variant_id": "synthetic_variant_1", "family": PLUGIN["family"],
               "hw_id": "SYN-HW-1", "image_hash": INPUT_IMAGE, "plugin_version": PLUGIN["version"], "sw_id": "SYN-SW-1"}
    payload.update(override)
    return {"event_id": event_id, "payload": payload, "project_id": "proj-1", "type": "identification_confirmed"}


def input_case(name: str, rules: list[str], *, declared: str, identification: dict[str, object] | None,
               confirm: dict[str, object] | None, confirmed: bool, verify_status: str | None,
               findings: list[dict[str, object]], tested: list[dict[str, object]],
               not_tested: list[dict[str, object]], verdict: str, admitted: list[str] = ADMITTED,
               signed_regions: list[dict[str, str]] | None = None) -> None:
    verify_run = any(e["kind"] == "input_verify" for e in tested)
    admitted_variant = identification is not None and identification["checksum_variant_id"] in admitted
    subject_status = None if not verify_run else (verify_status if admitted_variant else "not_applicable")
    inputs = {
        "admitted_variants": admitted,
        "confirmation": confirm,
        "conformance_report_hash": sh("conformance report"),
        "declared_sha256": declared,
        "identification": identification,
        "image_hash": INPUT_IMAGE,
        "plugin": PLUGIN,
        "project_id": "proj-1",
        "received_sha256": GOOD_SHA,
        "rule_table": "T1",
        "signed_regions": signed_regions or [],
        "verify_status": verify_status,
    }
    subject = {
        "checksum_variant_id": None if identification is None else identification["checksum_variant_id"],
        "confidence": None if identification is None else identification["confidence"],
        "conformance_report_hash": sh("conformance report"),
        "declared_sha256": declared,
        "identification_hash": None if identification is None else jcs_hash(identification),
        "identify_confirmation_event_id": confirm["event_id"] if confirmed else None,
        "image_hash": INPUT_IMAGE,
        "plugin": PLUGIN,
        "received_sha256": GOOD_SHA,
        "signed_regions": (signed_regions or []) if verify_run and admitted_variant else [],
        "verify_status": subject_status,
    }
    report = {
        "disclaimer": DISCLAIMER, "findings": sort_findings(findings),
        "gate": {"core_version": CORE_VERSION, "rule_table": table_ref("T1"), "spec": "SPEC-004"},
        "information": [], "not_tested": sort_not_tested(not_tested), "silenced": [], "stage": "input",
        "subject": subject, "tested": sort_tested(tested), "verdict": verdict,
    }
    INPUT_CASES.append({"name": name, "rules": rules, "input": inputs, "expected": {
        "artifact_state": "suspect" if verdict == "block" else "accepted",
        "report": report, "report_hash": jcs_hash(report), "verdict": verdict,
    }})


IN_TESTED = [t("identify"), t("input_hash"), t("input_verify")]
IDENTIFY_FAIL = finding("G-INPUT-IDENTIFY", "block", "identification below the confidence threshold and not confirmed")
input_case("I1_accepted", ["R10", "R11", "R12", "R13", "R14"], declared=GOOD_SHA, identification=ident(900), confirm=None,
           confirmed=False, verify_status="ok", findings=[], tested=IN_TESTED, not_tested=[], verdict="no findings")
input_case("I2_hash_mismatch", ["R11", "R14"], declared=sh("other file"), identification=ident(900), confirm=None,
           confirmed=False, verify_status="ok",
           findings=[finding("G-INPUT-HASH", "block", "received file hash differs from the declared hash")],
           tested=IN_TESTED, not_tested=[], verdict="block")
input_case("I3_confidence_equal_threshold_unconfirmed", ["R12", "R14"], declared=GOOD_SHA, identification=ident(800),
           confirm=None, confirmed=False, verify_status=None, findings=[IDENTIFY_FAIL],
           tested=[t("identify"), t("input_hash")], not_tested=[nt("input_verify", "identify_failed")], verdict="block")
input_case("I4_low_confidence_confirmed", ["R12"], declared=GOOD_SHA, identification=ident(500),
           confirm=confirmation("0123456789abcdef0123456789abcdef"), confirmed=True, verify_status="ok", findings=[],
           tested=IN_TESTED, not_tested=[], verdict="no findings")
input_case("I5_verify_bypassed_suspect", ["R13", "R14"], declared=GOOD_SHA, identification=ident(900), confirm=None,
           confirmed=False, verify_status="bypassed",
           findings=[finding("G-INPUT-VERIFY", "block", "input verify returned bypassed")],
           tested=IN_TESTED, not_tested=[], verdict="block")
input_case("I6_no_identification", ["R12"], declared=GOOD_SHA, identification=None, confirm=None, confirmed=False,
           verify_status=None, findings=[IDENTIFY_FAIL],
           tested=[t("identify"), t("input_hash")], not_tested=[nt("input_verify", "identify_failed")], verdict="block")
input_case("I7_confirmation_of_other_variant_ignored", ["R12"], declared=GOOD_SHA, identification=ident(500),
           confirm=confirmation("fedcba9876543210fedcba9876543210", checksum_variant_id="synthetic_variant_2"),
           confirmed=False, verify_status=None, findings=[IDENTIFY_FAIL],
           tested=[t("identify"), t("input_hash")], not_tested=[nt("input_verify", "identify_failed")], verdict="block")
input_case("I8_signed_input_warns", ["R4", "R13", "R14"], declared=GOOD_SHA, identification=ident(900), confirm=None,
           confirmed=False, verify_status="signature_unverifiable", signed_regions=[SIGNED_REGION],
           findings=[finding("G-INPUT-SIGNED", "warn", INPUT_SIGNED_TEXT)],
           tested=IN_TESTED, not_tested=[], verdict="warn")
input_case("I9_variant_not_admitted_suspect", ["R13", "R14", "R15"], declared=GOOD_SHA, identification=ident(900),
           confirm=None, confirmed=False, verify_status="ok", admitted=[],
           findings=[finding("G-INPUT-VERIFY", "block", "input verify returned not_applicable")],
           tested=IN_TESTED, not_tested=[], verdict="block")


# Export authorization with alert_ack (SPEC-004 §7, R50-R52); payload per SPEC-005 R36.
def by_name(name: str) -> dict[str, object]:
    return next(c for c in CASES if c["name"] == name)


def ack_for(name: str) -> dict[str, object]:
    c = by_name(name)
    exp = c["expected"]
    report = exp["report"]
    return {
        "confirmed_ms": 1760000003000,
        "gate_report_hash": exp["report_hash"],
        "image_hash_release": report["subject"]["release_candidate_hash"],
        "presented_ms": 1760000000000,
        "warnings": [{"finding_id": jcs_hash(f), "rule_id": f["rule_id"], "text": f["text"]}
                     for f in report["findings"] if f["severity"] == "warn"],
    }


good = ack_for("C02_ignition_range_warn")
ACK_CASES = [
    # Every ack case covers SPEC-004 R50, R51, R52; A9 also R61.
    {"name": "A1_valid_ack", "case": "C02_ignition_range_warn", "ack": good, "expected": {"authorized": True, "reason": None}},
    {"name": "A2_missing_ack", "case": "C02_ignition_range_warn", "ack": None, "expected": {"authorized": False, "reason": "ack_required"}},
    {"name": "A3_wrong_image", "case": "C02_ignition_range_warn", "ack": dict(good, image_hash_release=sh("other image")),
     "expected": {"authorized": False, "reason": "image_mismatch"}},
    {"name": "A4_wrong_report", "case": "C02_ignition_range_warn", "ack": dict(good, gate_report_hash=sh("other report")),
     "expected": {"authorized": False, "reason": "report_mismatch"}},
    {"name": "A5_missing_finding", "case": "C02_ignition_range_warn", "ack": dict(good, warnings=[]),
     "expected": {"authorized": False, "reason": "findings_mismatch"}},
    {"name": "A6_wrong_text", "case": "C02_ignition_range_warn",
     "ack": dict(good, warnings=[dict(good["warnings"][0], text="something else")]),
     "expected": {"authorized": False, "reason": "text_mismatch"}},
    {"name": "A7_unexpected_ack", "case": "C01_ignition_in_range", "ack": dict(good),
     "expected": {"authorized": False, "reason": "unexpected_ack"}},
    {"name": "A8_no_findings_no_ack", "case": "C01_ignition_in_range", "ack": None, "expected": {"authorized": True, "reason": None}},
    {"name": "A9_silenced_finding_not_acked", "case": "C14_silenced_warn", "ack": None,
     "expected": {"authorized": True, "reason": None}},
]


# Alert fatigue (SPEC-004 §8, R62-R63). latency_ms = confirmed_ms - presented_ms of the alert_ack (SPEC-005 R36);
# null means the alert was not confirmed.
def rec(family: str, rule_id: str, latency_ms: int | None, map_changed: bool) -> dict[str, object]:
    return {"family": family, "latency_ms": latency_ms, "map_changed": map_changed, "rule_id": rule_id}


FATIGUE_CASES = [
    {"name": "F1_downgrade", "rules": ["R62", "R63"],
     "records": [rec("fam.a", "ign.si.gasoline.base.range", 1000, False), rec("fam.a", "ign.si.gasoline.base.range", 4999, False),
                 rec("fam.a", "ign.si.gasoline.base.range", 2000, False), rec("fam.a", "ign.si.gasoline.base.range", 6000, False),
                 rec("fam.a", "ign.si.gasoline.base.range", 1000, True)],
     "expected": [{"alerts": 5, "downgrade": True, "family": "fam.a", "fraction": "3/5", "quick_confirms": 3,
                   "rule_id": "ign.si.gasoline.base.range"}]},
    {"name": "F2_exactly_half_and_5s_boundary", "rules": ["R62", "R63"],
     "records": [rec("fam.a", "r.x", 1000, False), rec("fam.a", "r.x", 5000, False), rec("fam.a", "r.x", None, False),
                 rec("fam.a", "r.x", 100, False)],
     "expected": [{"alerts": 4, "downgrade": False, "family": "fam.a", "fraction": "1/2", "quick_confirms": 2, "rule_id": "r.x"}]},
    {"name": "F3_per_family", "rules": ["R62"],
     "records": [rec("fam.b", "r.x", 10, False), rec("fam.a", "r.x", 10, True), rec("fam.b", "r.y", 9000, False)],
     "expected": [{"alerts": 1, "downgrade": False, "family": "fam.a", "fraction": "0", "quick_confirms": 0, "rule_id": "r.x"},
                  {"alerts": 1, "downgrade": True, "family": "fam.b", "fraction": "1", "quick_confirms": 1, "rule_id": "r.x"},
                  {"alerts": 1, "downgrade": False, "family": "fam.b", "fraction": "0", "quick_confirms": 0, "rule_id": "r.y"}]},
]

for _a in ACK_CASES:
    _a["rules"] = ["R50", "R51", "R52"] + (["R61"] if _a["name"].startswith("A9") else [])

vectors = {
    "spec": "SPEC-004",
    "generator": {
        "script": "generate.py",
        "python": sys.version.split()[0],
        "rfc8785": importlib.metadata.version("rfc8785"),
        "note": "Physical values are exact rationals as canonical strings (SPEC-004 R30); no floats anywhere. "
                "Category test_synthetic and its ranges exist only in these vectors.",
    },
    "disclaimer": DISCLAIMER,
    "rule_tables": {n: {"value": tb, "hash": jcs_hash(tb)} for n, tb in TABLES.items()},
    "output_cases": CASES,
    "input_cases": INPUT_CASES,
    "ack_cases": ACK_CASES,
    "fatigue_cases": FATIGUE_CASES,
}
json.dump(vectors, sys.stdout, indent=1, sort_keys=True, ensure_ascii=True)
sys.stdout.write("\n")
