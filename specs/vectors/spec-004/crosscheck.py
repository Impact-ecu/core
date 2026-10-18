"""Second, independent implementation that recomputes every expected result in vectors.json.

Stdlib only and independent of the core and of generate.py:
- canonical JSON: for these objects (ASCII strings, integers, null, booleans, no floats), RFC 8785 output equals
  json.dumps with sorted keys and no whitespace;
- rationals: parsed into (numerator, denominator) integer pairs and compared by cross-multiplication, never fractions;
- rule evaluation walks the rule table first and the maps second (generate.py has no evaluator at all).
It also checks that the disclaimer is verbatim in SPEC-000 and is the first canonical member of every report.
Run: python -I crosscheck.py vectors.json   (exit status 1 on any disagreement)
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import sys
from pathlib import Path

RATIONAL = re.compile(r"^-?(0|[1-9][0-9]*)(/[1-9][0-9]*)?$")
TABLE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
UNREVIEWED = "you edited a map whose meaning has not been confirmed"
UNMAPPED = "you edited bytes that belong to no known map"
BUILTIN_ROW = re.compile(r"^\| `(G-[A-Z0-9-]+)` \| [a-z]+ \| [a-z, S1]+ \| `([^`]+)` \|")


def canon(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha_obj(obj: object) -> str:
    return hashlib.sha256(canon(obj).encode("utf-8")).hexdigest()


def rat(text: str) -> tuple[int, int]:
    if not RATIONAL.match(text) or text == "-0":
        raise ValueError(f"non-canonical rational {text!r}")
    if "/" in text:
        n, d = (int(p) for p in text.split("/"))
        if d < 2 or math.gcd(n, d) != 1:
            raise ValueError(f"non-canonical rational {text!r}")
        return n, d
    return int(text), 1


def lt(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] * b[1] < b[0] * a[1]


def gt(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return lt(b, a)


def absdiff(a: tuple[int, int], b: tuple[int, int]) -> tuple[int, int]:
    return abs(a[0] * b[1] - b[0] * a[1]), a[1] * b[1]


def sign(a: tuple[int, int], b: tuple[int, int]) -> int:
    x = b[0] * a[1] - a[0] * b[1]
    return (x > 0) - (x < 0)


def finding(rule_id: str, severity: str, text: str, map_id: str | None = None, cells: list[list[int]] | None = None,
            axis_name: str | None = None, breakpoints: list[int] | None = None, incident: str | None = None,
            runs: list[dict] | None = None, rule_version: int = 1) -> dict:
    return {"axis": axis_name, "breakpoints": breakpoints or [], "cells": sorted(cells or []), "incident": incident,
            "map_id": map_id, "rule_id": rule_id, "rule_version": rule_version, "runs": runs or [],
            "severity": severity, "text": text}


def fkey(f: dict) -> tuple[str, str, str]:
    return f["rule_id"], f["map_id"] or "", f["axis"] or ""


def has_float(obj: object) -> bool:
    if isinstance(obj, float):
        return True
    if isinstance(obj, dict):
        return any(has_float(x) for x in obj.values())
    if isinstance(obj, list):
        return any(has_float(x) for x in obj)
    return False


def valid_table(tb: dict) -> bool:
    ids = [r["rule_id"] for r in tb["rules"]]
    if len(ids) != len(set(ids)):
        return False
    th = tb["identify_min_confidence"]
    if not isinstance(th, int) or isinstance(th, bool) or not 0 <= th <= 1000:
        return False
    need = {"range": set(), "sensor_range": {"min", "max"}, "conditional_cap": {"max", "axis_unit", "above"},
            "relative_amplitude": {"neutral", "max_deviation"}, "smoothness": {"max_step"}}
    for r in tb["rules"]:
        if not TABLE_ID.match(r["rule_id"]) or r["kind"] not in need or not need[r["kind"]] <= set(r["params"]):
            return False
        for k, val in r["params"].items():
            if k != "axis_unit":
                rat(val)
        if r["kind"] == "range" and not ({"min", "max"} & set(r["params"])):
            return False
        mt = r["key"]["map_type"]
        if r["kind"] in ("range", "conditional_cap", "sensor_range") and mt != "base":
            return False
        if r["kind"] == "relative_amplitude" and mt != "correction":
            return False
        want = {"block"} if r["kind"] == "sensor_range" else {"warn", "info"}
        if r["severity"] not in want:
            return False
    return True


class Checker:
    def __init__(self, v: dict) -> None:
        self.v = v
        self.failures: list[str] = []
        self.checked = 0
        self.reports: dict[str, tuple[dict, str]] = {}

    def expect(self, label: str, got: object, want: object) -> None:
        self.checked += 1
        if got != want:
            self.failures.append(f"{label}: got {got!r}, want {want!r}")

    # ---- output gate -------------------------------------------------------------------------------------
    def output_report(self, inp: dict) -> dict:
        tname = inp["rule_table"]
        tb = None if tname is None else self.v["rule_tables"][tname]["value"]
        integ = inp["integrity"]
        findings: list[dict] = []
        tested: list[dict] = []
        not_tested: list[dict] = []
        unavailable = []
        if tb is None or not valid_table(tb):
            unavailable.append(finding("G-UNAVAILABLE-RULES", "block", "rule table unavailable; export blocked"))
        if not integ["plugin_available"]:
            unavailable.append(finding("G-UNAVAILABLE-PLUGIN", "block", "plugin unavailable; export blocked"))
        src = inp["sources"]
        admitted_variant = src["checksum_variant_id"] in inp["admitted_variants"]
        if integ["plugin_available"] and admitted_variant and integ["dual"] in ("unavailable", "reference_none"):
            unavailable.append(finding("G-UNAVAILABLE-DUAL", "block",
                                       "reference checksum implementation unavailable; export blocked"))
        information: list[dict] = []
        silenced: list[dict] = []
        later = ("input_state", "kernel_invariants", "checksum_step", "verify", "dual_checksum", "map_rules")
        ran = {"step1_plugin": integ["plugin_available"], "binding": False, "input_state": False, "checksum": False}
        if unavailable:
            findings = unavailable
            for k in ("binding",) + later:
                not_tested.append({"kind": k, "map_id": None, "reason": "gate_unavailable", "rule_id": None})
        elif integ["binding"] != "ok":
            ran["binding"] = True
            tested.append({"kind": "binding", "map_id": None, "rule_id": None})
            if integ["binding"] == "containment":
                runs = sorted(integ["protected_runs"], key=lambda r: (r["memory_id"], r["offset"]))
                findings.append(finding("G-PROTECTED", "block", "a patch touches a region that is not calibration", runs=runs))
            else:
                findings.append(finding("G-BINDING", "block", "image, version, layout, plugin or input check do not match"))
            for k in later:
                not_tested.append({"kind": k, "map_id": None, "reason": "earlier_block", "rule_id": None})
        elif integ["checksum_resolution"] != "ok":
            ran.update(binding=True, input_state=True)
            for k in ("binding", "input_state", "kernel_invariants", "checksum_step"):
                tested.append({"kind": k, "map_id": None, "rule_id": None})
            findings.append(finding("G-CHECKSUM-RESOLUTION", "block", "checksum coverage could not be resolved on this file"))
            for k in ("verify", "dual_checksum", "map_rules"):
                not_tested.append({"kind": k, "map_id": None, "reason": "earlier_block", "rule_id": None})
        else:
            ran.update(binding=True, input_state=True, checksum=True)
            admitted = src["checksum_variant_id"] in inp["admitted_variants"]
            ran["checksum"] = admitted
            for k in ("binding", "input_state", "kernel_invariants", "verify") + (("checksum_step",) if admitted else ()):
                tested.append({"kind": k, "map_id": None, "rule_id": None})
            if not admitted:
                not_tested.append({"kind": "checksum_step", "map_id": None, "reason": "unknown_variant", "rule_id": None})
            if integ["input_state"] == "unacknowledged":
                findings.append(finding("G-INPUT-SUSPECT", "block", "input artifact is suspect and was not acknowledged"))
            want_iv = "failed_acknowledged" if integ["input_state"] == "acknowledged" else "ok"
            if src["input_verify"] != want_iv:
                self.failures.append(f"source input_verify {src['input_verify']!r} != {want_iv!r}")
            st = integ["verify_status"] if admitted else "not_applicable"
            if st == "signature_unverifiable" and not src["signed_regions"]:
                self.failures.append("subject signed_regions empty with signature_unverifiable")
            if st == "signature_unverifiable":
                findings.append(finding("G-VERIFY-SIGNED", "warn",
                                        "signed region: its signature cannot be verified, and an edit may invalidate it"))
            elif st != "ok":
                findings.append(finding("G-VERIFY", "block", f"checksum verify returned {st} after the checksum step"))
            if not admitted:
                not_tested.append({"kind": "dual_checksum", "map_id": None, "reason": "unknown_variant", "rule_id": None})
            elif integ["dual"] == "signed_only":
                not_tested.append({"kind": "dual_checksum", "map_id": None, "reason": "signed_only", "rule_id": None})
            else:
                tested.append({"kind": "dual_checksum", "map_id": None, "rule_id": None})
                if integ["dual"] == "diverge":
                    findings.append(finding("G-DUAL-DIVERGENCE", "block", "checksum implementations disagree", incident="S1"))
            self.map_rules(tb, inp, findings, information, tested, not_tested)
            if inp["unmapped_runs"]:
                runs = sorted(inp["unmapped_runs"], key=lambda r: (r["memory_id"], r["offset"]))
                findings.append(finding("G-UNMAPPED", "warn", UNMAPPED, runs=runs))
            kept = []
            for f in findings:
                sil = sorted(s["event_id"] for s in inp["silences"]
                             if s["rule_id"] == f["rule_id"] and s["justification_commitment"] is not None)
                if f["severity"] == "warn" and not f["rule_id"].startswith("G-") and sil:
                    silenced.append(dict(f, silence_event_id=sil[0]))
                else:
                    kept.append(f)
            findings = kept
        sevs = {f["severity"] for f in findings}
        verdict = "block" if "block" in sevs else "warn" if "warn" in sevs else "no findings"
        return {
            "disclaimer": self.v["disclaimer"],
            "findings": sorted(findings, key=fkey),
            "gate": {"core_version": "0.0.0",
                     "rule_table": None if tb is None else {"hash": sha_obj(tb), "table_id": tb["table_id"], "version": tb["version"]},
                     "spec": "SPEC-004"},
            "information": sorted(information, key=fkey),
            "not_tested": sorted(not_tested, key=lambda e: (e["kind"], e["map_id"] or "", e["rule_id"] or "", e["reason"])),
            "silenced": sorted(silenced, key=fkey),
            "stage": "output",
            "subject": self.subject_r45(src, ran),
            "tested": sorted(tested, key=lambda e: (e["kind"], e["map_id"] or "", e["rule_id"] or "")),
            "verdict": verdict,
        }

    @staticmethod
    def subject_r45(src: dict, ran: dict) -> dict:
        """SPEC-004 R45: a subject field whose producing step did not run is null."""
        subj = dict(src)
        if not ran["step1_plugin"]:
            for k in ("plugin", "conformance_report_hash", "checksum_variant_id"):
                subj[k] = None
        if not ran["binding"]:
            subj["layout_hash"] = None
        if not ran["input_state"]:
            subj["input_verify"] = None
        if not ran["checksum"]:
            subj["release_candidate_hash"] = None
        return subj

    def map_rules(self, tb: dict, inp: dict, findings: list, information: list, tested: list, not_tested: list) -> None:
        ctx = inp["context"]
        rules = tb["rules"]
        for r in rules:
            if r["key"]["fuel"] is None:
                not_tested.append({"kind": "physical_range" if r["kind"] in ("range", "conditional_cap", "sensor_range")
                                   else r["kind"], "map_id": None, "reason": "rule_without_fuel", "rule_id": r["rule_id"]})
        runnable = [r for r in rules if r["key"]["fuel"] is not None]
        ctx_reason = ("combustion_not_declared" if ctx["combustion"] is None
                      else "fuel_not_declared" if ctx["fuel"] is None else None)

        def emit(f: dict) -> None:
            (information if f["severity"] == "info" else findings).append(f)

        for m in inp["maps"]:
            mid = m["map_id"]
            if m["bind_error"]:
                findings.append(finding("G-DEFINITION", "block", "a map of the definition does not fit this file", mid))
                not_tested.append({"kind": "map_rules", "map_id": mid, "reason": "definition_bind", "rule_id": None})
                continue
            if not m["edited"]:
                not_tested.append({"kind": "map_rules", "map_id": mid, "reason": "not_edited", "rule_id": None})
                continue
            vals = [[rat(x) for x in row] for row in m["values"]]
            raw = [x for row in m["values"] for x in row]
            nrows, ncols = len(vals), len(vals[0])
            reviewed = (m["label_state"] in ("reviewed", "golden") and m["category"] is not None
                        and m["map_type"] is not None and m["unit"] is not None)
            # Rules first: which runnable table rules match this map's key under the engine context.
            matched = [r for r in runnable if ctx_reason is None and r["key"] == {
                "category": m["category"], "combustion": ctx["combustion"], "fuel": ctx["fuel"],
                "map_type": m["map_type"], "unit": m["unit"]}]

            axes = [(n, m[f"{n}_axis"]) for n in ("x", "y") if m[f"{n}_axis"] is not None]
            nonfinite = [(n, [i for i, x in enumerate(ax["values"]) if x == "non_finite"]) for n, ax in axes]
            nonfinite = [(n, idx) for n, idx in nonfinite if idx]
            for name, idx in nonfinite:
                findings.append(finding("G-NONFINITE", "block", "map value is not a finite number", mid,
                                        axis_name=name, breakpoints=idx))
            if not axes:
                not_tested.append({"kind": "axis_monotonic", "map_id": mid, "reason": "no_axis", "rule_id": None})
            elif nonfinite:
                not_tested.append({"kind": "axis_monotonic", "map_id": mid, "reason": "non_finite", "rule_id": None})
            else:
                tested.append({"kind": "axis_monotonic", "map_id": mid, "rule_id": "G-AXIS-MONOTONIC"})
            for name, ax in ([] if nonfinite else axes):
                pts = [rat(x) for x in ax["values"]]
                signs = [sign(pts[i], pts[i + 1]) for i in range(len(pts) - 1)]
                ref = next((s for s in signs if s != 0), None)
                bad = [i for i, s in enumerate(signs) if s == 0 or s != ref]
                if bad:
                    findings.append(finding("G-AXIS-MONOTONIC", "block", "axis is not strictly monotonic", mid,
                                            axis_name=name, breakpoints=bad))
            if not reviewed:
                findings.append(finding("G-UNREVIEWED", "warn", UNREVIEWED, mid))

            # smoothness
            if nrows < 2 or ncols < 2:
                not_tested.append({"kind": "smoothness", "map_id": mid, "reason": "shape", "rule_id": None})
            elif len(set(raw)) <= 2:
                not_tested.append({"kind": "smoothness", "map_id": mid, "reason": "binary", "rule_id": None})
            elif ctx_reason is not None:
                not_tested.append({"kind": "smoothness", "map_id": mid, "reason": ctx_reason, "rule_id": None})
            else:
                srules = [r for r in matched if r["kind"] == "smoothness"]
                if not srules:
                    not_tested.append({"kind": "smoothness", "map_id": mid, "reason": "no_rule", "rule_id": None})
                for r in srules:
                    tested.append({"kind": "smoothness", "map_id": mid, "rule_id": r["rule_id"]})
                    step = rat(r["params"]["max_step"])
                    cells = set()
                    for i in range(nrows):
                        for j in range(ncols):
                            for di, dj in ((0, 1), (1, 0)):
                                a, b = i + di, j + dj
                                if a < nrows and b < ncols and gt(absdiff(vals[i][j], vals[a][b]), step):
                                    cells.update({(i, j), (a, b)})
                    if cells:
                        emit(finding(r["rule_id"], r["severity"], r["text"], mid, [list(c) for c in cells],
                                     rule_version=r["rule_version"]))

            # physical range and relative amplitude
            if not reviewed:
                not_tested.append({"kind": "physical_range", "map_id": mid, "reason": "category_not_reviewed", "rule_id": None})
                if m["map_type"] == "correction":
                    not_tested.append({"kind": "relative_amplitude", "map_id": mid, "reason": "category_not_reviewed",
                                       "rule_id": None})
                continue
            if m["map_type"] != "base":
                not_tested.append({"kind": "physical_range", "map_id": mid, "reason": "map_type_" + m["map_type"],
                                   "rule_id": None})
            if m["map_type"] == "correction":
                arules = [r for r in matched if r["kind"] == "relative_amplitude"]
                if ctx_reason is not None:
                    not_tested.append({"kind": "relative_amplitude", "map_id": mid, "reason": ctx_reason, "rule_id": None})
                elif not arules:
                    not_tested.append({"kind": "relative_amplitude", "map_id": mid, "reason": "no_rule", "rule_id": None})
                for r in arules:
                    tested.append({"kind": "relative_amplitude", "map_id": mid, "rule_id": r["rule_id"]})
                    n, d = rat(r["params"]["neutral"]), rat(r["params"]["max_deviation"])
                    cells = [[i, j] for i in range(nrows) for j in range(ncols) if gt(absdiff(vals[i][j], n), d)]
                    if cells:
                        emit(finding(r["rule_id"], r["severity"], r["text"], mid, cells, rule_version=r["rule_version"]))
            if m["map_type"] != "base":
                continue
            ran = False
            if m["category"] == "injector_duty" and m["unit"] == "percent":
                ran = True
                tested.append({"kind": "physical_range", "map_id": mid, "rule_id": "G-INJECTOR-DUTY"})
                cells = [[i, j] for i in range(nrows) for j in range(ncols) if gt(vals[i][j], (100, 1))]
                if cells:
                    findings.append(finding("G-INJECTOR-DUTY", "block", "injector duty above 100%", mid, cells))
            if ctx_reason is not None:
                not_tested.append({"kind": "physical_range", "map_id": mid, "reason": ctx_reason, "rule_id": None})
                continue
            prules = [r for r in matched if r["kind"] in ("range", "conditional_cap", "sensor_range")]
            if not prules and not ran:
                not_tested.append({"kind": "physical_range", "map_id": mid, "reason": "no_rule", "rule_id": None})
            for r in prules:
                p = r["params"]
                if r["kind"] == "conditional_cap":
                    ymatch = m["y_axis"] is not None and m["y_axis"]["unit"] == p["axis_unit"]  # finite here
                    xmatch = m["x_axis"] is not None and m["x_axis"]["unit"] == p["axis_unit"]
                    if not (ymatch or xmatch):
                        not_tested.append({"kind": "physical_range", "map_id": mid, "reason": "axis_unit_absent",
                                           "rule_id": r["rule_id"]})
                        continue
                    above, cap = rat(p["above"]), rat(p["max"])

                    def hot(i: int, j: int) -> bool:
                        return ((ymatch and gt(rat(m["y_axis"]["values"][i]), above))
                                or (xmatch and gt(rat(m["x_axis"]["values"][j]), above)))

                    cells = [[i, j] for i in range(nrows) for j in range(ncols) if hot(i, j) and gt(vals[i][j], cap)]
                else:
                    lo = rat(p["min"]) if "min" in p else None
                    hi = rat(p["max"]) if "max" in p else None
                    cells = [[i, j] for i in range(nrows) for j in range(ncols)
                             if (lo is not None and lt(vals[i][j], lo)) or (hi is not None and gt(vals[i][j], hi))]
                tested.append({"kind": "physical_range", "map_id": mid, "rule_id": r["rule_id"]})
                if cells:
                    emit(finding(r["rule_id"], r["severity"], r["text"], mid, cells, rule_version=r["rule_version"]))

    # ---- input gate --------------------------------------------------------------------------------------
    def input_report(self, inp: dict) -> tuple[dict, str]:
        tb = self.v["rule_tables"][inp["rule_table"]]["value"]
        findings, tested, not_tested = [], [{"kind": "input_hash", "map_id": None, "rule_id": None}], []
        if inp["declared_sha256"] != inp["received_sha256"]:
            findings.append(finding("G-INPUT-HASH", "block", "received file hash differs from the declared hash"))
        tested.append({"kind": "identify", "map_id": None, "rule_id": None})
        ident = inp["identification"]
        conf = inp["confirmation"]
        confirmed = conf is not None and ident is not None and conf["type"] == "identification_confirmed" \
            and conf["project_id"] == inp["project_id"] and conf["payload"] == {
                "artifact_sha256": inp["received_sha256"], "image_hash": inp["image_hash"],
                "family": inp["plugin"]["family"], "plugin_version": inp["plugin"]["version"],
                "hw_id": ident["hw_id"], "sw_id": ident["sw_id"], "checksum_variant_id": ident["checksum_variant_id"]}
        ok = confirmed or (ident is not None and ident["confidence"] > tb["identify_min_confidence"])
        status = None
        if not ok:
            findings.append(finding("G-INPUT-IDENTIFY", "block",
                                    "identification below the confidence threshold and not confirmed"))
            not_tested.append({"kind": "input_verify", "map_id": None, "reason": "identify_failed", "rule_id": None})
        else:
            tested.append({"kind": "input_verify", "map_id": None, "rule_id": None})
            status = inp["verify_status"] if ident["checksum_variant_id"] in inp["admitted_variants"] else "not_applicable"
            if status == "signature_unverifiable":
                findings.append(finding("G-INPUT-SIGNED", "warn", "signed region: its signature cannot be verified"))
            elif status != "ok":
                findings.append(finding("G-INPUT-VERIFY", "block", f"input verify returned {status}"))
        sevs = {f["severity"] for f in findings}
        verdict = "block" if "block" in sevs else "warn" if "warn" in sevs else "no findings"
        report = {
            "disclaimer": self.v["disclaimer"],
            "findings": sorted(findings, key=lambda f: f["rule_id"]),
            "gate": {"core_version": "0.0.0", "rule_table": {"hash": sha_obj(tb), "table_id": tb["table_id"], "version": tb["version"]},
                     "spec": "SPEC-004"},
            "information": [], "not_tested": not_tested, "silenced": [], "stage": "input",
            "subject": {
                "checksum_variant_id": None if ident is None else ident["checksum_variant_id"],
                "confidence": None if ident is None else ident["confidence"],
                "conformance_report_hash": inp["conformance_report_hash"],
                "declared_sha256": inp["declared_sha256"],
                "identification_hash": None if ident is None else sha_obj(ident),
                "identify_confirmation_event_id": conf["event_id"] if confirmed else None,
                "image_hash": inp["image_hash"], "plugin": inp["plugin"], "received_sha256": inp["received_sha256"],
                "signed_regions": inp["signed_regions"] if status is not None and status != "not_applicable" else [],
                "verify_status": status,
            },
            "tested": sorted(tested, key=lambda e: e["kind"]),
            "verdict": verdict,
        }
        return report, "suspect" if verdict == "block" else "accepted"

    # ---- authorization and fatigue -----------------------------------------------------------------------
    @staticmethod
    def authorize(report: dict, report_hash: str, ack: dict | None) -> tuple[bool, str | None]:
        if report["verdict"] == "no findings":
            return (True, None) if ack is None else (False, "unexpected_ack")
        if ack is None:
            return False, "ack_required"
        warns = [f for f in report["findings"] if f["severity"] == "warn"]
        if set(ack) != {"image_hash_release", "gate_report_hash", "warnings", "presented_ms", "confirmed_ms"} \
                or not ack["presented_ms"] <= ack["confirmed_ms"]:
            return False, "bad_payload"
        if ack["image_hash_release"] != report["subject"]["release_candidate_hash"]:
            return False, "image_mismatch"
        if ack["gate_report_hash"] != report_hash:
            return False, "report_mismatch"
        if [(w["finding_id"], w["rule_id"]) for w in ack["warnings"]] != [(sha_obj(f), f["rule_id"]) for f in warns]:
            return False, "findings_mismatch"
        if [w["text"] for w in ack["warnings"]] != [f["text"] for f in warns]:
            return False, "text_mismatch"
        return True, None

    @staticmethod
    def fatigue(records: list[dict]) -> list[dict]:
        groups: dict[tuple[str, str], list[int]] = {}
        for r in records:
            g = groups.setdefault((r["family"], r["rule_id"]), [0, 0])
            g[0] += 1
            if r["latency_ms"] is not None and r["latency_ms"] < 5000 and not r["map_changed"]:
                g[1] += 1
        out = []
        for (fam, rid), (alerts, quick) in sorted(groups.items()):
            k = math.gcd(quick, alerts)
            n, d = quick // k, alerts // k
            out.append({"alerts": alerts, "downgrade": 2 * quick > alerts, "family": fam,
                        "fraction": str(n) if d == 1 else f"{n}/{d}", "quick_confirms": quick, "rule_id": rid})
        return out

    def check_builtin_texts(self, label: str, report: dict) -> None:
        for f in report["findings"] + report["information"] + report["silenced"]:
            if f["rule_id"].startswith("G-"):
                pattern = self.builtin.get(f["rule_id"])
                ok = pattern is not None and re.fullmatch(re.escape(pattern).replace(re.escape("<status>"), "[a-z_]+"),
                                                          f["text"]) is not None
                self.expect(f"{label} {f['rule_id']} text matches SPEC-004 §9", ok, True)

    def run(self) -> None:
        self.expect("no float anywhere in vectors", has_float(self.v), False)
        spec000 = Path(__file__).resolve().parents[2] / "SPEC-000-adr.md"
        self.expect("disclaimer verbatim in SPEC-000", self.v["disclaimer"] in spec000.read_text(encoding="utf-8"), True)
        spec004 = Path(__file__).resolve().parents[2] / "SPEC-004-gate.md"
        builtin = {}
        for line in spec004.read_text(encoding="utf-8").splitlines():
            mm = BUILTIN_ROW.match(line)
            if mm:
                builtin[mm.group(1)] = mm.group(2)
        self.builtin = builtin
        for name, tb in self.v["rule_tables"].items():
            self.expect(f"rule_table {name} hash", sha_obj(tb["value"]), tb["hash"])
            self.expect(f"rule_table {name} valid", valid_table(tb["value"]), True)
        for c in self.v["output_cases"]:
            report = self.output_report(c["input"])
            rh = sha_obj(report)
            self.reports[c["name"]] = (report, rh)
            exp = c["expected"]
            self.expect(f"{c['name']} report", canon(report), canon(exp["report"]))
            self.expect(f"{c['name']} report_hash", rh, exp["report_hash"])
            self.expect(f"{c['name']} verdict", report["verdict"], exp["verdict"])
            self.expect(f"{c['name']} finding_ids", [sha_obj(f) for f in report["findings"]], exp["finding_ids"])
            self.expect(f"{c['name']} disclaimer first", canon(report).startswith('{"disclaimer":'), True)
            self.check_builtin_texts(c["name"], exp["report"])
        for c in self.v["input_cases"]:
            report, state = self.input_report(c["input"])
            exp = c["expected"]
            self.expect(f"{c['name']} report", canon(report), canon(exp["report"]))
            self.expect(f"{c['name']} report_hash", sha_obj(report), exp["report_hash"])
            self.expect(f"{c['name']} artifact_state", state, exp["artifact_state"])
            self.check_builtin_texts(c["name"], exp["report"])
            self.expect(f"{c['name']} disclaimer first", canon(report).startswith('{"disclaimer":'), True)
        for a in self.v["ack_cases"]:
            report, rh = self.reports[a["case"]]
            ok, reason = self.authorize(report, rh, a["ack"])
            self.expect(f"{a['name']} authorization", {"authorized": ok, "reason": reason}, a["expected"])
        for f in self.v["fatigue_cases"]:
            self.expect(f"{f['name']} fatigue", self.fatigue(f["records"]), f["expected"])


def main() -> int:
    path = Path(sys.argv[1])
    v = json.loads(path.read_text(encoding="utf-8"))
    ck = Checker(v)
    ck.run()
    if ck.failures:
        for msg in ck.failures:
            print("FAIL", msg)
        print(f"{len(ck.failures)} failures out of {ck.checked} checks")
        return 1
    print(f"OK: {ck.checked} checks agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
