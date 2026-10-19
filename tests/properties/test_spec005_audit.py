"""SPEC-005 R20, R23-R26 as properties: whatever a third party wrote, the gate's audit binds the record to its
own input reports and to the kernel diff, and is deterministic."""

from hypothesis import given
from hypothesis import strategies as st

from core.gate._audit import Audit, run_audit
from core.kernel import diff, image_hash
from tests.unit.gate_support import CORE_VERSION, admit_all, arguments, doc, file_of
from tests.unit.plugin_fixtures import LAYOUT, ORIGINAL, dump_of


@st.composite
def candidates(draw: st.DrawFn) -> bytes:
    data = bytearray(ORIGINAL)
    for _ in range(draw(st.integers(0, 6))):
        offset = draw(st.integers(0, len(ORIGINAL) - 1))
        data[offset] ^= draw(st.integers(1, 255))
    return bytes(data)


# SPEC-005 R20, R23, R24, R26: verify fields are the input subjects, the gate report is the candidate's input
# report, the lists are SPEC-001 R31/R32's, and the same inputs give the same audit_hash.
@given(candidates())
def test_audit_binds_to_the_gate_and_the_diff(data: bytes) -> None:
    original, candidate = dump_of(ORIGINAL), dump_of(data)
    result = run_audit(file_of(original), file_of(candidate), arguments(), admit_all, CORE_VERSION)
    assert isinstance(result, Audit)
    record = doc(result.record.value)
    subjects = [doc(r.report)["subject"]["verify_status"] for r in (result.original_input, result.candidate_input)]
    assert [record["verify"]["original"], record["verify"]["candidate"]] == subjects
    assert record["gate_report_hash"] == result.candidate_input.report_hash
    assert record["image_hash_candidate"] == image_hash(candidate)
    expected = diff(original, candidate, LAYOUT)
    assert list(record["diff_patch_hashes"]) == [p.patch_hash for p in expected.patches]
    assert [(f["offset"], f["length"]) for f in record["foreign"]] == [(f.offset, f.length) for f in expected.foreign]
    again = run_audit(file_of(original), file_of(candidate), arguments(), admit_all, CORE_VERSION)
    assert isinstance(again, Audit)
    assert again.record.audit_hash == result.record.audit_hash
