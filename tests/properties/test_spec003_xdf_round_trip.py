"""SPEC-003 R62, R64 as properties: both round-trip statements over generated definitions."""

from hypothesis import given

from core.definitions import (
    Definition,
    License,
    SoftwareVersion,
    XdfParams,
    definition_hash,
    export_xdf,
    import_xdf,
    normalize_xdf,
)
from tests.properties.definition_strategies import xdf_definitions

PARAMS = XdfParams("synthetic.test", SoftwareVersion("exact", ("SYN0001",)), "cal", License("unverified", None), 0)


# SPEC-003 R62, R64: for any exportable e, import(export(e), P) == normalize(e, P), nothing rejected or
# ignored; for the importer result d, import(export(d), P) has the hash of d; export is deterministic.
@given(xdf_definitions())
def test_xdf_round_trip(definition: Definition) -> None:
    exported = export_xdf(definition, "cal")
    assert export_xdf(definition, "cal") == exported
    imported = import_xdf(exported, PARAMS)
    assert imported.rejected == ()
    assert imported.ignored == ()
    assert imported.definition == normalize_xdf(definition, PARAMS)
    again = import_xdf(export_xdf(imported.definition, "cal"), PARAMS)
    assert again.rejected == ()
    assert definition_hash(again.definition) == definition_hash(imported.definition)
