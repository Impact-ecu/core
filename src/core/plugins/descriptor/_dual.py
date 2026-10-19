"""`checksums` validation (R30-R33) and the comparison of the plugin with its reference (R45, R55)."""

from collections.abc import Mapping, Sequence

from core.kernel import Dump, MemoryLayout, Patch
from core.plugins._checks import check_regions, recalculable_fields
from core.plugins._contract import ChecksumRegion, Identification, RegionResult, VerifyReport, require
from core.plugins._schema import Descriptor, MirrorDescriptor, Range
from core.plugins.descriptor._interpret import (
    Span,
    chain_stores,
    interpret_patches,
    interpret_verify,
    validate_variant,
)


def _spans(items: Sequence[Range]) -> list[Span]:
    return [(item.start, item.end) for item in items]


def _static_inputs(d: Descriptor, stores: Mapping[tuple[str, str], Span]) -> list[Span]:
    """Inputs of `d` known without the dump (R75): table pieces are resolved per dump and are not here."""
    if isinstance(d, MirrorDescriptor):
        return _spans([d.mirror_block.source])
    inputs = _spans(d.ranges or ())
    if d.ranges_from_table is not None:
        inputs += _spans([d.ranges_from_table.span])
    # Static validation (R69) already guarantees every chain name is a target with a store.
    inputs += [stores[(d.memory_id, name)] for name in d.chain or ()]
    if d.strategy == "compensate" and d.store is not None:
        inputs += _spans([d.store.span])
    return inputs


def _overlap(a: Sequence[Span], b: Sequence[Span]) -> bool:
    return any(x[0] < y[1] and y[0] < x[1] for x in a for y in b)


def _check_no_edges(regions: Sequence[ChecksumRegion]) -> None:
    """R32: no dependency edge between a Python region and a descriptor region."""
    by_name = {r.name: r.descriptor for r in regions if r.descriptor is not None}
    stores = chain_stores(list(by_name.values()))
    fields = recalculable_fields(regions)
    python = [r for r in regions if r.descriptor is None and r.kind == "recalculable"]
    for p in python:
        p_fields = [(s, e) for (m, s, e), name in fields.items() if name == p.name and m == p.memory_id]
        for name, d in by_name.items():
            if d.memory_id != p.memory_id:
                continue
            d_fields = [(s, e) for (m, s, e), owner in fields.items() if owner == name and m == d.memory_id]
            edge = _overlap(_spans(p.covered or ()), d_fields) or _overlap(_static_inputs(d, stores), p_fields)
            require(not edge, "r32", f"{p.name} and {name}")


def check_checksums(regions: object, ident: Identification, layout: MemoryLayout) -> tuple[ChecksumRegion, ...]:
    """R30-R33 and the static validation of R31 (R79) on the result of `checksums(ident)`.

    `layout` is `layout(ident, dump.dump_kind)` of the dump being processed, checked by `check_layout`.
    """
    checked = check_regions(regions)
    if ident.checksum_variant_id is None:
        require(not checked, "r30", "unknown_variant has no checksum regions")
    present = {memory.memory_id for memory in ident.memories_present}
    for region in checked:
        require(region.memory_id in present, "r30", f"{region.name}: memory {region.memory_id} is absent")
    validate_variant(checked, layout)
    keys = [(region.memory_id, region.name) for region in checked]
    require(keys == sorted(keys), "r30", "regions sorted by (memory_id, name)")
    _check_no_edges(checked)
    return checked


def reference_result_usable(region: ChecksumRegion, result: object) -> bool:
    """R45: an independent reference returns only `ok` or `fail` for this region; otherwise it is unavailable."""
    return (
        isinstance(result, RegionResult)
        and (result.name, result.memory_id, result.kind) == (region.name, region.memory_id, region.kind)
        and result.status in ("ok", "fail")
        and result.bypass is None
    )


def _agrees(plugin: RegionResult | None, reference: RegionResult) -> bool:
    same = plugin is not None and (plugin.stored, plugin.computed, plugin.reason) == (
        reference.stored,
        reference.computed,
        reference.reason,
    )
    return same and plugin is not None and plugin.status in (reference.status, "bypassed")


def compare_verify(
    regions: Sequence[ChecksumRegion],
    report: VerifyReport,
    dump: Dump,
    layout: MemoryLayout,
    independent: Mapping[str, RegionResult],
) -> None:
    """R45. `report` passed `check_verify_report`; `independent` holds, by region name, the usable result
    (`reference_result_usable`) of every region whose reference is `independent`."""
    if report.status == "not_applicable":
        return
    reference = interpret_verify(regions, dump, layout)
    for region in regions:
        if region.reference.kind == "independent":
            reference[region.name] = independent[region.name]
    plugin = {result.name: result for result in report.regions}
    differing = sorted(name for name, result in reference.items() if not _agrees(plugin.get(name), result))
    require(not differing, "plugin_disagreement", ",".join(differing))


def _owners(patches: Sequence[Patch], fields: Mapping[tuple[str, int, int], str]) -> dict[str, set[str]]:
    owned: dict[str, set[str]] = {}
    for patch in patches:
        for (memory_id, start, end), name in fields.items():
            if memory_id == patch.memory_id and start < patch.end and patch.offset < end:
                owned.setdefault(name, set()).add(patch.patch_hash)
    return owned


def compare_patches(
    regions: Sequence[ChecksumRegion],
    patches: Sequence[Patch],
    dump: Dump,
    layout: MemoryLayout,
    independent: Mapping[str, Sequence[Patch]],
) -> None:
    """R55. `patches` passed `check_checksum_patches`; `independent` holds `patches_region` by region name.

    A resolution failure of the core derivation propagates as `DescriptorError` (R66).
    """
    reference = list(interpret_patches(regions, dump, layout))
    for region in regions:
        if region.reference.kind == "independent":
            reference += independent[region.name]
    fields = recalculable_fields(regions)
    compared = {region.name for region in regions if region.reference.kind != "none"}
    mine, theirs = _owners(patches, fields), _owners(reference, fields)
    differing = sorted(name for name in compared if mine.get(name, set()) != theirs.get(name, set()))
    require(not differing, "plugin_disagreement", ",".join(differing))
