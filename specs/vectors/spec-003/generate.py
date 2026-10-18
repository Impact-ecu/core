"""Generate SPEC-003 test vectors.

Independent of the core. JCS comes from the third-party `rfc8785` package (pinned in requirements.txt),
SHA-256 from hashlib. Expected definitions, including the one imported from the synthetic XDF and its export,
are hand-written JSON literals below, never produced by an importer or exporter. Conversions use
fractions.Fraction and struct with explicit byte order; a few values are also asserted by hand.
Every definition, name, address and factor here is synthetic (SPEC-003 R47).
Run: python -I generate.py > vectors.json   then   python -I crosscheck.py vectors.json
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import struct
import sys
from fractions import Fraction

import rfc8785


def h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def jhash(obj: object) -> str:
    return h(rfc8785.dumps(obj))


def rat(q: Fraction) -> str:
    return str(q.numerator) if q.denominator == 1 else f"{q.numerator}/{q.denominator}"


def derived_id(prefix: str, memory_id: str, name: str, offset: int) -> str:
    return prefix + jhash({"memory_id": memory_id, "name": name, "offset": offset})[:24]


def dtype(kind: str, bits: int, byte_order: str) -> dict[str, object]:
    return {"kind": kind, "bits": bits, "byte_order": byte_order}


def scaling(factor: str, addend: str) -> dict[str, str]:
    return {"factor": factor, "addend": addend}


# ---------------------------------------------------------------- rationals (R3, R74, R91)

RATIONALS = [
    {"id": "Q1", "grammar": "xdf_decimal", "text": "0.000123", "expect": {"value": "123/1000000"}},
    {"id": "Q2", "grammar": "a2l_number", "text": "256.000000", "expect": {"value": "256"}},
    {"id": "Q3", "grammar": "a2l_number", "text": "-0.5", "expect": {"value": "-1/2"}},
    {"id": "Q4", "grammar": "a2l_number", "text": "1.5e-3", "expect": {"value": "3/2000"}},
    {"id": "Q5", "grammar": "a2l_number", "text": "-0", "expect": {"value": "0"}},
    {"id": "Q6", "grammar": "a2l_number", "text": "1E3", "expect": {"value": "1000"}},
    {"id": "Q7", "grammar": "xdf_decimal", "text": "0.10", "expect": {"value": "1/10"}},
    {"id": "Q8", "grammar": "xdf_decimal", "text": "1.5e-3", "expect": {"error": "bad_number"}},
    {"id": "Q9", "grammar": "a2l_number", "text": "1e", "expect": {"error": "bad_number"}},
    {"id": "Q10", "grammar": "a2l_number", "text": "0x10", "expect": {"error": "bad_number"}},
    {"id": "Q11", "grammar": "xdf_decimal", "text": "-2.50", "expect": {"value": "-5/2"}},
    {"id": "Q12", "grammar": "rational_text", "text": "-7/4", "expect": {"value": "-7/4"}},
    {"id": "Q13", "grammar": "rational_text", "text": "2/4", "expect": {"error": "bad_rational"}},
    {"id": "Q14", "grammar": "rational_text", "text": "3/1", "expect": {"error": "bad_rational"}},
    {"id": "Q15", "grammar": "rational_text", "text": "-0", "expect": {"error": "bad_rational"}},
    {"id": "Q16", "grammar": "rational_text", "text": "1/0", "expect": {"error": "bad_rational"}},
]

# ---------------------------------------------------------------- decoding (R6, R7, R12)

INT_FMT = {(8, False): "B", (8, True): "b", (16, False): "H", (16, True): "h", (32, False): "I", (32, True): "i"}


def decode(dt: dict[str, object], data: bytes) -> Fraction | None:
    bits = int(str(dt["bits"]))
    order = "<" if dt["byte_order"] == "le" else ">"
    if dt["kind"] == "float":
        if data[0 if order == ">" else 3] & 0x7F == 0x7F and data[1 if order == ">" else 2] & 0x80:
            return None
        return Fraction(struct.unpack(order + "f", data)[0])
    return Fraction(struct.unpack(order + INT_FMT[(bits, dt["kind"] == "int")], data)[0])


DECODE_CASES = [
    ("C1", dtype("uint", 8, "none"), "ff", scaling("1", "0")),
    ("C2", dtype("int", 8, "none"), "80", scaling("3/4", "0")),
    ("C3", dtype("uint", 16, "le"), "3412", scaling("1/4", "0")),
    ("C4", dtype("uint", 16, "be"), "1234", scaling("1/4", "0")),
    ("C5", dtype("int", 16, "be"), "fffe", scaling("1/10", "5")),
    ("C6", dtype("int", 16, "le"), "0080", scaling("1", "0")),
    ("C7", dtype("uint", 32, "be"), "deadbeef", scaling("1", "0")),
    ("C8", dtype("int", 32, "le"), "ffffffff", scaling("1/250", "1/2")),
    ("C9", dtype("float", 32, "be"), "3fc00000", scaling("1", "0")),
    ("C10", dtype("float", 32, "le"), "0000c03f", scaling("1", "0")),
    ("C11", dtype("float", 32, "be"), "3dcccccd", scaling("1", "0")),
    ("C12", dtype("float", 32, "be"), "80000000", scaling("1", "0")),
    ("C13", dtype("float", 32, "be"), "00000001", scaling("1", "0")),
    ("C14", dtype("float", 32, "be"), "7f7fffff", scaling("2", "-1")),
    ("C15", dtype("float", 32, "be"), "7f800000", scaling("1", "0")),
    ("C16", dtype("float", 32, "le"), "0000c07f", scaling("1", "0")),
]


def decode_vectors() -> list[dict[str, object]]:
    out = []
    for cid, dt, hexs, sc in DECODE_CASES:
        raw = decode(dt, bytes.fromhex(hexs))
        if raw is None:
            expect: dict[str, object] = {"raw": "non_finite", "physical": "non_finite"}
        else:
            phys = Fraction(sc["factor"]) * raw + Fraction(sc["addend"])
            expect = {"raw": rat(raw), "physical": rat(phys)}
        out.append({"id": cid, "rules": ["R6", "R7", "R12"], "dtype": dt, "bytes_hex": hexs, "scaling": sc,
                    "expect": expect})
    return out


# ---------------------------------------------------------------- encoding (R13, R15)

def round_half_even(q: Fraction) -> int:
    fl = q.numerator // q.denominator
    rem = q - fl
    if rem > Fraction(1, 2) or (rem == Fraction(1, 2) and fl % 2 == 1):
        return fl + 1
    return fl


def f32_from_rational(q: Fraction) -> int | None:
    """Exact roundTiesToEven of a rational to binary32 bits; None on overflow."""
    if q == 0:
        return 0
    sign = 0x80000000 if q < 0 else 0
    a = abs(q)
    e = a.numerator.bit_length() - a.denominator.bit_length()
    if Fraction(2) ** e > a:
        e -= 1
    # now 2^e <= a < 2^(e+1)
    if e < -126:
        m = round_half_even(a / Fraction(2) ** -149)  # subnormal grid
        if m == 0:
            return 0  # R13: zero encodes as +0, also when a negative value rounds to zero
        if m >= 1 << 23:
            return sign | (1 << 23) if m == 1 << 23 else None
        return sign | m
    m = round_half_even(a / Fraction(2) ** (e - 23))
    if m == 1 << 24:
        m >>= 1
        e += 1
    if e > 127:
        return None
    return sign | ((e + 127) << 23) | (m - (1 << 23))


def encode(dt: dict[str, object], sc: dict[str, str], target: Fraction, current: bytes | None) -> bytes | str:
    if current is not None:
        cur_raw = decode(dt, current)
        if cur_raw is not None and Fraction(sc["factor"]) * cur_raw + Fraction(sc["addend"]) == target:
            return current  # R15: compared in physical units
    q = (target - Fraction(sc["addend"])) / Fraction(sc["factor"])
    order = "<" if dt["byte_order"] == "le" else ">"
    bits = int(str(dt["bits"]))
    if dt["kind"] == "float":
        b = f32_from_rational(q)
        if b is None:
            return "out_of_range"
        return struct.pack(order + "I", b)
    r = round_half_even(q)
    lo, hi = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if dt["kind"] == "int" else (0, (1 << bits) - 1)
    if not lo <= r <= hi:
        return "out_of_range"
    return struct.pack(order + INT_FMT[(bits, dt["kind"] == "int")], r)


ONE_PLUS = Fraction(1)
ENCODE_CASES = [
    ("E1", dtype("uint", 8, "none"), scaling("2", "0"), Fraction(3), None),
    ("E2", dtype("uint", 8, "none"), scaling("2", "0"), Fraction(5), None),
    ("E3", dtype("uint", 8, "none"), scaling("2", "0"), Fraction(7), None),
    ("E4", dtype("int", 8, "none"), scaling("1", "0"), Fraction(-129), None),
    ("E5", dtype("uint", 16, "le"), scaling("1/4", "0"), Fraction(1165), None),
    ("E6", dtype("int", 16, "be"), scaling("1/10", "5"), Fraction(24, 5), None),
    ("E7", dtype("float", 32, "be"), scaling("1", "0"), Fraction(3, 2), None),
    ("E8", dtype("float", 32, "be"), scaling("1", "0"), 1 + Fraction(1, 2**24), None),
    ("E9", dtype("float", 32, "be"), scaling("1", "0"), 1 + Fraction(3, 2**24), None),
    ("E10", dtype("float", 32, "be"), scaling("1", "0"), Fraction(1, 10), None),
    ("E11", dtype("float", 32, "be"), scaling("1", "0"), Fraction(2**128 - 2**103), None),
    ("E12", dtype("float", 32, "be"), scaling("1", "0"), Fraction(2**128 - 2**103 - 1), None),
    ("E13", dtype("float", 32, "be"), scaling("1", "0"), Fraction(0), bytes.fromhex("80000000")),
    ("E14", dtype("uint", 8, "none"), scaling("1", "0"), Fraction(256), None),
    ("E15", dtype("float", 32, "le"), scaling("1", "0"), Fraction(1, 2**150), None),
    ("E16", dtype("int", 16, "le"), scaling("-1/2", "0"), Fraction(3, 4), None),
    ("E17", dtype("float", 32, "be"), scaling("1", "0"), Fraction(-3, 2**150), None),
    ("E18", dtype("float", 32, "be"), scaling("1", "0"), Fraction(-1, 2**151), None),
    ("E19", dtype("float", 32, "be"), scaling("2", "5"), Fraction(5), bytes.fromhex("80000000")),
]


def encode_vectors() -> list[dict[str, object]]:
    out = []
    for cid, dt, sc, target, cur in ENCODE_CASES:
        res = encode(dt, sc, target, cur)
        expect = {"error": res} if isinstance(res, str) else {"bytes_hex": res.hex()}
        out.append({"id": cid, "rules": ["R13", "R14", "R15"], "dtype": dt, "scaling": sc, "target": rat(target),
                    "current_hex": None if cur is None else cur.hex(), "expect": expect})
    return out


# ---------------------------------------------------------------- units (R16, R17)

UNITS = [
    {"id": "U1", "unit_text": "us", "scaling": scaling("4", "500"),
     "expect": {"unit": "ms", "unit_text": None, "scaling": scaling("1/250", "1/2")}},
    {"id": "U2", "unit_text": "1/min", "scaling": scaling("1/4", "0"),
     "expect": {"unit": "rpm", "unit_text": None, "scaling": scaling("1/4", "0")}},
    {"id": "U3", "unit_text": "kPa", "scaling": scaling("1", "0"),
     "expect": {"unit": None, "unit_text": "kPa", "scaling": scaling("1", "0")}},
    {"id": "U4", "unit_text": "°C", "scaling": scaling("3/4", "-48"),
     "expect": {"unit": "degC", "unit_text": None, "scaling": scaling("3/4", "-48")}},
    {"id": "U5", "unit_text": "s", "scaling": scaling("1/1000", "0"),
     "expect": {"unit": "ms", "unit_text": None, "scaling": scaling("1", "0")}},
    {"id": "U6", "unit_text": "RPM", "scaling": scaling("1", "0"),
     "expect": {"unit": None, "unit_text": "RPM", "scaling": scaling("1", "0")}},
    # R17: the alias s -> ms (k = 1000) would give factor 1000/3, which XDF cannot export (R76): not applied.
    {"id": "U7", "unit_text": "s", "scaling": scaling("1/3", "0"),
     "expect": {"unit": None, "unit_text": "s", "scaling": scaling("1/3", "0")}},
]

# ---------------------------------------------------------------- A2L conversion (R90, R99)

A2L_COMPU = [
    {"id": "A1a", "conversion_type": "IDENTICAL", "coeffs": [], "expect": {"scaling": scaling("1", "0")}},
    {"id": "A1b", "conversion_type": "LINEAR", "coeffs": ["0.75", "-48"], "expect": {"scaling": scaling("3/4", "-48")}},
    {"id": "A1c", "conversion_type": "RAT_FUNC", "coeffs": ["0", "64.000000", "0.000000", "0", "0.000000", "5.000000"],
     "expect": {"scaling": scaling("5/64", "0")}},
    {"id": "A1d", "conversion_type": "RAT_FUNC", "coeffs": ["0", "2", "-10", "0", "0", "1"],
     "expect": {"scaling": scaling("1/2", "5")}},
    {"id": "A1e", "conversion_type": "RAT_FUNC", "coeffs": ["1", "2", "0", "0", "0", "1"],
     "expect": {"error": "unsupported_conversion"}},
    {"id": "A1f", "conversion_type": "RAT_FUNC", "coeffs": ["0", "0", "1", "0", "0", "1"],
     "expect": {"error": "unsupported_conversion"}},
    {"id": "A1g", "conversion_type": "RAT_FUNC", "coeffs": ["0", "1", "0", "0", "1", "0"],
     "expect": {"error": "unsupported_conversion"}},
    {"id": "A1h", "conversion_type": "LINEAR", "coeffs": ["0", "5"], "expect": {"error": "zero_factor"}},
    {"id": "A1i", "conversion_type": "TAB_VERB", "coeffs": [], "expect": {"error": "unsupported_conversion"}},
    {"id": "A1j", "conversion_type": "FORM", "coeffs": [], "expect": {"error": "unsupported_conversion"}},
]

A2L_EXPORT = [
    {"id": "A2a", "scaling": scaling("2/5", "50"), "expect": {"coeffs": [0, 5, -250, 0, 0, 2]}},
    {"id": "A2b", "scaling": scaling("1/250", "1/2"), "expect": {"coeffs": [0, 250, -125, 0, 0, 1]}},
    {"id": "A2c", "scaling": scaling("-3/4", "-48"), "expect": {"coeffs": [0, 4, 192, 0, 0, -3]}},
    {"id": "A2d", "scaling": scaling("1", "0"), "expect": {"coeffs": [0, 1, 0, 0, 0, 1]}},
]

# ---------------------------------------------------------------- MapDef and Definition (R20-R38, R51, R52)

M2_ID = derived_id("m_", "cal", "SYN_SCALAR", 128)

M1 = {
    "map_id": "syn.scalar", "name": "SYN_SCALAR", "category": None, "map_type": None, "state": "proposed",
    "memory_id": "cal", "offset": 128, "dims": {"rows": 1, "cols": 1}, "cell_order": "x_fastest",
    "dtype": dtype("uint", 8, "none"), "scaling": scaling("1", "0"), "unit": "one", "unit_text": None,
    "axes": {"x": None, "y": None},
}
M2 = dict(M1, map_id=M2_ID)

AX_SHARED = {"axis_id": "syn.rpm_axis", "name": "SYN_RPM_AXIS",
             "axis": {"axis_source": "inline", "memory_id": "cal", "offset": 512, "count": 4,
                      "dtype": dtype("uint", 16, "be"), "scaling": scaling("25", "0"), "unit": "rpm", "unit_text": None}}

MAP_IGN = {
    "map_id": "syn.ign_base", "name": "Zündwinkel Basis", "category": "ignition", "map_type": "base",
    "state": "reviewed", "memory_id": "cal", "offset": 0, "dims": {"rows": 3, "cols": 4}, "cell_order": "y_fastest",
    "dtype": dtype("int", 8, "none"), "scaling": scaling("3/4", "0"), "unit": "deg_crank", "unit_text": None,
    "axes": {"x": {"axis_source": "shared", "axis_id": "syn.rpm_axis"},
             "y": {"axis_source": "fixed", "values": ["20", "121/2", "100"], "unit": "kPa_rel", "unit_text": None}},
}
MAP_DEAD = {
    "map_id": "syn.dead_time", "name": "SYN_DEAD_TIME", "category": "injector_dead_time", "map_type": "base",
    "state": "proposed", "memory_id": "cal", "offset": 16, "dims": {"rows": 1, "cols": 1}, "cell_order": "x_fastest",
    "dtype": dtype("uint", 16, "le"), "scaling": scaling("1/250", "1/2"), "unit": "ms", "unit_text": None,
    "axes": {"x": None, "y": None},
}
MAP_VVT = {
    "map_id": "syn.vvt_ptr", "name": "SYN_VVT", "category": "vvt", "map_type": "base", "state": "potential",
    "memory_id": "cal", "offset": 48, "dims": {"rows": 1, "cols": 2}, "cell_order": "x_fastest",
    "dtype": dtype("int", 16, "be"), "scaling": scaling("1/16", "0"), "unit": "deg_crank", "unit_text": None,
    "axes": {"x": {"axis_source": "pointer", "memory_id": "pflash", "pointer_offset": 16,
                   "pointer_dtype": dtype("uint", 32, "be"), "target_memory_id": "cal", "count": 2,
                   "dtype": dtype("uint", 8, "none"), "scaling": scaling("50", "0"), "unit": "rpm", "unit_text": None},
             "y": None},
}
MAP_LAM = {
    "map_id": "syn.lambda_target", "name": "SYN_LAMBDA_TARGET", "category": "lambda", "map_type": "base",
    "state": "golden", "memory_id": "cal", "offset": 96, "dims": {"rows": 1, "cols": 4}, "cell_order": "x_fastest",
    "dtype": dtype("uint", 16, "be"), "scaling": scaling("1/1000", "0"), "unit": "lambda", "unit_text": None,
    "axes": {"x": {"axis_source": "shared", "axis_id": "syn.rpm_axis"}, "y": None},
}


def definition(mapdefs: list[dict[str, object]], axes: list[dict[str, object]]) -> dict[str, object]:
    return {
        "spec": "SPEC-003/1", "family_id": "synthetic.test",
        "software_version": {"match": "exact", "values": ["SYN0001", "SYN0002"]},
        "axes": axes, "mapdefs": mapdefs,
        "origin": {"kind": "platform", "derived_from": []},
        "license": {"kind": "platform_created", "reference": None},
        "confidence_permille": 900,
    }


D1 = definition(sorted([MAP_IGN, MAP_DEAD, MAP_VVT, MAP_LAM], key=lambda m: str(m["map_id"])), [AX_SHARED])
D2_INPUT = definition([MAP_LAM, MAP_VVT, MAP_IGN, MAP_DEAD], [AX_SHARED])
D3 = definition(sorted([dict(MAP_IGN, state="proposed"), MAP_DEAD, MAP_VVT, MAP_LAM], key=lambda m: str(m["map_id"])),
                [AX_SHARED])

# ---------------------------------------------------------------- span (R22, R30)

# Synthetic dump: zero-filled memories, plus the bytes listed. The pointer of MAP_VVT (pflash offset 16, uint32 be)
# holds 0x80010100; cal starts at 0x80010000, so the breakpoints are at cal offset 0x100 = 256 (R22).
SPAN_DUMP = {
    "memories": [{"memory_id": "cal", "base_address": 0x80010000, "size": 1024},
                 {"memory_id": "pflash", "base_address": 0x80000000, "size": 64}],
    "bytes": [{"memory_id": "pflash", "offset": 16, "hex": "80010100"}],
}


def rng(memory_id: str, start: int, end: int) -> dict[str, object]:
    return {"memory_id": memory_id, "start": start, "end": end}


# Hand-computed spans: cells, then each axis however reached; sorted by (memory_id, start), merged.
SPANS = {
    "syn.dead_time": [rng("cal", 16, 18)],
    "syn.ign_base": [rng("cal", 0, 12), rng("cal", 512, 520)],            # 3x4 int8 cells; shared rpm axis; fixed y
    "syn.lambda_target": [rng("cal", 96, 104), rng("cal", 512, 520)],    # 4 uint16 cells; shared rpm axis
    "syn.vvt_ptr": [rng("cal", 48, 52), rng("cal", 256, 258), rng("pflash", 16, 20)],  # cells, target, pointer
}

# S2: a pointer axis whose target memory is absent from the dump -> unknown_memory (R55), never a crash.
SPAN_FAR_DEFINITION = {
    "spec": "SPEC-003/1", "family_id": "synthetic.test", "software_version": {"match": "exact", "values": ["SYN0001"]},
    "axes": [],
    "mapdefs": [{
        "map_id": "syn.far_pointer", "name": "SYN_FAR_POINTER", "category": None, "map_type": None,
        "state": "proposed", "memory_id": "pflash", "offset": 0, "dims": {"rows": 1, "cols": 2},
        "cell_order": "x_fastest", "dtype": dtype("uint", 8, "none"), "scaling": scaling("1", "0"),
        "unit": None, "unit_text": "",
        "axes": {"x": {"axis_source": "pointer", "memory_id": "pflash", "pointer_offset": 16,
                       "pointer_dtype": dtype("uint", 32, "be"), "target_memory_id": "dflash", "count": 2,
                       "dtype": dtype("uint", 8, "none"), "scaling": scaling("1", "0"), "unit": None,
                       "unit_text": ""}, "y": None},
    }],
    "origin": {"kind": "platform", "derived_from": []},
    "license": {"kind": "platform_created", "reference": None}, "confidence_permille": 0,
}

# ---------------------------------------------------------------- XDF (R61-R64, R70-R80)

XDF_SOURCE = """<?xml version="1.0" encoding="UTF-8"?>
<XDFFORMAT version="1.60">
  <XDFHEADER>
    <deftitle>Synthetic test definition</deftitle>
    <description>Synthetic. Not derived from any ECU or third-party file.</description>
    <BASEOFFSET offset="0" subtract="0" />
    <DEFAULTS datasizeinbits="8" sigdigits="2" outputtype="1" signed="0" lsbfirst="0" float="0" />
    <CATEGORY index="0x0" name="Synthetic" />
  </XDFHEADER>
  <XDFCONSTANT uniqueid="0x101">
    <title>SYN_DEAD_TIME</title>
    <CATEGORYMEM index="0" category="1" />
    <EMBEDDEDDATA mmedtypeflags="0x02" mmedaddress="0x10" mmedelementsizebits="16" mmedmajorstridebits="0" mmedminorstridebits="0" />
    <units>us</units>
    <decimalpl>1</decimalpl>
    <MATH equation="X*4+500">
      <VAR id="X" />
    </MATH>
  </XDFCONSTANT>
  <XDFTABLE uniqueid="0x102" flags="0x0">
    <title>SYN_IGN_BASE</title>
    <CATEGORYMEM index="0" category="1" />
    <XDFAXIS id="x" uniqueid="0x0">
      <EMBEDDEDDATA mmedtypeflags="0x02" mmedaddress="0x20" mmedelementsizebits="16" mmedmajorstridebits="0" mmedminorstridebits="0" />
      <indexcount>4</indexcount>
      <units>1/min</units>
      <DALINK index="0" />
      <MATH equation="X/4">
        <VAR id="X" />
      </MATH>
    </XDFAXIS>
    <XDFAXIS id="y" uniqueid="0x0">
      <EMBEDDEDDATA mmedelementsizebits="8" mmedmajorstridebits="0" mmedminorstridebits="0" />
      <indexcount>3</indexcount>
      <units>kPa</units>
      <LABEL index="0" value="20.0" />
      <LABEL index="1" value="60.5" />
      <LABEL index="2" value="100" />
      <MATH equation="X">
        <VAR id="X" />
      </MATH>
    </XDFAXIS>
    <XDFAXIS id="z">
      <EMBEDDEDDATA mmedtypeflags="0x01" mmedaddress="0x40" mmedelementsizebits="8" mmedrowcount="3" mmedcolcount="4" mmedmajorstridebits="0" mmedminorstridebits="0" />
      <units>°</units>
      <decimalpl>2</decimalpl>
      <min>-20.000000</min>
      <max>60.000000</max>
      <MATH equation="0.000000+X*0.75">
        <VAR id="X" />
      </MATH>
    </XDFAXIS>
  </XDFTABLE>
  <XDFCHECKSUM uniqueid="0x103">
    <title>SYN_CHECKSUM</title>
  </XDFCHECKSUM>
</XDFFORMAT>
"""

XDF_PARAMS = {
    "family_id": "synthetic.test", "software_version": {"match": "exact", "values": ["SYN0001"]},
    "memory_id": "cal", "license": {"kind": "unverified", "reference": None}, "confidence_permille": 0,
}

XDF_CONST = {
    "map_id": derived_id("m_", "cal", "SYN_DEAD_TIME", 16), "name": "SYN_DEAD_TIME", "category": None,
    "map_type": None, "state": "imported", "memory_id": "cal", "offset": 16, "dims": {"rows": 1, "cols": 1},
    "cell_order": "x_fastest", "dtype": dtype("uint", 16, "le"), "scaling": scaling("1/250", "1/2"),
    "unit": "ms", "unit_text": None, "axes": {"x": None, "y": None},
}
XDF_TABLE = {
    "map_id": derived_id("m_", "cal", "SYN_IGN_BASE", 64), "name": "SYN_IGN_BASE", "category": None,
    "map_type": None, "state": "imported", "memory_id": "cal", "offset": 64, "dims": {"rows": 3, "cols": 4},
    "cell_order": "x_fastest", "dtype": dtype("int", 8, "none"), "scaling": scaling("3/4", "0"),
    "unit": None, "unit_text": "°",
    "axes": {"x": {"axis_source": "inline", "memory_id": "cal", "offset": 32, "count": 4,
                   "dtype": dtype("uint", 16, "le"), "scaling": scaling("1/4", "0"), "unit": "rpm", "unit_text": None},
             "y": {"axis_source": "fixed", "values": ["20", "121/2", "100"], "unit": None, "unit_text": "kPa"}},
}
XDF_DEFINITION = {
    "spec": "SPEC-003/1", "family_id": "synthetic.test",
    "software_version": {"match": "exact", "values": ["SYN0001"]},
    "axes": [], "mapdefs": sorted([XDF_CONST, XDF_TABLE], key=lambda m: str(m["map_id"])),
    "origin": {"kind": "xdf_import", "derived_from": []},
    "license": {"kind": "unverified", "reference": None}, "confidence_permille": 0,
}
XDF_REJECTED = [{"path": "XDFFORMAT[0]/XDFCHECKSUM[0]", "reason": "unsupported_element"}]
XDF_IGNORED = sorted([
    "XDFFORMAT[0]/@version",
    "XDFFORMAT[0]/XDFHEADER[0]/deftitle[0]",
    "XDFFORMAT[0]/XDFHEADER[0]/description[0]",
    "XDFFORMAT[0]/XDFHEADER[0]/DEFAULTS[0]/@datasizeinbits",
    "XDFFORMAT[0]/XDFHEADER[0]/DEFAULTS[0]/@sigdigits",
    "XDFFORMAT[0]/XDFHEADER[0]/DEFAULTS[0]/@outputtype",
    "XDFFORMAT[0]/XDFHEADER[0]/CATEGORY[0]",
    "XDFFORMAT[0]/XDFCONSTANT[0]/@uniqueid",
    "XDFFORMAT[0]/XDFCONSTANT[0]/CATEGORYMEM[0]",
    "XDFFORMAT[0]/XDFCONSTANT[0]/decimalpl[0]",
    "XDFFORMAT[0]/XDFTABLE[0]/@uniqueid",
    "XDFFORMAT[0]/XDFTABLE[0]/CATEGORYMEM[0]",
    "XDFFORMAT[0]/XDFTABLE[0]/XDFAXIS[0]/@uniqueid",
    "XDFFORMAT[0]/XDFTABLE[0]/XDFAXIS[0]/DALINK[0]",
    "XDFFORMAT[0]/XDFTABLE[0]/XDFAXIS[1]/@uniqueid",
    "XDFFORMAT[0]/XDFTABLE[0]/XDFAXIS[1]/EMBEDDEDDATA[0]/@mmedelementsizebits",
    "XDFFORMAT[0]/XDFTABLE[0]/XDFAXIS[1]/EMBEDDEDDATA[0]/@mmedmajorstridebits",
    "XDFFORMAT[0]/XDFTABLE[0]/XDFAXIS[1]/EMBEDDEDDATA[0]/@mmedminorstridebits",
    "XDFFORMAT[0]/XDFTABLE[0]/XDFAXIS[2]/decimalpl[0]",
    "XDFFORMAT[0]/XDFTABLE[0]/XDFAXIS[2]/min[0]",
    "XDFFORMAT[0]/XDFTABLE[0]/XDFAXIS[2]/max[0]",
])

XDF_EXPORT_CONST = """  <XDFCONSTANT>
    <title>SYN_DEAD_TIME</title>
    <EMBEDDEDDATA mmedtypeflags="0x02" mmedaddress="0x10" mmedelementsizebits="16" />
    <units>ms</units>
    <MATH equation="X*0.004+0.5">
      <VAR id="X" />
    </MATH>
  </XDFCONSTANT>
"""
XDF_EXPORT_TABLE = """  <XDFTABLE>
    <title>SYN_IGN_BASE</title>
    <XDFAXIS id="x">
      <EMBEDDEDDATA mmedtypeflags="0x02" mmedaddress="0x20" mmedelementsizebits="16" />
      <indexcount>4</indexcount>
      <units>rpm</units>
      <MATH equation="X*0.25">
        <VAR id="X" />
      </MATH>
    </XDFAXIS>
    <XDFAXIS id="y">
      <indexcount>3</indexcount>
      <units>kPa</units>
      <LABEL index="0" value="20" />
      <LABEL index="1" value="60.5" />
      <LABEL index="2" value="100" />
    </XDFAXIS>
    <XDFAXIS id="z">
      <EMBEDDEDDATA mmedtypeflags="0x01" mmedaddress="0x40" mmedelementsizebits="8" mmedrowcount="3" mmedcolcount="4" />
      <units>°</units>
      <MATH equation="X*0.75">
        <VAR id="X" />
      </MATH>
    </XDFAXIS>
  </XDFTABLE>
"""


def xdf_export_text() -> str:
    parts = {str(XDF_CONST["map_id"]): XDF_EXPORT_CONST, str(XDF_TABLE["map_id"]): XDF_EXPORT_TABLE}
    body = "".join(parts[k] for k in sorted(parts))
    return '<?xml version="1.0" encoding="UTF-8"?>\n<XDFFORMAT>\n' + body + "</XDFFORMAT>\n"


# XE1: a definition already in import-normal form (R64), exported per R76/R77 and re-imported.
XE_PARAMS = dict(XDF_PARAMS, memory_id="cal")
XE_CONST = {
    "map_id": derived_id("m_", "cal", "SYN_COOLANT_OFFSET", 512), "name": "SYN_COOLANT_OFFSET", "category": None,
    "map_type": None, "state": "imported", "memory_id": "cal", "offset": 512, "dims": {"rows": 1, "cols": 1},
    "cell_order": "x_fastest", "dtype": dtype("uint", 8, "none"), "scaling": scaling("1", "-40"),
    "unit": "degC", "unit_text": None, "axes": {"x": None, "y": None},
}
XE_CELL = {
    "map_id": derived_id("m_", "cal", "SYN_SINGLE_CELL", 528), "name": "SYN_SINGLE_CELL", "category": None,
    "map_type": None, "state": "imported", "memory_id": "cal", "offset": 528, "dims": {"rows": 1, "cols": 1},
    "cell_order": "x_fastest", "dtype": dtype("uint", 16, "be"), "scaling": scaling("1", "1/2"),
    "unit": None, "unit_text": "",
    "axes": {"x": {"axis_source": "fixed", "values": ["7"], "unit": None, "unit_text": ""}, "y": None},
}
XE_DEFINITION = {
    "spec": "SPEC-003/1", "family_id": "synthetic.test",
    "software_version": {"match": "exact", "values": ["SYN0001"]},
    "axes": [], "mapdefs": sorted([XE_CONST, XE_CELL], key=lambda m: str(m["map_id"])),
    "origin": {"kind": "xdf_import", "derived_from": []},
    "license": {"kind": "unverified", "reference": None}, "confidence_permille": 0,
}
XE_PART_CONST = """  <XDFCONSTANT>
    <title>SYN_COOLANT_OFFSET</title>
    <EMBEDDEDDATA mmedtypeflags="0x00" mmedaddress="0x200" mmedelementsizebits="8" />
    <units>degC</units>
    <MATH equation="X-40">
      <VAR id="X" />
    </MATH>
  </XDFCONSTANT>
"""
XE_PART_CELL = """  <XDFTABLE>
    <title>SYN_SINGLE_CELL</title>
    <XDFAXIS id="x">
      <indexcount>1</indexcount>
      <LABEL index="0" value="7" />
    </XDFAXIS>
    <XDFAXIS id="z">
      <EMBEDDEDDATA mmedtypeflags="0x00" mmedaddress="0x210" mmedelementsizebits="16" mmedrowcount="1" mmedcolcount="1" />
      <MATH equation="X+0.5">
        <VAR id="X" />
      </MATH>
    </XDFAXIS>
  </XDFTABLE>
"""


def xe_export_text() -> str:
    parts = {str(XE_CONST["map_id"]): XE_PART_CONST, str(XE_CELL["map_id"]): XE_PART_CELL}
    body = "".join(parts[k] for k in sorted(parts))
    return '<?xml version="1.0" encoding="UTF-8"?>\n<XDFFORMAT>\n' + body + "</XDFFORMAT>\n"


# XN1: a platform-form definition (non-derived map_ids, reviewed/golden states, categories, P-independent
# family, versions, origin, license, confidence) exported per R76/R77; re-import equals normalize(e, P) (R64).
NE_CURVE = {
    "map_id": "syn.dead_time_curve", "name": "SYN_DEAD_TIME_CURVE", "category": "injector_dead_time",
    "map_type": "base", "state": "reviewed", "memory_id": "cal", "offset": 600, "dims": {"rows": 1, "cols": 2},
    "cell_order": "x_fastest", "dtype": dtype("uint", 16, "be"), "scaling": scaling("1/250", "1/2"),
    "unit": "ms", "unit_text": None,
    "axes": {"x": {"axis_source": "fixed", "values": ["-40", "90"], "unit": "degC", "unit_text": None}, "y": None},
}
NE_FLAG = {
    "map_id": "syn.flag", "name": "SYN_FLAG", "category": None, "map_type": "flag", "state": "golden",
    "memory_id": "cal", "offset": 620, "dims": {"rows": 1, "cols": 1}, "cell_order": "x_fastest",
    "dtype": dtype("uint", 8, "none"), "scaling": scaling("1", "0"), "unit": None, "unit_text": "",
    "axes": {"x": None, "y": None},
}
NE_DEFINITION = {
    "spec": "SPEC-003/1", "family_id": "synthetic.platform",
    "software_version": {"match": "prefix", "values": ["SYN"]},
    "axes": [], "mapdefs": [NE_CURVE, NE_FLAG],
    "origin": {"kind": "platform", "derived_from": []},
    "license": {"kind": "platform_created", "reference": None}, "confidence_permille": 900,
}
NE_EXPORT = """<?xml version="1.0" encoding="UTF-8"?>
<XDFFORMAT>
  <XDFTABLE>
    <title>SYN_DEAD_TIME_CURVE</title>
    <XDFAXIS id="x">
      <indexcount>2</indexcount>
      <units>degC</units>
      <LABEL index="0" value="-40" />
      <LABEL index="1" value="90" />
    </XDFAXIS>
    <XDFAXIS id="z">
      <EMBEDDEDDATA mmedtypeflags="0x00" mmedaddress="0x258" mmedelementsizebits="16" mmedrowcount="1" mmedcolcount="2" />
      <units>ms</units>
      <MATH equation="X*0.004+0.5">
        <VAR id="X" />
      </MATH>
    </XDFAXIS>
  </XDFTABLE>
  <XDFCONSTANT>
    <title>SYN_FLAG</title>
    <EMBEDDEDDATA mmedtypeflags="0x00" mmedaddress="0x26C" mmedelementsizebits="8" />
    <MATH equation="X">
      <VAR id="X" />
    </MATH>
  </XDFCONSTANT>
</XDFFORMAT>
"""
# normalize(e, P), written by hand: derived map_ids (R28), state imported, category/map_type null, units re-derived
# from the export text (R17), the rest from P.
NN_CURVE = dict(NE_CURVE, map_id=derived_id("m_", "cal", "SYN_DEAD_TIME_CURVE", 600), category=None, map_type=None,
                state="imported")
NN_FLAG = dict(NE_FLAG, map_id=derived_id("m_", "cal", "SYN_FLAG", 620), map_type=None, state="imported")
NN_DEFINITION = {
    "spec": "SPEC-003/1", "family_id": "synthetic.test",
    "software_version": {"match": "exact", "values": ["SYN0001"]},
    "axes": [], "mapdefs": sorted([NN_CURVE, NN_FLAG], key=lambda m: str(m["map_id"])),
    "origin": {"kind": "xdf_import", "derived_from": []},
    "license": {"kind": "unverified", "reference": None}, "confidence_permille": 0,
}

# XU1, XU2: R76 rejects a map whose axis is missing on a dimension > 1 (re-import would be dims_mismatch, R72).
XU_ROW = dict(NE_FLAG, map_id="syn.row_no_axis", name="SYN_ROW", dims={"rows": 1, "cols": 3}, state="proposed")
XU_COL = dict(NE_FLAG, map_id="syn.col_no_axis", name="SYN_COL", dims={"rows": 3, "cols": 1}, state="proposed")
# XU3-XU7: every other R76 rejection carries its field.
XU_MEM = dict(NE_FLAG, map_id="syn.other_memory", memory_id="pflash")
XU_FACTOR = dict(NE_FLAG, map_id="syn.third_factor", scaling=scaling("2/3", "0"))
XU_ADDEND = dict(NE_FLAG, map_id="syn.third_addend", scaling=scaling("1", "1/3"))
XU_LABEL = dict(NE_CURVE, map_id="syn.third_label",
                axes={"x": {"axis_source": "fixed", "values": ["1/3", "1"], "unit": "degC", "unit_text": None},
                      "y": None})
XU_POINTER = dict(NE_CURVE, map_id="syn.pointer_axis",
                  axes={"x": {"axis_source": "pointer", "memory_id": "cal", "pointer_offset": 0,
                              "pointer_dtype": dtype("uint", 32, "be"), "target_memory_id": "cal", "count": 2,
                              "dtype": dtype("uint", 8, "none"), "scaling": scaling("1", "0"), "unit": None,
                              "unit_text": ""}, "y": None})
EXPORT_REJECTS = [
    {"id": "XU1", "rules": ["R76"], "memory_id": "cal", "definition": dict(NE_DEFINITION, mapdefs=[XU_ROW]),
     "expect": {"error": "unrepresentable", "field": "axes.x"}},
    {"id": "XU2", "rules": ["R76"], "memory_id": "cal", "definition": dict(NE_DEFINITION, mapdefs=[XU_COL]),
     "expect": {"error": "unrepresentable", "field": "axes.y"}},
    {"id": "XU3", "rules": ["R76"], "memory_id": "cal", "definition": dict(NE_DEFINITION, mapdefs=[XU_MEM]),
     "expect": {"error": "unrepresentable", "field": "memory_id"}},
    {"id": "XU4", "rules": ["R76"], "memory_id": "cal", "definition": dict(NE_DEFINITION, mapdefs=[XU_FACTOR]),
     "expect": {"error": "unrepresentable", "field": "scaling.factor"}},
    {"id": "XU5", "rules": ["R76"], "memory_id": "cal", "definition": dict(NE_DEFINITION, mapdefs=[XU_ADDEND]),
     "expect": {"error": "unrepresentable", "field": "scaling.addend"}},
    {"id": "XU6", "rules": ["R76"], "memory_id": "cal", "definition": dict(NE_DEFINITION, mapdefs=[XU_LABEL]),
     "expect": {"error": "unrepresentable", "field": "axes.x.values"}},
    {"id": "XU7", "rules": ["R76"], "memory_id": "cal", "definition": dict(NE_DEFINITION, mapdefs=[XU_POINTER]),
     "expect": {"error": "unrepresentable", "field": "axes.x.axis_source"}},
]


def xdf_doc(header: str, body: str) -> str:
    return ('<?xml version="1.0" encoding="UTF-8"?>\n<XDFFORMAT>\n  <XDFHEADER>\n' + header
            + "  </XDFHEADER>\n" + body + "</XDFFORMAT>\n")


def xdf_table(title: str, x_axis: str, z_ed: str, eq: str = "X") -> str:
    return (f"  <XDFTABLE>\n    <title>{title}</title>\n{x_axis}"
            f'    <XDFAXIS id="z">\n      <EMBEDDEDDATA {z_ed} />\n'
            f'      <MATH equation="{eq}">\n        <VAR id="X" />\n      </MATH>\n    </XDFAXIS>\n  </XDFTABLE>\n')


LABEL_X = ('    <XDFAXIS id="x">\n      <indexcount>2</indexcount>\n'
           '      <LABEL index="0" value="1" />\n      <LABEL index="1" value="2" />\n    </XDFAXIS>\n')
Z_2 = 'mmedaddress="0x80" mmedelementsizebits="8" mmedrowcount="1" mmedcolcount="2"'

XDF_REJECTS = [
    {"id": "X2", "source": '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE XDFFORMAT [<!ENTITY e "x">]>\n'
                           "<XDFFORMAT>\n</XDFFORMAT>\n",
     "expect": {"error": "xml_forbidden"}},
    {"id": "X3", "source": xdf_doc("", xdf_table("SYN_STRIDE", LABEL_X, Z_2 + ' mmedmajorstridebits="16"')),
     "expect": {"rejected": [{"path": "XDFFORMAT[0]/XDFTABLE[0]", "reason": "unsupported_stride"}]}},
    {"id": "X4", "source": xdf_doc("", xdf_table("SYN_EQ", LABEL_X, Z_2, "X*X")),
     "expect": {"rejected": [{"path": "XDFFORMAT[0]/XDFTABLE[0]", "reason": "unsupported_equation"}]}},
    {"id": "X5", "source": xdf_doc('    <BASEOFFSET offset="4096" subtract="0" />\n', ""),
     "expect": {"error": "unsupported_baseoffset"}},
    {"id": "X6", "source": xdf_doc('    <DEFAULTS signed="0" lsbfirst="1" float="0" />\n', ""),
     "expect": {"error": "unverified_defaults"}},
    {"id": "X7", "source": xdf_doc("", xdf_table("SYN_DIMS", LABEL_X, Z_2.replace('mmedcolcount="2"', 'mmedcolcount="3"'))),
     "expect": {"rejected": [{"path": "XDFFORMAT[0]/XDFTABLE[0]", "reason": "dims_mismatch"}]}},
    {"id": "X8", "source": xdf_doc("", xdf_table(
        "SYN_LABEL_MATH",
        LABEL_X.replace("    </XDFAXIS>\n", '      <MATH equation="X*2">\n        <VAR id="X" />\n      </MATH>\n'
                        "    </XDFAXIS>\n"), Z_2)),
     "expect": {"rejected": [{"path": "XDFFORMAT[0]/XDFTABLE[0]", "reason": "ambiguous_label_scaling"}]}},
    {"id": "X9", "source": xdf_doc("", xdf_table("SYN_FLAGS", LABEL_X, Z_2 + ' mmedtypeflags="0x04"')),
     "expect": {"rejected": [{"path": "XDFFORMAT[0]/XDFTABLE[0]", "reason": "unsupported_typeflags"}]}},
    {"id": "X10", "source": xdf_doc("", xdf_table("SYN_NO_EQ", LABEL_X, Z_2).replace('<MATH equation="X">', "<MATH>")),
     "expect": {"rejected": [{"path": "XDFFORMAT[0]/XDFTABLE[0]", "reason": "missing_element"}]}},
    {"id": "X11", "source": xdf_doc("", xdf_table("SYN_NO_COUNT", LABEL_X.replace("      <indexcount>2</indexcount>\n", ""),
                                                  Z_2)),
     "expect": {"rejected": [{"path": "XDFFORMAT[0]/XDFTABLE[0]", "reason": "missing_element"}]}},
    {"id": "X12", "source": xdf_doc("", xdf_table("SYN_LABEL_WS", LABEL_X.replace('value="1"', 'value=" -1.5 "'), Z_2)),
     "expect": {"rejected": []}},
    {"id": "X13", "source": xdf_doc("", xdf_table("SYN_LABEL_PLUS", LABEL_X.replace('value="1"', 'value="+1"'), Z_2)),
     "expect": {"rejected": [{"path": "XDFFORMAT[0]/XDFTABLE[0]", "reason": "non_numeric_label"}]}},
    {"id": "X14", "source": xdf_doc("", xdf_table("SYN_NBSP", LABEL_X, Z_2.replace('mmedaddress="0x80"',
                                                                                  'mmedaddress="\u00a00x80"'))),
     "expect": {"rejected": [{"path": "XDFFORMAT[0]/XDFTABLE[0]", "reason": "bad_number"}]}},
    {"id": "X15", "source": xdf_doc("", xdf_table("SYN_DEC_DIV", LABEL_X, Z_2, "X/3.5")),
     "expect": {"rejected": [{"path": "XDFFORMAT[0]/XDFTABLE[0]", "reason": "unsupported_equation"}]}},
]


def hand_checks() -> None:
    # Spot values computed by hand, independent of the code paths above.
    assert decode(dtype("float", 32, "be"), bytes.fromhex("3fc00000")) == Fraction(3, 2)
    assert decode(dtype("float", 32, "be"), bytes.fromhex("3dcccccd")) == Fraction(13421773, 2**27)
    assert decode(dtype("float", 32, "be"), bytes.fromhex("00000001")) == Fraction(1, 2**149)
    assert decode(dtype("float", 32, "be"), bytes.fromhex("7f7fffff")) == Fraction((2**24 - 1) * 2**104)
    assert decode(dtype("int", 16, "be"), bytes.fromhex("fffe")) == -2
    assert round_half_even(Fraction(5, 2)) == 2 and round_half_even(Fraction(-3, 2)) == -2
    assert Fraction(2, 5) * 1 + 50 == Fraction(1 * 2 + 250, 5)
    assert 0x80010100 - 0x80010000 == 256  # S1 pointer target offset
    assert (600, 620) == (0x258, 0x26C) and Fraction(1, 250) == Fraction(4, 1000)  # XN1 addresses and factor
    assert Fraction(5) / Fraction(64) == Fraction(5, 64)  # A1c: f/b


def main() -> None:
    hand_checks()
    out = {
        "spec": "SPEC-003",
        "generator": {"rfc8785": importlib.metadata.version("rfc8785"), "python": sys.version.split()[0]},
        "rationals": RATIONALS,
        "decode": decode_vectors(),
        "encode": encode_vectors(),
        "units": UNITS,
        "a2l_compu": A2L_COMPU,
        "a2l_export": A2L_EXPORT,
        "mapdefs": {
            "M1": {"rules": ["R26", "R51"], "value": M1, "mapdef_hash": jhash(M1)},
            "M2": {"rules": ["R28", "R51"], "derive": {"memory_id": "cal", "name": "SYN_SCALAR", "offset": 128},
                   "value": M2, "mapdef_hash": jhash(M2)},
        },
        "definitions": {
            "D1": {"rules": ["R20", "R21", "R23", "R34", "R35", "R36", "R37", "R38", "R51", "R52"], "value": D1,
                   "definition_hash": jhash(D1), "axisdef_hashes": {"syn.rpm_axis": jhash(AX_SHARED)}},
            "D2": {"rules": ["R35", "R52"], "input": D2_INPUT, "expect_same_as": "D1",
                   "definition_hash": jhash(D1)},
            "D3": {"rules": ["R51", "R52"], "value": D3, "definition_hash": jhash(D3), "differs_from": "D1"},
        },
        "spans": {
            "S1": {"rules": ["R22", "R30"], "definition": "D1", "dump": SPAN_DUMP, "expect": SPANS},
            "S2": {"rules": ["R30", "R55"], "definition": SPAN_FAR_DEFINITION, "dump": SPAN_DUMP,
                   "expect": {"syn.far_pointer": {"error": "unknown_memory"}}},
        },
        "xdf": {
            "X1": {
                "rules": ["R61", "R62", "R63", "R64", "R70", "R71", "R72", "R73", "R74", "R75", "R76", "R77", "R79"],
                "source": XDF_SOURCE, "params": XDF_PARAMS,
                "expect": {"definition": XDF_DEFINITION, "definition_hash": jhash(XDF_DEFINITION),
                           "rejected": XDF_REJECTED, "ignored": XDF_IGNORED},
                "export": xdf_export_text(),
                "reimport": {"definition_hash": jhash(XDF_DEFINITION), "rejected": [], "ignored": []},
            },
            "XE1": {
                "rules": ["R64", "R76", "R77"], "params": XE_PARAMS, "definition": XE_DEFINITION,
                "definition_hash": jhash(XE_DEFINITION), "export": xe_export_text(),
                "reimport": {"definition_hash": jhash(XE_DEFINITION), "rejected": [], "ignored": []},
            },
            "XN1": {
                "rules": ["R64", "R75", "R76", "R77"], "params": XE_PARAMS, "definition": NE_DEFINITION,
                "export": NE_EXPORT, "normalized": NN_DEFINITION, "normalized_hash": jhash(NN_DEFINITION),
            },
            "export_rejects": EXPORT_REJECTS,
            "rejects": XDF_REJECTS,
        },
    }
    assert jhash(D3) != jhash(D1)
    json.dump(out, sys.stdout, indent=2, ensure_ascii=False, sort_keys=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
