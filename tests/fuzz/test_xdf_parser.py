"""SPEC-003 R65: the XDF importer and the number and equation grammars are parsers of untrusted input.

Short Hypothesis fuzzing on every PR (the 10-minute Atheris run of SPEC-000 belongs to a job that does
not exist yet). Any exception other than DefinitionError is a bug. Accepted equations and numbers are
checked against an independent evaluation with `fractions.Fraction`.
"""

import contextlib
import json
import re
from fractions import Fraction
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from core.definitions import (
    DefinitionError,
    License,
    SoftwareVersion,
    XdfParams,
    import_xdf,
    parse_a2l_number,
    parse_rational,
    parse_xdf_decimal,
)
from core.definitions._xdf import parse_equation

PARAMS = XdfParams("synthetic.test", SoftwareVersion("exact", ("SYN0001",)), "cal", License("unverified", None), 0)
VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / "specs" / "vectors" / "spec-003" / "vectors.json").read_text(
        encoding="utf-8"
    )
)
SEEDS = [VECTORS["xdf"]["X1"]["source"], *(v["source"] for v in VECTORS["xdf"]["rejects"])]

ELEMENTS = [
    "XDFFORMAT", "XDFHEADER", "XDFCONSTANT", "XDFTABLE", "XDFAXIS", "EMBEDDEDDATA", "MATH", "VAR", "LABEL",
    "title", "units", "indexcount", "BASEOFFSET", "baseoffset", "DEFAULTS", "flags", "XDFCHECKSUM", "embedinfo",
    "description", "decimalpl", "min", "max", "CATEGORYMEM",
]  # fmt: skip
ATTRIBUTES = [
    "id", "uniqueid", "flags", "mmedaddress", "mmedelementsizebits", "mmedtypeflags", "mmedrowcount", "mmedcolcount",
    "mmedmajorstridebits", "mmedminorstridebits", "equation", "index", "value", "offset", "subtract", "signed",
    "lsbfirst", "float", "version", "datasizeinbits",
]  # fmt: skip
VALUES = [
    "0",
    "1",
    "2",
    "3",
    "8",
    "16",
    "32",
    "0x10",
    "0x02",
    "0x10000",
    "x",
    "y",
    "z",
    "X",
    "X*2",
    "X/0",
    "-1.5",
    "",
    "a",
]


def run(source: bytes) -> None:
    with contextlib.suppress(DefinitionError):
        import_xdf(source, PARAMS)


# SPEC-003 R65, R80: arbitrary bytes.
@given(st.binary(max_size=512))
def test_arbitrary_bytes(source: bytes) -> None:
    run(source)


# SPEC-003 R65: byte-level mutations of the vector documents.
@given(
    st.sampled_from(SEEDS),
    st.lists(st.tuples(st.integers(0, 4096), st.binary(max_size=4), st.integers(0, 4)), max_size=6),
)
def test_mutated_vectors(seed: str, edits: list[tuple[int, bytes, int]]) -> None:
    source = bytearray(seed.encode("utf-8"))
    for position, insert, delete in edits:
        at = position % (len(source) + 1)
        source[at : at + delete] = insert
    run(bytes(source))


@st.composite
def elements(draw: st.DrawFn, depth: int = 0) -> str:
    name = draw(st.sampled_from(ELEMENTS))
    attrs = draw(st.dictionaries(st.sampled_from(ATTRIBUTES), st.sampled_from(VALUES), max_size=4))
    text = "".join(f' {k}="{v}"' for k, v in attrs.items())
    children = draw(st.lists(elements(depth + 1), max_size=0 if depth >= 3 else 3))
    body = draw(st.sampled_from(["", "1", "0x10", " 2 ", "X", "°C"])) + "".join(children)
    return f"<{name}{text}>{body}</{name}>"


# SPEC-003 R61, R65: well-formed documents from the XDF vocabulary, so the mapping code is reached.
@given(st.lists(elements(1), max_size=5), st.booleans())
def test_structured_documents(children: list[str], declaration: bool) -> None:
    prefix = '<?xml version="1.0" encoding="UTF-8"?>' if declaration else ""
    run(f"{prefix}<XDFFORMAT>{''.join(children)}</XDFFORMAT>".encode())


_TOKEN = re.compile(r"[0-9]+(?:\.[0-9]+)?|[X+\-*/]")


def evaluate(equation: str, x: Fraction) -> Fraction:
    """Independent recursive-descent evaluation of an accepted R74 equation, exact."""
    tokens = _TOKEN.findall(equation.strip(" \t\r\n").replace(" ", ""))
    position = 0

    def factor() -> Fraction:
        nonlocal position
        token = tokens[position]
        position += 1
        if token == "-":
            return -factor()
        return x if token == "X" else Fraction(token)

    def term() -> Fraction:
        nonlocal position
        value = factor()
        while position < len(tokens) and tokens[position] in "*/":
            position += 1
            value = value * factor() if tokens[position - 1] == "*" else value / factor()
        return value

    value = term()
    while position < len(tokens):
        position += 1
        value = value + term() if tokens[position - 1] == "+" else value - term()
    return value


# SPEC-003 R74: accepted equations mean exactly `factor·X + addend`; everything else is rejected.
@given(st.text(st.sampled_from("X0123456789.+-*/ "), max_size=14))
def test_equations(equation: str) -> None:
    try:
        factor, addend = parse_equation(equation)
    except DefinitionError as error:
        reason: str | None = error.reason
    else:
        reason = None
    if reason is not None:
        assert reason in {"unsupported_equation", "zero_factor", "bad_number", "rational_too_large"}
        return
    assert evaluate(equation, Fraction(0)) == addend
    assert evaluate(equation, Fraction(1)) == factor + addend


# SPEC-003 R3, R74, R91: accepted numbers are exactly Python's reading of the same text.
@given(st.text(st.sampled_from("0123456789.-+eE/x "), max_size=12))
def test_number_grammars(text: str) -> None:
    for parse in (parse_xdf_decimal, parse_a2l_number, parse_rational):
        try:
            value: Fraction | str = parse(text)
        except DefinitionError as error:
            value = error.reason
        if isinstance(value, str):
            assert value in {"bad_number", "bad_rational", "rational_too_large"}
        else:
            assert value == Fraction(text)
