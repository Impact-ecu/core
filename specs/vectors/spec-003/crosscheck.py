"""Second, independent implementation that recomputes every expected value in vectors.json.

Stdlib only and independent of the core and of generate.py, with different methods:
- its own RFC 8785 serializer (keys sorted by UTF-16 code units, ES6 string escaping, integers only);
- its own rational type (numerator, denominator) and decimal parsers, instead of fractions.Fraction;
- integer decoding with int.from_bytes, binary32 decoding from sign/exponent/fraction bits;
- binary32 encoding by binary search over bit patterns, instead of exponent arithmetic;
- its own XDF importer (xml.parsers.expat) implementing SPEC-003 §7 and the exporter of R77;
- A2L COMPU_METHOD conversion (R90) and export coefficients (R99).
Run: python -I crosscheck.py vectors.json   (exit status 1 on any disagreement)
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import unicodedata
from math import gcd
from typing import Any
from xml.parsers import expat


# ------------------------------------------------------------------ canonical JSON (RFC 8785 subset)

def esc(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o < 0x20:
            out.append({8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r"}.get(o, "\\u%04x" % o))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def canon(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return esc(v)
    if isinstance(v, list):
        return "[" + ",".join(canon(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(esc(k) + ":" + canon(v[k]) for k in keys) + "}"
    raise TypeError(f"non-canonical value {v!r}")


def sha(v: Any) -> str:
    return hashlib.sha256(canon(v).encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ rationals

class Err(Exception):
    def __init__(self, reason: str, field: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.field = field


class Q:
    __slots__ = ("n", "d")

    def __init__(self, n: int, d: int = 1) -> None:
        if d == 0:
            raise ZeroDivisionError
        if d < 0:
            n, d = -n, -d
        g = gcd(n, d)
        self.n, self.d = n // g, d // g

    def __add__(self, o: "Q") -> "Q":
        return Q(self.n * o.d + o.n * self.d, self.d * o.d)

    def __sub__(self, o: "Q") -> "Q":
        return Q(self.n * o.d - o.n * self.d, self.d * o.d)

    def __mul__(self, o: "Q") -> "Q":
        return Q(self.n * o.n, self.d * o.d)

    def __truediv__(self, o: "Q") -> "Q":
        return Q(self.n * o.d, self.d * o.n)

    def __eq__(self, o: object) -> bool:
        return isinstance(o, Q) and self.n == o.n and self.d == o.d

    def __lt__(self, o: "Q") -> bool:
        return self.n * o.d < o.n * self.d

    def __le__(self, o: "Q") -> bool:
        return self.n * o.d <= o.n * self.d

    def text(self) -> str:
        return str(self.n) if self.d == 1 else f"{self.n}/{self.d}"


CANON_RE = re.compile(r"^-?(0|[1-9][0-9]*)(/[1-9][0-9]*)?$")


def parse_canonical(t: str) -> Q:
    if not CANON_RE.match(t) or t == "-0":
        raise Err("bad_rational")
    if "/" in t:
        a, b = t.split("/")
        n, d = int(a), int(b)
        if d < 2 or gcd(abs(n), d) != 1:
            raise Err("bad_rational")
        return Q(n, d)
    return Q(int(t))


def digits_to_q(sign: int, ip: str, fp: str, exp: int) -> Q:
    n = int(ip + fp) * sign
    e = exp - len(fp)
    return Q(n * 10 ** e) if e >= 0 else Q(n, 10 ** (-e))


XDF_NUM = re.compile(r"^(-?)([0-9]+)(?:\.([0-9]+))?$")
A2L_NUM = re.compile(r"^([+-]?)([0-9]+)(?:\.([0-9]*))?(?:[eE]([+-]?[0-9]+))?$")


def parse_xdf_decimal(t: str) -> Q:
    m = XDF_NUM.match(t)
    if not m:
        raise Err("bad_number")
    return digits_to_q(-1 if m.group(1) else 1, m.group(2), m.group(3) or "", 0)


def parse_a2l_number(t: str) -> Q:
    m = A2L_NUM.match(t)
    if not m:
        raise Err("bad_number")
    return digits_to_q(-1 if m.group(1) == "-" else 1, m.group(2), m.group(3) or "", int(m.group(4) or "0"))


def finite_decimal(q: Q) -> str | None:
    d, a, b = q.d, 0, 0
    while d % 2 == 0:
        d //= 2
        a += 1
    while d % 5 == 0:
        d //= 5
        b += 1
    if d != 1:
        return None
    k = max(a, b)
    scaled = abs(q.n) * (10 ** k) // q.d
    s = str(scaled).rjust(k + 1, "0")
    ip, fp = s[: len(s) - k], s[len(s) - k:].rstrip("0")
    return ("-" if q.n < 0 else "") + ip + ("." + fp if fp else "")


# ------------------------------------------------------------------ cells (R6, R7, R13, R15)

def check_dtype(dt: dict) -> None:
    if set(dt) != {"kind", "bits", "byte_order"} or dt["bits"] not in (8, 16, 32):
        raise Err("bad_dtype")
    if (dt["byte_order"] == "none") != (dt["bits"] == 8) or dt["byte_order"] not in ("le", "be", "none"):
        raise Err("bad_dtype")
    if dt["kind"] not in ("uint", "int", "float") or (dt["kind"] == "float" and dt["bits"] != 32):
        raise Err("bad_dtype")


def f32_value(bits: int) -> Q | None:
    sign = -1 if bits >> 31 else 1
    exp = (bits >> 23) & 0xFF
    frac = bits & 0x7FFFFF
    if exp == 0xFF:
        return None
    if exp == 0:
        return Q(sign * frac, 1 << 149)
    e = exp - 150
    m = (1 << 23) | frac
    return Q(sign * m * (1 << e)) if e >= 0 else Q(sign * m, 1 << -e)


def raw_of(dt: dict, data: bytes) -> Q | None:
    order = "little" if dt["byte_order"] == "le" else "big"
    if dt["kind"] == "float":
        return f32_value(int.from_bytes(data, order))
    return Q(int.from_bytes(data, order, signed=dt["kind"] == "int"))


def rhe(q: Q) -> int:
    fl = q.n // q.d
    twice_rem = 2 * (q.n - fl * q.d)
    if twice_rem > q.d or (twice_rem == q.d and fl % 2):
        return fl + 1
    return fl


INF_PATTERN = 0x7F800000
TWO_128 = Q(1 << 128)


def pattern_value(p: int) -> Q:
    v = f32_value(p)
    return TWO_128 if v is None else v


def f32_nearest(q: Q) -> int | None:
    a = Q(abs(q.n), q.d)
    lo, hi = 0, 0x7F7FFFFF
    if pattern_value(hi) <= a:
        lo = hi
    else:
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if pattern_value(mid) <= a:
                lo = mid
            else:
                hi = mid - 1
    below, above = lo, lo + 1
    vb = pattern_value(below)
    if vb == a:
        best = below
    else:
        db, da = a - vb, pattern_value(above) - a
        best = below if db < da else above if da < db else (below if below % 2 == 0 else above)
    if best >= INF_PATTERN:
        return None
    if best == 0:
        return 0
    return best | (0x80000000 if q.n < 0 else 0)


def encode(dt: dict, sc: dict, target: Q, current: bytes | None) -> bytes:
    if current is not None:
        cr = raw_of(dt, current)
        if cr is not None and parse_canonical(sc["factor"]) * cr + parse_canonical(sc["addend"]) == target:
            return current
    q = (target - parse_canonical(sc["addend"])) / parse_canonical(sc["factor"])
    order = "little" if dt["byte_order"] == "le" else "big"
    if dt["kind"] == "float":
        p = f32_nearest(q)
        if p is None:
            raise Err("out_of_range")
        return p.to_bytes(4, order)
    r = rhe(q)
    bits = dt["bits"]
    try:
        return r.to_bytes(bits // 8, order, signed=dt["kind"] == "int")
    except OverflowError:
        raise Err("out_of_range") from None


# ------------------------------------------------------------------ units (R16, R17)

UNIT_TEXT = {"deg_crank": "deg_crank", "lambda": "lambda", "kPa_abs": "kPa_abs", "kPa_rel": "kPa_rel",
             "mg_per_stroke": "mg/stroke", "percent": "%", "rpm": "rpm", "degC": "degC", "ms": "ms", "Nm": "Nm",
             "one": "1"}
ALIASES: dict[str, tuple[str, Q]] = {t: (u, Q(1)) for u, t in UNIT_TEXT.items()}
ALIASES.update({"λ": ("lambda", Q(1)), "1/min": ("rpm", Q(1)), "°C": ("degC", Q(1)),
                "s": ("ms", Q(1000)), "us": ("ms", Q(1, 1000)), "µs": ("ms", Q(1, 1000))})


def xdf_exportable(factor: Q, addend: Q, values: list[Q]) -> bool:
    if finite_decimal(factor) is None and factor.n != 1:
        return False
    return all(finite_decimal(v) is not None for v in [addend, *values])


def map_unit(text: str, factor: Q = Q(1), addend: Q = Q(0), values: list[Q] | None = None) -> tuple[str | None, str | None, Q]:
    # R17: an alias with k != 1 applies only when the multiplied scaling stays XDF-exportable (R76).
    if text in ALIASES:
        u, k = ALIASES[text]
        if k == Q(1) or xdf_exportable(factor * k, addend * k, [v * k for v in (values or [])]):
            return u, None, k
    return None, text, Q(1)


def sc_obj(f: Q, a: Q) -> dict:
    return {"factor": f.text(), "addend": a.text()}


# ------------------------------------------------------------------ A2L (R90, R99)

def a2l_compu(ctype: str, coeffs: list[str]) -> dict:
    c = [parse_a2l_number(x) for x in coeffs]
    zero = Q(0)
    if ctype == "IDENTICAL" and not c:
        return sc_obj(Q(1), zero)
    if ctype == "LINEAR" and len(c) == 2:
        if c[0] == zero:
            raise Err("zero_factor")
        return sc_obj(c[0], c[1])
    if ctype == "RAT_FUNC" and len(c) == 6:
        a, b, cc, d, e, f = c
        if a == zero and d == zero and e == zero and not b == zero and not f == zero:
            return sc_obj(f / b, Q(0) - cc / b)
    raise Err("unsupported_conversion")


def a2l_export(sc: dict) -> list[int]:
    fq, aq = parse_canonical(sc["factor"]), parse_canonical(sc["addend"])
    f, c, b = fq.n * aq.d, -aq.n * fq.d, fq.d * aq.d
    g = gcd(gcd(b, abs(c)), abs(f))
    return [0, b // g, c // g, 0, 0, f // g]


# ------------------------------------------------------------------ definitions (R20-R38)

MAP_KEYS = {"map_id", "name", "category", "map_type", "state", "memory_id", "offset", "dims", "cell_order",
            "dtype", "scaling", "unit", "unit_text", "axes"}


def check_unit(o: dict) -> None:
    if o["unit"] is not None and (o["unit"] not in UNIT_TEXT or o["unit_text"] is not None):
        raise Err("non_canonical")
    if o["unit"] is None and not isinstance(o["unit_text"], str):
        raise Err("non_canonical")


def check_axis(ax: dict, count: int, axes_by_id: dict) -> None:
    src = ax["axis_source"]
    if src == "shared":
        if ax["axis_id"] not in axes_by_id:
            raise Err("unknown_axis")
        check_axis(axes_by_id[ax["axis_id"]]["axis"], count, {})
        return
    check_unit(ax)
    n = len(ax["values"]) if src == "fixed" else ax["count"]
    if n != count:
        raise Err("dims_mismatch")
    if src == "fixed":
        for v in ax["values"]:
            parse_canonical(v)
        return
    check_dtype(ax["dtype"])
    parse_canonical(ax["scaling"]["factor"])
    if src == "pointer" and (ax["pointer_dtype"]["kind"] != "uint" or ax["pointer_dtype"]["bits"] not in (16, 32)):
        raise Err("bad_dtype")


def check_definition(d: dict) -> None:
    ids = [m["map_id"] for m in d["mapdefs"]]
    aids = [a["axis_id"] for a in d["axes"]]
    if ids != sorted(set(ids)) or aids != sorted(set(aids)):
        raise Err("not_sorted")
    by_id = {a["axis_id"]: a for a in d["axes"]}
    used: set[str] = set()
    for m in d["mapdefs"]:
        if set(m) != MAP_KEYS:
            raise Err("bad_shape")
        check_dtype(m["dtype"])
        check_unit(m)
        if parse_canonical(m["scaling"]["factor"]) == Q(0):
            raise Err("zero_factor")
        rows, cols = m["dims"]["rows"], m["dims"]["cols"]
        if (rows == 1 or cols == 1) and m["cell_order"] != "x_fastest":
            raise Err("non_canonical")
        if unicodedata.normalize("NFC", m["name"]) != m["name"]:
            raise Err("bad_text")
        for key, n in (("x", cols), ("y", rows)):
            ax = m["axes"][key]
            if ax is not None:
                check_axis(ax, n, by_id)
                if ax["axis_source"] == "shared":
                    used.add(ax["axis_id"])
    if used != set(aids):
        raise Err("orphan_axis")


# ------------------------------------------------------------------ span (R22, R30)

def span_of(m: dict, d: dict, dump: dict) -> list[dict]:
    mems = {x["memory_id"]: x for x in dump["memories"]}
    data = {k: bytearray(v["size"]) for k, v in mems.items()}
    for b in dump["bytes"]:
        raw = bytes.fromhex(b["hex"])
        data[b["memory_id"]][b["offset"]:b["offset"] + len(raw)] = raw
    by_id = {a["axis_id"]: a["axis"] for a in d["axes"]}
    parts: list[tuple[str, int, int]] = []

    def add(mem: str, start: int, length: int) -> None:
        if mem not in mems:
            raise Err("unknown_memory")
        if start + length > mems[mem]["size"]:
            raise Err("out_of_memory")
        parts.append((mem, start, start + length))

    add(m["memory_id"], m["offset"], m["dims"]["rows"] * m["dims"]["cols"] * m["dtype"]["bits"] // 8)
    for key in ("x", "y"):
        ax = m["axes"][key]
        while ax is not None and ax["axis_source"] == "shared":
            ax = by_id[ax["axis_id"]]
        if ax is None or ax["axis_source"] == "fixed":
            continue
        if ax["axis_source"] == "inline":
            add(ax["memory_id"], ax["offset"], ax["count"] * ax["dtype"]["bits"] // 8)
            continue
        pw = ax["pointer_dtype"]["bits"] // 8
        add(ax["memory_id"], ax["pointer_offset"], pw)
        order = "little" if ax["pointer_dtype"]["byte_order"] == "le" else "big"
        ptr = int.from_bytes(data[ax["memory_id"]][ax["pointer_offset"]:ax["pointer_offset"] + pw], order)
        if ax["target_memory_id"] not in mems:
            raise Err("unknown_memory")
        base = mems[ax["target_memory_id"]]["base_address"]
        if base is None:
            raise Err("unknown_base_address")
        if ptr < base:
            raise Err("out_of_memory")
        add(ax["target_memory_id"], ptr - base, ax["count"] * ax["dtype"]["bits"] // 8)
    merged: list[list] = []
    for mem, a, b in sorted(parts, key=lambda t: (t[0].encode("utf-16-be"), t[1])):
        if merged and merged[-1][0] == mem and a <= merged[-1][2]:
            merged[-1][2] = max(merged[-1][2], b)
        else:
            merged.append([mem, a, b])
    return [{"memory_id": x, "start": a, "end": b} for x, a, b in merged]


# ------------------------------------------------------------------ XDF importer (SPEC-003 §7)

class Node:
    def __init__(self, name: str, attrs: dict[str, str], path: str) -> None:
        self.name, self.attrs, self.path = name, attrs, path
        self.children: list[Node] = []
        self.text = ""


def parse_xml(data: bytes) -> Node:
    p = expat.ParserCreate()
    p.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    stack: list[Node] = []
    counters: list[dict[str, int]] = [{}]
    root: list[Node] = []

    def forbid(*_: object) -> None:
        raise Err("xml_forbidden")

    def xmldecl(version: str, encoding: str | None, standalone: int) -> None:
        if encoding is not None and encoding not in ("UTF-8", "utf-8"):
            raise Err("unsupported_encoding")

    def start(name: str, attrs: dict[str, str]) -> None:
        c = counters[-1]
        i = c.get(name, 0)
        c[name] = i + 1
        base = stack[-1].path + "/" if stack else ""
        n = Node(name, dict(attrs), f"{base}{name}[{i}]")
        if stack:
            stack[-1].children.append(n)
        else:
            root.append(n)
        stack.append(n)
        counters.append({})

    def end(name: str) -> None:
        stack.pop()
        counters.pop()

    def chars(t: str) -> None:
        stack[-1].text += t

    p.StartDoctypeDeclHandler = forbid
    p.EntityDeclHandler = forbid
    p.ExternalEntityRefHandler = forbid
    p.XmlDeclHandler = xmldecl
    p.StartElementHandler = start
    p.EndElementHandler = end
    p.CharacterDataHandler = chars
    try:
        p.Parse(data, True)
    except expat.ExpatError:
        raise Err("bad_xml") from None
    return root[0]


IGNORED_MAP_CHILDREN = {"description", "CATEGORYMEM", "DALINK", "datatype", "unittype", "outputtype", "decimalpl",
                        "min", "max"}
HEADER_IGNORED = {"deftitle", "description", "author", "fileversion", "CATEGORY", "REGION"}
REJECTED_TOP = {"XDFFLAG", "XDFPATCH", "XDFCHECKSUM"}


def xint(t: str) -> int:
    t = t.strip(" \t\r\n")
    if re.fullmatch(r"0x[0-9A-Fa-f]+", t):
        return int(t[2:], 16)
    if re.fullmatch(r"[0-9]+", t):
        return int(t)
    raise Err("bad_number")


def check_text(s: str, lo: int, hi: int) -> None:
    if not lo <= len(s) <= hi or unicodedata.normalize("NFC", s) != s:
        raise Err("bad_text")
    if any(ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F or 0xD800 <= ord(ch) <= 0xDFFF for ch in s):
        raise Err("bad_text")


D = r"([0-9]+(?:\.[0-9]+)?)"
N = r"([0-9]+)"
F = r"(-?[0-9]+(?:\.[0-9]+)?)"


def parse_equation(eq: str) -> tuple[Q, Q]:
    s = eq.replace(" ", "")
    dec = parse_xdf_decimal
    tail = r"(?:([+-])" + D + r")?"
    forms = [
        (r"^X" + tail + "$", lambda m: (Q(1), m, 1)),
        (r"^X\*" + F + tail + "$", lambda m: (dec(m.group(1)), m, 2)),
        (r"^" + F + r"\*X" + tail + "$", lambda m: (dec(m.group(1)), m, 2)),
        (r"^X/" + N + tail + "$", lambda m: (div(m.group(1)), m, 2)),
        (r"^" + D + r"\+X\*" + F + "$", lambda m: (dec(m.group(2)), m, -1)),
        (r"^" + D + r"-X\*" + F + "$", lambda m: (Q(0) - dec(m.group(2)), m, -1)),
        (r"^" + D + r"\+X/" + N + "$", lambda m: (div(m.group(2)), m, -1)),
    ]

    def div(t: str) -> Q:
        dq = dec(t)
        if dq == Q(0):
            raise Err("zero_factor")
        return Q(1) / dq

    for pat, fn in forms:
        m = re.match(pat, s)
        if m:
            factor, mm, gi = fn(m)
            if gi == -1:
                addend = dec(mm.group(1))
            elif mm.group(gi) is None:
                addend = Q(0)
            else:
                v = dec(mm.group(gi + 1))
                addend = v if mm.group(gi) == "+" else Q(0) - v
            if factor == Q(0):
                raise Err("zero_factor")
            return factor, addend
    raise Err("unsupported_equation")


class XdfImport:
    def __init__(self, params: dict) -> None:
        self.params = params
        self.ignored: list[str] = []
        self.rejected: list[dict] = []
        self.mapdefs: list[dict] = []

    # -- helpers that record ignored items into a per-map buffer
    def math(self, n: Node | None, required: bool) -> tuple[Q, Q] | None:
        if n is None:
            if required:
                raise Err("missing_element")
            return None
        if set(n.attrs) - {"equation"}:
            raise Err("unknown_attribute")
        if "equation" not in n.attrs:
            raise Err("missing_element")
        if len(n.children) != 1 or n.children[0].name != "VAR" or n.children[0].attrs != {"id": "X"}:
            raise Err("unsupported_equation")
        return parse_equation(n.attrs["equation"])

    def embedded(self, n: Node, cells: bool, z: bool, buf: list[str]) -> tuple[int, dict] | None:
        allowed = {"mmedaddress", "mmedelementsizebits", "mmedtypeflags", "mmedmajorstridebits", "mmedminorstridebits"}
        if z:
            allowed |= {"mmedrowcount", "mmedcolcount"}
        if not cells and "mmedaddress" not in n.attrs:
            buf.extend(f"{n.path}/@{a}" for a in n.attrs)
            return None
        if set(n.attrs) - allowed:
            raise Err("unknown_attribute")
        if "mmedaddress" not in n.attrs or "mmedelementsizebits" not in n.attrs:
            raise Err("missing_element")
        for s in ("mmedmajorstridebits", "mmedminorstridebits"):
            if s in n.attrs and n.attrs[s].strip(" \t\r\n") != "0":
                raise Err("unsupported_stride")
        bits = xint(n.attrs["mmedelementsizebits"])
        if bits not in (8, 16, 32):
            raise Err("bad_dtype")
        flags = xint(n.attrs.get("mmedtypeflags", "0x00"))
        if flags & ~0x10003:
            raise Err("unsupported_typeflags")
        is_float = bool(flags & 0x10000)
        if is_float and (bits != 32 or flags & 0x01):
            raise Err("unsupported_typeflags")
        kind = "float" if is_float else ("int" if flags & 0x01 else "uint")
        order = "none" if bits == 8 else ("le" if flags & 0x02 else "be")
        return xint(n.attrs["mmedaddress"]), {"kind": kind, "bits": bits, "byte_order": order}

    def children(self, n: Node, allowed: set[str], buf: list[str]) -> dict[str, list[Node]]:
        out: dict[str, list[Node]] = {}
        for c in n.children:
            if c.name in IGNORED_MAP_CHILDREN:
                buf.append(c.path)
            elif c.name in allowed:
                out.setdefault(c.name, []).append(c)
            elif c.name == "embedinfo":
                raise Err("unsupported_linked_axis")
            else:
                raise Err("unknown_element")
        return out

    def one(self, kids: dict[str, list[Node]], name: str, required: bool) -> Node | None:
        lst = kids.get(name, [])
        if len(lst) > 1:
            raise Err("bad_shape")
        if not lst and required:
            raise Err("missing_element")
        return lst[0] if lst else None

    def unit_text(self, kids: dict[str, list[Node]]) -> str:
        u = self.one(kids, "units", False)
        t = "" if u is None else u.text
        check_text(t, 0, 64)
        return t

    def axis(self, n: Node, buf: list[str]) -> tuple[dict, int]:
        if set(n.attrs) - {"id", "uniqueid"}:
            raise Err("unknown_attribute")
        if "uniqueid" in n.attrs:
            buf.append(f"{n.path}/@uniqueid")
        kids = self.children(n, {"EMBEDDEDDATA", "indexcount", "units", "LABEL", "MATH"}, buf)
        ic = self.one(kids, "indexcount", True)
        count = xint(ic.text)
        ed = self.one(kids, "EMBEDDEDDATA", False)
        stored = self.embedded(ed, False, False, buf) if ed is not None else None
        utext_raw = self.unit_text(kids)
        labels = kids.get("LABEL", [])
        if stored is not None:
            if labels:
                raise Err("bad_labels")
            f, a = self.math(self.one(kids, "MATH", False), True)
            unit, utext, k = map_unit(utext_raw, f, a)
            off, dt = stored
            return ({"axis_source": "inline", "memory_id": self.params["memory_id"], "offset": off, "count": count,
                     "dtype": dt, "scaling": sc_obj(f * k, a * k), "unit": unit, "unit_text": utext}, count)
        m = self.math(self.one(kids, "MATH", False), False)
        if m is not None and m != (Q(1), Q(0)):
            raise Err("ambiguous_label_scaling")
        vals: dict[int, Q] = {}
        for lab in labels:
            if set(lab.attrs) != {"index", "value"}:
                raise Err("bad_labels")
            i = xint(lab.attrs["index"])
            if i in vals:
                raise Err("bad_labels")
            try:
                vals[i] = parse_xdf_decimal(lab.attrs["value"].strip(" \t\r\n"))
            except Err:
                raise Err("non_numeric_label") from None
        if sorted(vals) != list(range(count)):
            raise Err("bad_labels")
        unit, utext, k = map_unit(utext_raw, Q(1), Q(0), list(vals.values()))
        return ({"axis_source": "fixed", "values": [(vals[i] * k).text() for i in range(count)], "unit": unit,
                 "unit_text": utext}, count)

    def mapdef(self, name: str, off: int, dims: tuple[int, int], dt: dict, sc: tuple[Q, Q], utext_raw: str,
               ax: dict) -> dict:
        check_text(name, 1, 256)
        unit, utext, k = map_unit(utext_raw, sc[0], sc[1])
        mem = self.params["memory_id"]
        mid = "m_" + sha({"memory_id": mem, "name": name, "offset": off})[:24]
        return {"map_id": mid, "name": name, "category": None, "map_type": None, "state": "imported",
                "memory_id": mem, "offset": off, "dims": {"rows": dims[0], "cols": dims[1]},
                "cell_order": "x_fastest", "dtype": dt, "scaling": sc_obj(sc[0] * k, sc[1] * k),
                "unit": unit, "unit_text": utext, "axes": ax}

    def constant(self, n: Node, buf: list[str]) -> dict:
        if set(n.attrs) - {"uniqueid"}:
            raise Err("unknown_attribute")
        if "uniqueid" in n.attrs:
            buf.append(f"{n.path}/@uniqueid")
        kids = self.children(n, {"title", "EMBEDDEDDATA", "units", "MATH"}, buf)
        title = self.one(kids, "title", True)
        off, dt = self.embedded(self.one(kids, "EMBEDDEDDATA", True), True, False, buf)
        sc = self.math(self.one(kids, "MATH", True), True)
        return self.mapdef(title.text, off, (1, 1), dt, sc, self.unit_text(kids), {"x": None, "y": None})

    def table(self, n: Node, buf: list[str]) -> dict:
        if set(n.attrs) - {"uniqueid", "flags"}:
            raise Err("unknown_attribute")
        if "uniqueid" in n.attrs:
            buf.append(f"{n.path}/@uniqueid")
        if "flags" in n.attrs and xint(n.attrs["flags"]) != 0:
            raise Err("unsupported_flags")
        kids = self.children(n, {"title", "XDFAXIS"}, buf)
        title = self.one(kids, "title", True)
        axes: dict[str, Node] = {}
        for a in kids.get("XDFAXIS", []):
            aid = a.attrs.get("id")
            if aid not in ("x", "y", "z") or aid in axes:
                raise Err("bad_shape")
            axes[aid] = a
        if "z" not in axes:
            raise Err("missing_element")
        z = axes["z"]
        if set(z.attrs) - {"id"}:
            raise Err("unknown_attribute")
        zk = self.children(z, {"EMBEDDEDDATA", "units", "MATH"}, buf)
        zed = self.one(zk, "EMBEDDEDDATA", True)
        off, dt = self.embedded(zed, True, True, buf)
        rows = xint(zed.attrs.get("mmedrowcount", "1"))
        cols = xint(zed.attrs.get("mmedcolcount", "1"))
        if not (1 <= rows <= 65535 and 1 <= cols <= 65535):
            raise Err("bad_dims")
        sc = self.math(self.one(zk, "MATH", True), True)
        ax: dict[str, dict | None] = {"x": None, "y": None}
        for key, need in (("x", cols), ("y", rows)):
            if key in axes:
                axd, count = self.axis(axes[key], buf)
                if count != need:
                    raise Err("dims_mismatch")
                ax[key] = axd
            elif need > 1:
                raise Err("dims_mismatch")
        return self.mapdef(title.text, off, (rows, cols), dt, sc, self.unit_text(zk), ax)

    def header(self, n: Node) -> None:
        if n.attrs:
            raise Err("unknown_attribute")
        for c in n.children:
            if c.name in HEADER_IGNORED:
                self.ignored.append(c.path)
            elif c.name == "BASEOFFSET":
                if set(c.attrs) - {"offset", "subtract"}:
                    raise Err("unknown_attribute")
                if xint(c.attrs.get("offset", "0")) != 0:
                    raise Err("unsupported_baseoffset")
            elif c.name == "baseoffset":
                if xint(c.text) != 0:
                    raise Err("unsupported_baseoffset")
            elif c.name == "DEFAULTS":
                for a, v in c.attrs.items():
                    if a in ("signed", "lsbfirst", "float"):
                        if v.strip(" \t\r\n") != "0":
                            raise Err("unverified_defaults")
                    elif a in ("datasizeinbits", "sigdigits", "outputtype"):
                        self.ignored.append(f"{c.path}/@{a}")
                    else:
                        raise Err("unknown_attribute")
            elif c.name == "flags":
                if xint(c.text) != 0:
                    raise Err("unsupported_flags")
            else:
                raise Err("unknown_element")

    def run(self, data: bytes) -> dict:
        root = parse_xml(data)
        if root.name != "XDFFORMAT":
            raise Err("unknown_element")
        for a in root.attrs:
            if a != "version":
                raise Err("unknown_attribute")
            self.ignored.append(f"{root.path}/@version")
        for c in root.children:
            if c.name == "XDFHEADER":
                self.header(c)
        for c in root.children:
            if c.name == "XDFHEADER":
                continue
            if c.name in REJECTED_TOP:
                self.rejected.append({"path": c.path, "reason": "unsupported_element"})
            elif c.name in ("XDFCONSTANT", "XDFTABLE"):
                buf: list[str] = []
                try:
                    md = self.constant(c, buf) if c.name == "XDFCONSTANT" else self.table(c, buf)
                except Err as e:
                    self.rejected.append({"path": c.path, "reason": e.reason})
                    continue
                self.mapdefs.append(md)
                self.ignored.extend(buf)
            else:
                raise Err("unknown_element")
        p = self.params
        definition = {"spec": "SPEC-003/1", "family_id": p["family_id"], "software_version": p["software_version"],
                      "axes": [], "mapdefs": sorted(self.mapdefs, key=lambda m: m["map_id"]),
                      "origin": {"kind": "xdf_import", "derived_from": []}, "license": p["license"],
                      "confidence_permille": p["confidence_permille"]}
        return {"definition": definition, "rejected": sorted(self.rejected, key=lambda r: r["path"]),
                "ignored": sorted(self.ignored)}


# ------------------------------------------------------------------ XDF exporter (R76, R77)

def xesc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def eq_text(sc: dict, prefix: str = "") -> str:
    f, a = parse_canonical(sc["factor"]), parse_canonical(sc["addend"])
    fd = finite_decimal(f)
    if f == Q(1):
        s = "X"
    elif fd is not None:
        s = "X*" + fd
    elif f.n == 1:
        s = f"X/{f.d}"
    else:
        raise Err("unrepresentable", prefix + "scaling.factor")
    if not a == Q(0):
        ad = finite_decimal(a)
        if ad is None:
            raise Err("unrepresentable", prefix + "scaling.addend")
        s += ad if ad.startswith("-") else "+" + ad
    return s


def flags_text(dt: dict) -> str:
    v = (0x01 if dt["kind"] == "int" else 0) | (0x02 if dt["byte_order"] == "le" else 0) | (
        0x10000 if dt["kind"] == "float" else 0)
    return "0x%02X" % v


def units_line(ind: str, o: dict) -> str:
    t = UNIT_TEXT[o["unit"]] if o["unit"] is not None else o["unit_text"]
    return f"{ind}<units>{xesc(t)}</units>\n" if t else ""


def math_lines(ind: str, sc: dict, prefix: str = "") -> str:
    return (f'{ind}<MATH equation="{xesc(eq_text(sc, prefix))}">\n{ind}  <VAR id="X" />\n{ind}</MATH>\n')


def export_xdf(d: dict, memory_id: str) -> str:
    out = ['<?xml version="1.0" encoding="UTF-8"?>\n<XDFFORMAT>\n']
    for m in d["mapdefs"]:
        if m["memory_id"] != memory_id:
            raise Err("unrepresentable", "memory_id")
        dt = m["dtype"]
        ed = f'mmedtypeflags="{flags_text(dt)}" mmedaddress="0x{m["offset"]:X}" mmedelementsizebits="{dt["bits"]}"'
        if m["dims"] == {"rows": 1, "cols": 1} and m["axes"] == {"x": None, "y": None}:
            out.append("  <XDFCONSTANT>\n")
            out.append(f"    <title>{xesc(m['name'])}</title>\n    <EMBEDDEDDATA {ed} />\n")
            out.append(units_line("    ", m) + math_lines("    ", m["scaling"]) + "  </XDFCONSTANT>\n")
            continue
        if m["cell_order"] != "x_fastest":
            raise Err("unrepresentable", "cell_order")
        if m["dims"]["cols"] > 1 and m["axes"]["x"] is None:
            raise Err("unrepresentable", "axes.x")
        if m["dims"]["rows"] > 1 and m["axes"]["y"] is None:
            raise Err("unrepresentable", "axes.y")
        out.append(f"  <XDFTABLE>\n    <title>{xesc(m['name'])}</title>\n")
        for key in ("x", "y"):
            ax = m["axes"][key]
            if ax is None:
                continue
            out.append(f'    <XDFAXIS id="{key}">\n')
            if ax["axis_source"] == "inline":
                if ax["memory_id"] != memory_id:
                    raise Err("unrepresentable", f"axes.{key}.memory_id")
                adt = ax["dtype"]
                out.append(f'      <EMBEDDEDDATA mmedtypeflags="{flags_text(adt)}" mmedaddress="0x{ax["offset"]:X}" '
                           f'mmedelementsizebits="{adt["bits"]}" />\n')
                out.append(f"      <indexcount>{ax['count']}</indexcount>\n" + units_line("      ", ax)
                           + math_lines("      ", ax["scaling"], f"axes.{key}."))
            elif ax["axis_source"] == "fixed":
                out.append(f"      <indexcount>{len(ax['values'])}</indexcount>\n" + units_line("      ", ax))
                for i, v in enumerate(ax["values"]):
                    dv = finite_decimal(parse_canonical(v))
                    if dv is None:
                        raise Err("unrepresentable", f"axes.{key}.values")
                    out.append(f'      <LABEL index="{i}" value="{dv}" />\n')
            else:
                raise Err("unrepresentable", f"axes.{key}.axis_source")
            out.append("    </XDFAXIS>\n")
        out.append('    <XDFAXIS id="z">\n')
        out.append(f'      <EMBEDDEDDATA {ed} mmedrowcount="{m["dims"]["rows"]}" mmedcolcount="{m["dims"]["cols"]}" />\n')
        out.append(units_line("      ", m) + math_lines("      ", m["scaling"]) + "    </XDFAXIS>\n  </XDFTABLE>\n")
    out.append("</XDFFORMAT>\n")
    return "".join(out)


# ------------------------------------------------------------------ checker

class Checker:
    def __init__(self, v: dict) -> None:
        self.v = v
        self.failures: list[str] = []
        self.checked = 0

    def expect(self, label: str, got: object, want: object) -> None:
        self.checked += 1
        if got != want:
            self.failures.append(f"{label}: got {got!r}, want {want!r}")

    def outcome(self, fn: Any) -> dict:
        try:
            return {"ok": fn()}
        except Err as e:
            return {"error": e.reason}

    def rationals(self) -> None:
        parsers = {"xdf_decimal": parse_xdf_decimal, "a2l_number": parse_a2l_number, "rational_text": parse_canonical}
        for r in self.v["rationals"]:
            got = self.outcome(lambda: parsers[r["grammar"]](r["text"]).text())
            want = {"ok": r["expect"]["value"]} if "value" in r["expect"] else r["expect"]
            self.expect(r["id"], got, want)

    def decode(self) -> None:
        for c in self.v["decode"]:
            check_dtype(c["dtype"])
            raw = raw_of(c["dtype"], bytes.fromhex(c["bytes_hex"]))
            if raw is None:
                got = {"raw": "non_finite", "physical": "non_finite"}
            else:
                sc = c["scaling"]
                phys = parse_canonical(sc["factor"]) * raw + parse_canonical(sc["addend"])
                got = {"raw": raw.text(), "physical": phys.text()}
            self.expect(c["id"], got, c["expect"])

    def encode(self) -> None:
        for c in self.v["encode"]:
            cur = None if c["current_hex"] is None else bytes.fromhex(c["current_hex"])
            got = self.outcome(lambda: encode(c["dtype"], c["scaling"], parse_canonical(c["target"]), cur).hex())
            want = {"ok": c["expect"]["bytes_hex"]} if "bytes_hex" in c["expect"] else c["expect"]
            self.expect(c["id"], got, want)
            if "ok" in got and cur is None and c["dtype"]["kind"] != "float":
                # R14: raw -> physical -> raw is the identity on the encoded raw value.
                raw = raw_of(c["dtype"], bytes.fromhex(got["ok"]))
                sc = c["scaling"]
                phys = parse_canonical(sc["factor"]) * raw + parse_canonical(sc["addend"])
                self.expect(c["id"] + ".R14", encode(c["dtype"], sc, phys, None).hex(), got["ok"])

    def units(self) -> None:
        for u in self.v["units"]:
            f, a = parse_canonical(u["scaling"]["factor"]), parse_canonical(u["scaling"]["addend"])
            unit, text, k = map_unit(u["unit_text"], f, a)
            self.expect(u["id"], {"unit": unit, "unit_text": text, "scaling": sc_obj(f * k, a * k)}, u["expect"])

    def a2l(self) -> None:
        for c in self.v["a2l_compu"]:
            got = self.outcome(lambda: a2l_compu(c["conversion_type"], c["coeffs"]))
            want = {"ok": c["expect"]["scaling"]} if "scaling" in c["expect"] else c["expect"]
            self.expect(c["id"], got, want)
        for c in self.v["a2l_export"]:
            co = a2l_export(c["scaling"])
            self.expect(c["id"], co, c["expect"]["coeffs"])
            back = a2l_compu("RAT_FUNC", [str(x) for x in co])
            self.expect(c["id"] + ".roundtrip", back, c["scaling"])

    def definitions(self) -> None:
        for name, m in self.v["mapdefs"].items():
            self.expect(f"{name}.mapdef_hash", sha(m["value"]), m["mapdef_hash"])
            if "derive" in m:
                self.expect(f"{name}.map_id", "m_" + sha(m["derive"])[:24], m["value"]["map_id"])
        defs = self.v["definitions"]
        d1 = defs["D1"]
        check_definition(d1["value"])
        self.expect("D1.definition_hash", sha(d1["value"]), d1["definition_hash"])
        for aid, hsh in d1["axisdef_hashes"].items():
            ax = next(a for a in d1["value"]["axes"] if a["axis_id"] == aid)
            self.expect(f"D1.axisdef_hash.{aid}", sha(ax), hsh)
        d2 = dict(defs["D2"]["input"])
        d2["mapdefs"] = sorted(d2["mapdefs"], key=lambda m: m["map_id"].encode("utf-16-be"))
        d2["axes"] = sorted(d2["axes"], key=lambda a: a["axis_id"].encode("utf-16-be"))
        self.expect("D2.sorted_equals_D1", d2, d1["value"])
        self.expect("D2.definition_hash", sha(d2), defs["D2"]["definition_hash"])
        d3 = defs["D3"]
        check_definition(d3["value"])
        self.expect("D3.definition_hash", sha(d3["value"]), d3["definition_hash"])
        self.expect("D3.differs", sha(d3["value"]) != sha(d1["value"]), True)

    def spans(self) -> None:
        for sid, sv in self.v["spans"].items():
            d = sv["definition"] if isinstance(sv["definition"], dict) else self.v["definitions"][sv["definition"]]["value"]
            got = {}
            for m in d["mapdefs"]:
                try:
                    got[m["map_id"]] = span_of(m, d, sv["dump"])
                except Err as e:
                    got[m["map_id"]] = {"error": e.reason}
            self.expect(sid, got, sv["expect"])

    def xdf(self) -> None:
        xe = self.v["xdf"]["XE1"]
        check_definition(xe["definition"])
        self.expect("XE1.definition_hash", sha(xe["definition"]), xe["definition_hash"])
        self.expect("XE1.export", export_xdf(xe["definition"], xe["params"]["memory_id"]), xe["export"])
        back = XdfImport(xe["params"]).run(xe["export"].encode("utf-8"))
        self.expect("XE1.reimport", {"definition_hash": sha(back["definition"]), "rejected": back["rejected"],
                                     "ignored": back["ignored"]}, xe["reimport"])
        xn = self.v["xdf"]["XN1"]
        check_definition(xn["definition"])
        self.expect("XN1.export", export_xdf(xn["definition"], xn["params"]["memory_id"]), xn["export"])
        back = XdfImport(xn["params"]).run(xn["export"].encode("utf-8"))
        self.expect("XN1.normalize", back["definition"], xn["normalized"])
        self.expect("XN1.normalized_hash", sha(back["definition"]), xn["normalized_hash"])
        self.expect("XN1.rejected", back["rejected"], [])
        for u in self.v["xdf"]["export_rejects"]:
            try:
                export_xdf(u["definition"], u["memory_id"])
                got: dict = {"error": None, "field": None}
            except Err as e:
                got = {"error": e.reason, "field": e.field}
            self.expect(u["id"], got, u["expect"])
        x1 = self.v["xdf"]["X1"]
        res = XdfImport(x1["params"]).run(x1["source"].encode("utf-8"))
        exp = x1["expect"]
        check_definition(res["definition"])
        self.expect("X1.definition", res["definition"], exp["definition"])
        self.expect("X1.definition_hash", sha(res["definition"]), exp["definition_hash"])
        self.expect("X1.rejected", res["rejected"], exp["rejected"])
        self.expect("X1.ignored", res["ignored"], exp["ignored"])
        text = export_xdf(res["definition"], x1["params"]["memory_id"])
        self.expect("X1.export", text, x1["export"])
        again = XdfImport(x1["params"]).run(x1["export"].encode("utf-8"))
        self.expect("X1.reimport", {"definition_hash": sha(again["definition"]), "rejected": again["rejected"],
                                    "ignored": again["ignored"]}, x1["reimport"])
        self.expect("X1.R64", sha(again["definition"]), exp["definition_hash"])
        for r in self.v["xdf"]["rejects"]:
            params = x1["params"]
            try:
                got: dict = {"rejected": XdfImport(params).run(r["source"].encode("utf-8"))["rejected"]}
            except Err as e:
                got = {"error": e.reason}
            self.expect(r["id"], got, r["expect"])

    def run(self) -> int:
        for step in (self.rationals, self.decode, self.encode, self.units, self.a2l, self.definitions, self.spans, self.xdf):
            try:
                step()
            except Err as e:
                self.failures.append(f"{step.__name__}: unexpected rejection {e.reason}")
        for f in self.failures:
            print("FAIL", f)
        print(f"{self.checked} checks, {len(self.failures)} failures")
        return 1 if self.failures else 0


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as fh:
        sys.exit(Checker(json.load(fh)).run())
