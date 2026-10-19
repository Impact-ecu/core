"""A safe XML reader for XDF input (SPEC-003 R60, R80).

Expat is used with every DTD hook turned into a rejection: a document type declaration, an entity or
notation declaration, or an external reference raises `xml_forbidden` the moment expat sees it, so
no entity is ever expanded and nothing is fetched. Undefined entities are an expat error (`bad_xml`).
"""

from dataclasses import dataclass, field
from typing import NoReturn
from xml.parsers import expat

from core.definitions._errors import DefinitionError


@dataclass(eq=False, slots=True)
class Node:
    """An element. `index` is its 0-based position among siblings with the same name (R61)."""

    name: str
    attrs: dict[str, str]
    parent: "Node | None"
    index: int
    children: list["Node"] = field(default_factory=list)
    chunks: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return "".join(self.chunks)

    @property
    def path(self) -> str:
        """R61: `/`-joined names with `[i]`. Built on demand, so deep input costs no quadratic memory."""
        parts: list[str] = []
        node: Node | None = self
        while node is not None:
            parts.append(f"{node.name}[{node.index}]")
            node = node.parent
        return "/".join(reversed(parts))

    def attribute_path(self, name: str) -> str:
        return f"{self.path}/@{name}"


class _Builder:
    def __init__(self) -> None:
        self.roots: list[Node] = []
        self.stack: list[Node] = []
        self.counters: list[dict[str, int]] = [{}]

    def start(self, name: str, attrs: dict[str, str]) -> None:
        counter = self.counters[-1]
        index = counter.get(name, 0)
        counter[name] = index + 1
        parent = self.stack[-1] if self.stack else None
        node = Node(name, attrs, parent, index)
        (self.roots if parent is None else parent.children).append(node)
        self.stack.append(node)
        self.counters.append({})

    def end(self, _name: str) -> None:
        self.stack.pop()
        self.counters.pop()

    def characters(self, text: str) -> None:
        # Expat reports character data only inside the root element.
        self.stack[-1].chunks.append(text)


def _forbid(*_args: object) -> NoReturn:
    raise DefinitionError("xml_forbidden", "DTDs, entity declarations and external references are not accepted")


def _declaration(_version: str, encoding: str | None, _standalone: int) -> None:
    if encoding is not None and encoding not in ("UTF-8", "utf-8"):
        raise DefinitionError("unsupported_encoding", encoding)


def parse_xml(data: bytes) -> Node:
    """The element tree of `data`. File-level failures raise (R61, R80)."""
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        raise DefinitionError("unsupported_encoding", "the input is not UTF-8") from None
    builder = _Builder()
    parser = expat.ParserCreate(encoding="UTF-8")
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.StartDoctypeDeclHandler = _forbid
    parser.EntityDeclHandler = _forbid
    parser.UnparsedEntityDeclHandler = _forbid
    parser.NotationDeclHandler = _forbid
    parser.ExternalEntityRefHandler = _forbid
    parser.XmlDeclHandler = _declaration
    parser.StartElementHandler = builder.start
    parser.EndElementHandler = builder.end
    parser.CharacterDataHandler = builder.characters
    try:
        parser.Parse(data, True)
    except expat.ExpatError as error:
        raise DefinitionError("bad_xml", str(error)) from None
    # A document without a root element is an ExpatError ("no element found"), so there is exactly one.
    return builder.roots[0]
