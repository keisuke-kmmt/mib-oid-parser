#!/usr/bin/env python3
"""
Extract and resolve OIDs from SNMP MIB files without external dependencies.

Features:
- Standard-library only
- Tokenizer + parser based implementation
- Resolves symbols across multiple input MIB files
- Can search dependent MIB modules from directories via IMPORTS

Supported declarations:
- <name> OBJECT IDENTIFIER ::= { ... }
- <name> OBJECT-TYPE ::= { ... }
- <name> MODULE-IDENTITY ::= { ... }
- <name> NOTIFICATION-TYPE ::= { ... }
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple


ROOT_OIDS: Dict[str, List[int]] = {
    "iso": [1],
    "org": [1, 3],
    "dod": [1, 3, 6],
    "internet": [1, 3, 6, 1],
    "directory": [1, 3, 6, 1, 1],
    "mgmt": [1, 3, 6, 1, 2],
    "mib-2": [1, 3, 6, 1, 2, 1],
    "transmission": [1, 3, 6, 1, 2, 1, 10],
    "experimental": [1, 3, 6, 1, 3],
    "private": [1, 3, 6, 1, 4],
    "enterprises": [1, 3, 6, 1, 4, 1],
    "security": [1, 3, 6, 1, 5],
    "snmpV2": [1, 3, 6, 1, 6],
    "snmpDomains": [1, 3, 6, 1, 6, 1],
    "snmpProxys": [1, 3, 6, 1, 6, 2],
    "snmpModules": [1, 3, 6, 1, 6, 3],
}

SUPPORTED_KINDS = {
    "OBJECT IDENTIFIER",
    "OBJECT-TYPE",
    "MODULE-IDENTITY",
    "NOTIFICATION-TYPE",
}

KEYWORDS = {
    "OBJECT",
    "IDENTIFIER",
    "OBJECT-TYPE",
    "MODULE-IDENTITY",
    "NOTIFICATION-TYPE",
    "IMPORTS",
    "FROM",
    "DEFINITIONS",
    "BEGIN",
    "END",
}

DEFAULT_MIB_SUFFIXES = {"", ".mib", ".txt", ".my", ".asn1"}


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    pos: int


@dataclass(frozen=True)
class OidComponent:
    symbol: Optional[str]
    number: Optional[int]


@dataclass
class Declaration:
    name: str
    kind: str
    oid_components: List[OidComponent]
    source: str
    module_name: Optional[str]


@dataclass
class OidEntry:
    name: str
    kind: str
    oid: List[int]
    source: str
    module_name: Optional[str]

    @property
    def oid_str(self) -> str:
        return ".".join(str(x) for x in self.oid)


@dataclass
class ParsedMib:
    source: str
    module_name: Optional[str]
    imports: List[str]
    declarations: List[Declaration]


class Tokenizer:
    def __init__(self, text: str) -> None:
        self.text = text
        self.length = len(text)
        self.pos = 0

    def tokenize(self) -> List[Token]:
        tokens: List[Token] = []
        while self.pos < self.length:
            ch = self.text[self.pos]

            if ch.isspace():
                self.pos += 1
                continue

            if ch == "-" and self._peek(1) == "-":
                self._skip_comment()
                continue

            if self.text.startswith("::=", self.pos):
                tokens.append(Token("ASSIGN", "::=", self.pos))
                self.pos += 3
                continue

            if ch == "{":
                tokens.append(Token("LBRACE", ch, self.pos))
                self.pos += 1
                continue
            if ch == "}":
                tokens.append(Token("RBRACE", ch, self.pos))
                self.pos += 1
                continue
            if ch == "(":
                tokens.append(Token("LPAREN", ch, self.pos))
                self.pos += 1
                continue
            if ch == ")":
                tokens.append(Token("RPAREN", ch, self.pos))
                self.pos += 1
                continue
            if ch == ",":
                tokens.append(Token("COMMA", ch, self.pos))
                self.pos += 1
                continue
            if ch == ";":
                tokens.append(Token("SEMI", ch, self.pos))
                self.pos += 1
                continue

            if ch.isdigit():
                start = self.pos
                while self.pos < self.length and self.text[self.pos].isdigit():
                    self.pos += 1
                tokens.append(Token("NUMBER", self.text[start:self.pos], start))
                continue

            if ch.isalpha():
                start = self.pos
                self.pos += 1
                while self.pos < self.length and (self.text[self.pos].isalnum() or self.text[self.pos] == "-"):
                    self.pos += 1
                value = self.text[start:self.pos]
                kind = "KEYWORD" if value in KEYWORDS else "IDENT"
                tokens.append(Token(kind, value, start))
                continue

            self.pos += 1

        return tokens

    def _peek(self, offset: int) -> str:
        idx = self.pos + offset
        if idx >= self.length:
            return ""
        return self.text[idx]

    def _skip_comment(self) -> None:
        self.pos += 2
        while self.pos < self.length and self.text[self.pos] not in "\r\n":
            self.pos += 1


class Parser:
    def __init__(self, tokens: Sequence[Token], source: str) -> None:
        self.tokens = tokens
        self.source = source
        self.pos = 0
        self.module_name = self._detect_module_name()

    def parse(self) -> ParsedMib:
        imports = self._parse_imports()
        declarations = self.parse_declarations()
        return ParsedMib(
            source=self.source,
            module_name=self.module_name,
            imports=imports,
            declarations=declarations,
        )

    def parse_declarations(self) -> List[Declaration]:
        declarations: List[Declaration] = []
        self.pos = 0
        while not self._at_end():
            declaration = self._parse_one_declaration()
            if declaration is not None:
                declarations.append(declaration)
            else:
                self.pos += 1
        return declarations

    def _detect_module_name(self) -> Optional[str]:
        for idx in range(len(self.tokens) - 2):
            a = self.tokens[idx]
            b = self.tokens[idx + 1]
            c = self.tokens[idx + 2]
            if a.kind == "IDENT" and b.value == "DEFINITIONS" and c.kind == "ASSIGN":
                return a.value
        return None

    def _parse_imports(self) -> List[str]:
        imports: List[str] = []
        idx = 0
        while idx < len(self.tokens):
            tok = self.tokens[idx]
            if tok.value != "IMPORTS":
                idx += 1
                continue

            idx += 1
            while idx < len(self.tokens):
                current = self.tokens[idx]
                if current.kind == "SEMI":
                    return imports
                if current.value == "FROM":
                    next_tok = self._peek_index(idx + 1)
                    if next_tok is not None and next_tok.kind == "IDENT":
                        imports.append(next_tok.value)
                        idx += 2
                        continue
                idx += 1
        return imports

    def _parse_one_declaration(self) -> Optional[Declaration]:
        start = self.pos
        name_tok = self._current()
        if name_tok is None or name_tok.kind != "IDENT":
            return None

        kind, consumed = self._match_kind(self.pos + 1)
        if kind is None:
            return None

        self.pos = self.pos + 1 + consumed
        if not self._match("ASSIGN"):
            self.pos = start
            return None
        if not self._match("LBRACE"):
            self.pos = start
            return None

        oid_components = self._parse_oid_expression()
        if not oid_components:
            self.pos = start
            return None

        if not self._match("RBRACE"):
            self.pos = start
            return None

        return Declaration(
            name=name_tok.value,
            kind=kind,
            oid_components=oid_components,
            source=self.source,
            module_name=self.module_name,
        )

    def _parse_oid_expression(self) -> List[OidComponent]:
        components: List[OidComponent] = []
        while not self._at_end():
            token = self._current()
            if token is None or token.kind == "RBRACE":
                break
            if token.kind == "COMMA":
                self.pos += 1
                continue

            component = self._parse_oid_component()
            if component is None:
                self.pos += 1
                continue
            components.append(component)

        return components

    def _parse_oid_component(self) -> Optional[OidComponent]:
        token = self._current()
        if token is None:
            return None

        if token.kind == "NUMBER":
            self.pos += 1
            return OidComponent(symbol=None, number=int(token.value))

        if token.kind in {"IDENT", "KEYWORD"}:
            symbol = token.value
            self.pos += 1
            if self._match("LPAREN"):
                number_tok = self._current()
                if number_tok is None or number_tok.kind != "NUMBER":
                    return OidComponent(symbol=symbol, number=None)
                self.pos += 1
                self._match("RPAREN")
                return OidComponent(symbol=symbol, number=int(number_tok.value))
            return OidComponent(symbol=symbol, number=None)

        return None

    def _match_kind(self, start: int) -> Tuple[Optional[str], int]:
        patterns = [
            (["OBJECT", "IDENTIFIER"], "OBJECT IDENTIFIER"),
            (["OBJECT-TYPE"], "OBJECT-TYPE"),
            (["MODULE-IDENTITY"], "MODULE-IDENTITY"),
            (["NOTIFICATION-TYPE"], "NOTIFICATION-TYPE"),
        ]
        for expected, kind in patterns:
            ok = True
            for idx, expected_value in enumerate(expected):
                token = self._peek_index(start + idx)
                if token is None or token.value != expected_value:
                    ok = False
                    break
            if ok:
                return kind, len(expected)
        return None, 0

    def _match(self, kind: str) -> bool:
        token = self._current()
        if token is None or token.kind != kind:
            return False
        self.pos += 1
        return True

    def _current(self) -> Optional[Token]:
        return self._peek_index(self.pos)

    def _peek_index(self, index: int) -> Optional[Token]:
        if index >= len(self.tokens):
            return None
        return self.tokens[index]

    def _at_end(self) -> bool:
        return self.pos >= len(self.tokens)


class Resolver:
    def __init__(self) -> None:
        self.symbols: Dict[str, List[int]] = dict(ROOT_OIDS)

    def resolve(self, declarations: Sequence[Declaration]) -> Tuple[List[OidEntry], List[Declaration]]:
        resolved_entries: Dict[str, OidEntry] = {}
        pending = list(declarations)
        progress = True

        while pending and progress:
            progress = False
            next_pending: List[Declaration] = []

            for decl in pending:
                oid = self._resolve_oid_components(decl.oid_components)
                if oid is None:
                    next_pending.append(decl)
                    continue

                entry = OidEntry(
                    name=decl.name,
                    kind=decl.kind,
                    oid=oid,
                    source=decl.source,
                    module_name=decl.module_name,
                )
                resolved_entries[decl.name] = entry
                self.symbols[decl.name] = oid
                progress = True

            pending = next_pending

        return sorted(resolved_entries.values(), key=lambda e: e.oid), pending

    def _resolve_oid_components(self, components: Sequence[OidComponent]) -> Optional[List[int]]:
        result: List[int] = []
        for component in components:
            if component.symbol is not None:
                if component.number is not None:
                    result.append(component.number)
                    continue
                symbol_oid = self.symbols.get(component.symbol)
                if symbol_oid is None:
                    return None
                result.extend(symbol_oid)
                continue
            if component.number is not None:
                result.append(component.number)
                continue
            return None
        return result if result else None


class MibRepository:
    def __init__(self, mib_dirs: Sequence[Path], recursive: bool = True) -> None:
        self.mib_dirs = [path for path in mib_dirs if path.exists() and path.is_dir()]
        self.recursive = recursive
        self.module_to_path: Dict[str, Path] = {}
        self._indexed_paths: Set[Path] = set()

    def build_index(self) -> None:
        for mib_dir in self.mib_dirs:
            for path in self._iter_candidate_files(mib_dir):
                if path in self._indexed_paths:
                    continue
                self._indexed_paths.add(path)
                module_name = self._probe_module_name(path)
                if module_name and module_name not in self.module_to_path:
                    self.module_to_path[module_name] = path

    def find_module(self, module_name: str) -> Optional[Path]:
        return self.module_to_path.get(module_name)

    def _iter_candidate_files(self, root: Path) -> Iterator[Path]:
        iterator = root.rglob("*") if self.recursive else root.glob("*")
        for path in iterator:
            if not path.is_file():
                continue
            suffix = path.suffix.lower()
            if suffix in DEFAULT_MIB_SUFFIXES:
                yield path

    def _probe_module_name(self, path: Path) -> Optional[str]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return None
        tokens = Tokenizer(text).tokenize()
        parser = Parser(tokens, str(path))
        return parser.module_name


class MibLoader:
    def __init__(self, mib_dirs: Sequence[Path], recursive: bool = True) -> None:
        self.repo = MibRepository(mib_dirs, recursive=recursive)
        self.repo.build_index()
        self.loaded_paths: Set[Path] = set()
        self.loaded_modules: Set[str] = set()
        self.unresolved_modules: Set[str] = set()

    def load(self, entry_paths: Sequence[Path]) -> List[ParsedMib]:
        parsed: List[ParsedMib] = []
        queue: List[Path] = list(entry_paths)

        while queue:
            path = queue.pop(0)
            path = path.resolve()
            if path in self.loaded_paths:
                continue
            self.loaded_paths.add(path)

            mib = self._parse_path(path)
            if mib is None:
                continue
            parsed.append(mib)
            if mib.module_name:
                self.loaded_modules.add(mib.module_name)

            for module_name in mib.imports:
                if module_name in self.loaded_modules:
                    continue
                dep_path = self.repo.find_module(module_name)
                if dep_path is None:
                    self.unresolved_modules.add(module_name)
                    continue
                queue.append(dep_path)

        return parsed

    def _parse_path(self, path: Path) -> Optional[ParsedMib]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return None
        tokens = Tokenizer(text).tokenize()
        return Parser(tokens, str(path)).parse()


def extract_from_files(
    paths: Sequence[Path],
    mib_dirs: Sequence[Path],
    recursive: bool = True,
) -> Tuple[List[OidEntry], List[Declaration], Set[str]]:
    loader = MibLoader(mib_dirs, recursive=recursive)
    parsed_mibs = loader.load(paths)

    declarations: List[Declaration] = []
    for mib in parsed_mibs:
        declarations.extend(mib.declarations)

    resolver = Resolver()
    entries, unresolved_declarations = resolver.resolve(declarations)
    return entries, unresolved_declarations, loader.unresolved_modules


def filter_entries(entries: Iterable[OidEntry], only_kind: Optional[str]) -> List[OidEntry]:
    if only_kind is None:
        return list(entries)
    return [entry for entry in entries if entry.kind == only_kind]


def print_table(entries: List[OidEntry]) -> None:
    if not entries:
        print("No resolvable OIDs found.")
        return

    name_width = max(len(e.name) for e in entries)
    kind_width = max(len(e.kind) for e in entries)
    oid_width = max(len(e.oid_str) for e in entries)
    source_width = max(len(e.source) for e in entries)

    header = (
        f"{'NAME':<{name_width}}  "
        f"{'KIND':<{kind_width}}  "
        f"{'OID':<{oid_width}}  "
        f"{'SOURCE':<{source_width}}"
    )
    print(header)
    print("-" * len(header))
    for entry in entries:
        print(
            f"{entry.name:<{name_width}}  "
            f"{entry.kind:<{kind_width}}  "
            f"{entry.oid_str:<{oid_width}}  "
            f"{entry.source:<{source_width}}"
        )


def print_json(entries: List[OidEntry]) -> None:
    data = [
        {
            "name": e.name,
            "kind": e.kind,
            "oid": e.oid,
            "oid_str": e.oid_str,
            "source": e.source,
            "module_name": e.module_name,
        }
        for e in entries
    ]
    print(json.dumps(data, ensure_ascii=False, indent=2))


def print_csv(entries: List[OidEntry]) -> None:
    writer = csv.writer(sys.stdout)
    writer.writerow(["name", "kind", "oid_str", "module_name", "source"])
    for e in entries:
        writer.writerow([e.name, e.kind, e.oid_str, e.module_name or "", e.source])


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Extract and resolve OIDs from SNMP MIB files without external dependencies."
    )
    parser.add_argument("files", nargs="+", help="Path(s) to entry MIB files")
    parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--only-kind",
        choices=sorted(SUPPORTED_KINDS),
        help="Filter output by declaration kind",
    )
    parser.add_argument(
        "--mib-dir",
        action="append",
        default=[],
        help="Directory to search for imported dependent MIB files (can be specified multiple times)",
    )
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Do not recursively search --mib-dir directories",
    )
    parser.add_argument(
        "--show-unresolved",
        action="store_true",
        help="Print unresolved declarations and missing imported modules to stderr",
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    paths = [Path(name) for name in args.files]
    missing = [str(path) for path in paths if not path.exists()]
    if missing:
        for path in missing:
            print(f"File not found: {path}", file=sys.stderr)
        return 1

    mib_dirs = [Path(name) for name in args.mib_dir]
    entries, unresolved_declarations, unresolved_modules = extract_from_files(
        paths=paths,
        mib_dirs=mib_dirs,
        recursive=not args.no_recursive,
    )
    entries = filter_entries(entries, args.only_kind)

    if args.format == "json":
        print_json(entries)
    elif args.format == "csv":
        print_csv(entries)
    else:
        print_table(entries)

    if args.show_unresolved:
        if unresolved_modules:
            print("\nMissing imported modules:", file=sys.stderr)
            for module_name in sorted(unresolved_modules):
                print(f"- {module_name}", file=sys.stderr)
        if unresolved_declarations:
            print("\nUnresolved declarations:", file=sys.stderr)
            for decl in unresolved_declarations:
                module_hint = f" [{decl.module_name}]" if decl.module_name else ""
                print(f"- {decl.name} ({decl.kind}) in {decl.source}{module_hint}", file=sys.stderr)

    return 0 if entries or not unresolved_declarations else 2


if __name__ == "__main__":
    raise SystemExit(main())
