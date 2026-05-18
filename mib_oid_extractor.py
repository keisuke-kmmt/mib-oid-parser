#!/usr/bin/env python3
"""
Extract OIDs from SNMP MIB files.

This script parses common ASN.1 MIB declarations and resolves numeric OIDs.
It is intentionally lightweight and regex-based, so it works well for many
plain-text MIB files without requiring a full SMI parser.

Supported declaration styles:
- <name> OBJECT IDENTIFIER ::= { parent 1 }
- <name> OBJECT-TYPE ::= { parent 2 }
- <name> MODULE-IDENTITY ::= { enterprises 99999 }
- <name> NOTIFICATION-TYPE ::= { parent 3 }

Output formats:
- table (default)
- json
- csv

Examples:
    python mib_oid_extractor.py MY-MIB.txt
    python mib_oid_extractor.py MY-MIB.txt --format json
    python mib_oid_extractor.py MY-MIB.txt --only-object-type
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


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


DECLARATION_RE = re.compile(
    r"(?ms)^\s*(?P<name>[A-Za-z][\w-]*)\s+"
    r"(?P<kind>OBJECT IDENTIFIER|OBJECT-TYPE|MODULE-IDENTITY|NOTIFICATION-TYPE)"
    r".*?::=\s*\{\s*(?P<body>[^}]*)\}"
)

COMMENT_RE = re.compile(r"--.*?$", re.MULTILINE)
TOKEN_RE = re.compile(r"([A-Za-z][\w-]*|\d+|\([^)]+\))")
PAREN_NUM_RE = re.compile(r"\((\d+)\)")


@dataclass
class OidEntry:
    name: str
    kind: str
    parent: str
    subid: int
    oid: List[int]
    source: str

    @property
    def oid_str(self) -> str:
        return ".".join(str(x) for x in self.oid)


class MibOidExtractor:
    def __init__(self) -> None:
        self.known_oids: Dict[str, List[int]] = dict(ROOT_OIDS)

    def parse_file(self, path: Path) -> List[OidEntry]:
        text = path.read_text(encoding="utf-8", errors="ignore")
        return self.parse_text(text, source=str(path))

    def parse_text(self, text: str, source: str = "<memory>") -> List[OidEntry]:
        cleaned = self._strip_comments(text)
        raw_entries = []

        for match in DECLARATION_RE.finditer(cleaned):
            name = match.group("name")
            kind = match.group("kind")
            body = match.group("body").strip()
            parent, subid = self._parse_oid_body(body)
            if parent is None or subid is None:
                continue
            raw_entries.append((name, kind, parent, subid, source))

        resolved: Dict[str, OidEntry] = {}
        pending = list(raw_entries)
        progress = True

        while pending and progress:
            progress = False
            next_pending = []

            for name, kind, parent, subid, src in pending:
                parent_oid = self.known_oids.get(parent)
                if parent_oid is None:
                    next_pending.append((name, kind, parent, subid, src))
                    continue

                oid = parent_oid + [subid]
                entry = OidEntry(
                    name=name,
                    kind=kind,
                    parent=parent,
                    subid=subid,
                    oid=oid,
                    source=src,
                )
                resolved[name] = entry
                self.known_oids[name] = oid
                progress = True

            pending = next_pending

        return sorted(resolved.values(), key=lambda e: e.oid)

    def _strip_comments(self, text: str) -> str:
        return COMMENT_RE.sub("", text)

    def _parse_oid_body(self, body: str) -> Tuple[Optional[str], Optional[int]]:
        tokens = TOKEN_RE.findall(body)
        if not tokens:
            return None, None

        parent: Optional[str] = None
        numeric_parts: List[int] = []

        for token in tokens:
            if token.isdigit():
                numeric_parts.append(int(token))
                continue

            paren_match = PAREN_NUM_RE.fullmatch(token)
            if paren_match:
                numeric_parts.append(int(paren_match.group(1)))
                continue

            inline_match = re.fullmatch(r"([A-Za-z][\w-]*)\((\d+)\)", token)
            if inline_match:
                parent = inline_match.group(1)
                numeric_parts.append(int(inline_match.group(2)))
                continue

            if parent is None:
                parent = token
            else:
                # If multiple symbolic identifiers are present, prefer the latest
                # unresolved symbolic token as parent. This keeps the extractor
                # simple and works for common patterns like { iso org(3) dod(6) 1 }.
                parent = token

        if parent is None or not numeric_parts:
            return None, None

        return parent, numeric_parts[-1]


def filter_entries(entries: Iterable[OidEntry], only_kind: Optional[str]) -> List[OidEntry]:
    if not only_kind:
        return list(entries)
    return [entry for entry in entries if entry.kind == only_kind]


def print_table(entries: List[OidEntry]) -> None:
    if not entries:
        print("No resolvable OIDs found.")
        return

    name_width = max(len(e.name) for e in entries)
    kind_width = max(len(e.kind) for e in entries)
    oid_width = max(len(e.oid_str) for e in entries)

    header = (
        f"{'NAME':<{name_width}}  "
        f"{'KIND':<{kind_width}}  "
        f"{'OID':<{oid_width}}  "
        f"PARENT"
    )
    print(header)
    print("-" * len(header))
    for entry in entries:
        print(
            f"{entry.name:<{name_width}}  "
            f"{entry.kind:<{kind_width}}  "
            f"{entry.oid_str:<{oid_width}}  "
            f"{entry.parent}"
        )


def print_json(entries: List[OidEntry]) -> None:
    data = [
        {
            "name": e.name,
            "kind": e.kind,
            "parent": e.parent,
            "subid": e.subid,
            "oid": e.oid,
            "oid_str": e.oid_str,
            "source": e.source,
        }
        for e in entries
    ]
    print(json.dumps(data, ensure_ascii=False, indent=2))


def print_csv(entries: List[OidEntry]) -> None:
    writer = csv.writer(sys.stdout)
    writer.writerow(["name", "kind", "parent", "subid", "oid_str", "source"])
    for e in entries:
        writer.writerow([e.name, e.kind, e.parent, e.subid, e.oid_str, e.source])


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Extract and resolve OIDs from SNMP MIB files.")
    parser.add_argument("files", nargs="+", help="Path(s) to MIB file(s)")
    parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--only-kind",
        choices=["OBJECT IDENTIFIER", "OBJECT-TYPE", "MODULE-IDENTITY", "NOTIFICATION-TYPE"],
        help="Filter output by declaration kind",
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    extractor = MibOidExtractor()
    all_entries: List[OidEntry] = []

    for file_name in args.files:
        path = Path(file_name)
        if not path.exists():
            print(f"File not found: {file_name}", file=sys.stderr)
            return 1
        all_entries.extend(extractor.parse_file(path))

    entries = filter_entries(all_entries, args.only_kind)

    if args.format == "json":
        print_json(entries)
    elif args.format == "csv":
        print_csv(entries)
    else:
        print_table(entries)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
