"""Use API-88.4's existing SD-streamed relocations with a small symbol cache.

Build-only transformation. Fold INTERNAL R_ARM_ABS32 symbol offsets into their
32-bit addends and reference the existing zero-valued section symbol instead.
The pinned loader adds symAddr to that word, so A + (base + S) == (A + S) + base
modulo 2**32, including the Thumb-state low bit. Branch/imports are untouched.
Reject unexpected formats; verify ALL loaded bytes and relocation expressions
before replacing the build artifact. No runtime loader or firmware change.
"""

import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from check_fap_memory import IGNORED_PREFIXES, read_sections

SYMBOL = struct.Struct("<IIIBBH")
REL = struct.Struct("<II")
ABS32 = 2
THM_JUMP24 = 30
UINT32_MASK = 0xFFFFFFFF
BASE_PREFIX = "__tb2_section_base_"


def content(data, section):
    return data[section["offset"] : section["offset"] + section["size"]]


def symbol_table(data, sections):
    """Read only the normal symbol table used by the pinned firmware loader."""
    indexed = {s["index"]: s for s in sections}
    table = next(s for s in sections if s["name"] == ".symtab")
    if table["type"] != 2 or table["entry_size"] != SYMBOL.size:
        raise ValueError("Unexpected symbol table format")
    if table["size"] % SYMBOL.size:
        raise ValueError("Truncated symbol table")
    strings = indexed[table["link"]]
    if strings["name"] != ".strtab" or strings["type"] != 3:
        raise ValueError("Unexpected symbol string table")
    names = content(data, strings)
    result = []
    for name, value, size, info, other, target in SYMBOL.iter_unpack(
        content(data, table)
    ):
        end = names.find(b"\0", name)
        if name >= len(names) or end < 0:
            raise ValueError("Invalid symbol name")
        result.append(
            {
                "name": names[name:end].decode("ascii"),
                "value": value,
                "target": target,
                "info": info,
                "size": size,
                "other": other,
            }
        )
    return table, result


def normal_relocations(data):
    """Validate and expand every runtime .rel record, retaining its file offset."""
    sections = read_sections(data)
    indexed = {s["index"]: s for s in sections}
    table, symbols = symbol_table(data, sections)
    occupied = set()
    records = []
    for rel in sections:
        if not rel["name"].startswith(".rel.") or rel["name"].startswith(
            IGNORED_PREFIXES
        ):
            continue
        if rel["type"] != 9 or rel["entry_size"] != REL.size or rel["size"] % REL.size:
            raise ValueError("Unexpected/truncated REL table")
        dest = indexed.get(rel["info"])
        if (
            not dest
            or dest["name"] != rel["name"][4:]
            or not dest["flags"] & 2
            or dest["type"] == 8
            or rel["link"] != table["index"]
            or not rel["flags"] & 0x40
            or rel["flags"] & 2
        ):
            raise ValueError("Invalid streamed relocation destination/table")
        for i, (offset, info) in enumerate(REL.iter_unpack(content(data, rel))):
            symbol_id, kind = info >> 8, info & 255
            if kind not in (ABS32, THM_JUMP24):
                raise ValueError(f"Unexpected streamed relocation type {kind}")
            if offset + 4 > dest["size"] or offset % (4 if kind == ABS32 else 2):
                raise ValueError("Unaligned/out-of-range relocation")
            sites = {(dest["index"], offset + byte) for byte in range(4)}
            if occupied & sites:
                raise ValueError("Overlapping relocation writes")
            occupied.update(sites)
            if symbol_id >= len(symbols):
                raise ValueError("Invalid relocation symbol index")
            symbol = symbols[symbol_id]
            if symbol["target"]:
                target = indexed.get(symbol["target"])
                if (
                    not target
                    or not target["flags"] & 2
                    or target["name"].startswith(IGNORED_PREFIXES)
                    or (symbol["value"] & ~1) > target["size"]
                ):
                    raise ValueError("Invalid internal relocation target")
                target_name = target["name"]
            else:
                if not symbol["name"] or symbol["value"]:
                    raise ValueError("Invalid imported symbol")
                target_name = symbol["name"]
            records.append(
                {
                    "destination": dest["name"],
                    "offset": offset,
                    "kind": kind,
                    "symbol_id": symbol_id,
                    "internal": bool(symbol["target"]),
                    "target": target_name,
                    "value": symbol["value"],
                    "target_index": symbol["target"],
                    "word_offset": dest["offset"] + offset,
                    "entry_offset": rel["offset"] + i * REL.size,
                }
            )
    if not records:
        raise ValueError("No streamed relocations")
    return records


def base_symbols(symbols):
    return {
        s["target"]: i
        for i, s in enumerate(symbols)
        if s["target"]
        and s["value"] == 0
        and (s["info"] == 3 or (s["info"] == 0 and s["name"].startswith(BASE_PREFIX)))
    }


def normalize(data):
    """Canonicalize internal ABS32 references without changing ELF table layout."""
    sections = read_sections(data)
    _, symbols = symbol_table(data, sections)
    section_symbols = base_symbols(symbols)
    result = bytearray(data)
    for rel in normal_relocations(data):
        if not rel["internal"] or rel["kind"] != ABS32:
            continue
        symbol = section_symbols.get(rel["target_index"])
        if symbol is None:
            raise ValueError("Missing zero-valued section symbol")
        word = struct.unpack_from("<I", data, rel["word_offset"])[0]
        struct.pack_into(
            "<I", result, rel["word_offset"], (word + rel["value"]) & UINT32_MASK
        )
        REL.pack_into(result, rel["entry_offset"], rel["offset"], (symbol << 8) | ABS32)
    return bytes(result)


def signatures(data, fast=False):
    """Canonical relocation expressions and untouched loaded bytes, by section name.

    Equality proves ABS32 equivalence for ANY section base/import address, not
    only one hypothetical RAM layout. All other relocation words remain exact.
    """
    sections = read_sections(data)
    loaded = {
        s["name"]: bytearray(bytes(s["size"]) if s["type"] == 8 else content(data, s))
        for s in sections
        if s["flags"] & 2 and not s["name"].startswith(IGNORED_PREFIXES)
    }
    expressions = {}
    if fast:
        # Independent decoding of the format actually executed by the old FAL.
        from check_fap_loader import relocation_records

        indexed = {s["index"]: s for s in sections}
        named = {s["name"]: s for s in sections}
        records = []
        for section in sections:
            if not section["name"].startswith(".fast.rel.") or section[
                "name"
            ].startswith(IGNORED_PREFIXES):
                continue
            dest = named[section["name"].removeprefix(".fast.rel")]
            for kind, internal, target, value, offsets in relocation_records(
                content(data, section)
            ):
                for offset in offsets:
                    records.append(
                        {
                            "destination": dest["name"],
                            "offset": offset,
                            "kind": kind,
                            "internal": internal,
                            "target": indexed[target]["name"] if internal else target,
                            "value": value,
                        }
                    )
    else:
        from check_fap_loader import gnu_hash

        records = normal_relocations(data)
        for rel in records:
            if not rel["internal"]:
                rel["target"] = gnu_hash(rel["target"])
    for rel in records:
        buf = loaded[rel["destination"]]
        site = (rel["destination"], rel["offset"])
        if site in expressions or rel["offset"] + 4 > len(buf):
            raise ValueError("Duplicate/out-of-range relocation expression")
        word = struct.unpack_from("<I", buf, rel["offset"])[0]
        term = (
            ((word + rel["value"]) & UINT32_MASK)
            if rel["kind"] == ABS32
            else (word, rel["value"])
        )
        expressions[site] = (
            rel["kind"],
            rel["internal"],
            rel["target"],
            term,
        )
        buf[rel["offset"] : rel["offset"] + 4] = bytes(4)
    shape = [
        (s["name"], s["flags"], s["size"], s["alignment"], s["type"])
        for s in sections
        if s["name"] in loaded
    ]
    return data[24:28], shape, loaded, expressions


def verify_equivalent(before, after):
    fast = any(s["name"].startswith(".fast.rel.") for s in read_sections(before))
    if signatures(before, fast) != signatures(after):
        raise ValueError("Loaded image/relocation semantics changed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("objcopy")
    parser.add_argument("--revision")
    parser.add_argument("--fastfap", type=Path,
                        help="Repack canonical references with the pinned SDK FastFAP tool")
    args = parser.parse_args()
    before = args.artifact.read_bytes()
    fast = [
        s["name"] for s in read_sections(before) if s["name"].startswith(".fast.rel.")
    ]
    if not fast:
        raise ValueError("Expected freshly packaged FastFAP input")
    with tempfile.TemporaryDirectory(prefix="tb2-stream-") as temporary:
        output = Path(temporary) / "backend.fal"
        sections = read_sections(before)
        _, symbols = symbol_table(before, sections)
        bases = base_symbols(symbols)
        # --strip-unneeded may remove section symbols that had no original REL
        # references (notably .tb2math/.tb2fs). Let objcopy add local zero-base
        # aliases and update all symbol indices; never hand-shift ELF tables.
        aliases = [
            f"--add-symbol={BASE_PREFIX}{s['index']}={s['name']}:0,local"
            for s in sections
            if s["flags"] & 2
            and not s["name"].startswith(IGNORED_PREFIXES)
            and s["index"] not in bases
        ]
        subprocess.run(
            [
                args.objcopy,
                *[f"--remove-section={s}" for s in fast],
                *aliases,
                str(args.artifact),
                str(output),
            ],
            check=True,
        )
        after = normalize(output.read_bytes())
        verify_equivalent(before, after)
        if args.fastfap:
            output.write_bytes(after)
            subprocess.run([sys.executable, str(args.fastfap), str(output), args.objcopy], check=True)
            after = output.read_bytes()
            if signatures(before, True) != signatures(after, True):
                raise ValueError("Repacked FastFAP relocation semantics changed")
        if not args.fastfap and any(s["name"].startswith(".fast.rel.") for s in read_sections(after)):
            raise ValueError("Fast tables still present after conversion")
        report = {
            "tool_revision": args.revision,
            "before_sha256": hashlib.sha256(before).hexdigest(),
            "after_sha256": hashlib.sha256(after).hexdigest(),
            "relocation_writes": len(normal_relocations(after)),
            "symbols_before": len({r["symbol_id"] for r in normal_relocations(before)}),
            "symbols_after": len({r["symbol_id"] for r in normal_relocations(after)}),
            "removed_fast_bytes": sum(
                s["size"]
                for s in read_sections(before)
                if s["name"] in fast and not s["name"].startswith(IGNORED_PREFIXES)
            ) - sum(s["size"] for s in read_sections(after)
                    if s["name"].startswith(".fast.rel.")
                    and not s["name"].startswith(IGNORED_PREFIXES)),
            "equivalence": "All resident bytes, entry and relocation expressions identical for arbitrary bases",
        }
        args.artifact.write_bytes(after)
        args.artifact.with_suffix(".stream.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
        print("STREAM BACKEND PASS: " + json.dumps(report))


if __name__ == "__main__":
    main()
