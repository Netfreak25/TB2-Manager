"""Validate the actual embedded FAL's entry, manifest and relocations.

Follows the selected pinned firmware loader format; does not execute ARM code or claim
hardware heap acceptance. Unlike FBT's default plugin APPCHK, imports are fatal.
"""

import argparse
import csv
import hashlib
import json
import struct
from pathlib import Path

from check_fap_memory import (
    ELF_HEADER,
    SECTION_HEADER,
    read_sections,
    unpack_plugins,
)
from stream_backend import normal_relocations

SUPPORTED_RELOCATIONS = {2, 10, 30, 38, 47, 48}
def gnu_hash(name):
    value = 0x1505
    for byte in name.encode("ascii"):
        value = (value * 33 + byte) & 0xFFFFFFFF
    return value


def relocation_records(data):
    """Decode bounded fast-relocation records including 24-bit write offsets."""
    cursor = 0

    def take(size):
        nonlocal cursor
        if size > len(data) - cursor:
            raise ValueError("Truncated fast relocation")
        result = data[cursor : cursor + size]
        cursor += size
        return result

    def uint():
        return struct.unpack("<I", take(4))[0]

    if take(1) != b"\x01":
        raise ValueError("Unsupported fast relocation version")
    for _ in range(uint()):
        tag = take(1)[0]
        kind, internal = tag & 0x7F, bool(tag & 0x80)
        target = uint()
        value = uint() if internal else 0
        if kind not in SUPPORTED_RELOCATIONS:
            raise ValueError(f"Unsupported relocation type {kind}")
        offsets = take(uint() * 3)
        yield (
            kind,
            internal,
            target,
            value,
            [
                int.from_bytes(offsets[i : i + 3], "little")
                for i in range(0, len(offsets), 3)
            ],
        )
    if cursor != len(data):
        raise ValueError("Trailing fast relocation data")


def check_binary(data, api, expected_api, expected_manifest_size, plugin):
    sections = read_sections(data)
    named = {section["name"]: section for section in sections}
    indexed = dict(enumerate(sections, 1))

    def content(section):
        return data[section["offset"] : section["offset"] + section["size"]]

    manifest = content(named[".fapmeta"])
    if len(manifest) != expected_manifest_size:
        raise ValueError(
            f"Invalid manifest size {len(manifest)}; expected {expected_manifest_size}"
        )
    magic, version, api_version, target, stack = struct.unpack_from("<IIIHH", manifest)
    if (magic, version, api_version, target) != (0x52474448, 1, expected_api, 7):
        raise ValueError("Manifest API does not match the selected F7 SDK")
    if (stack == 0) != plugin:
        raise ValueError("Wrong app/plugin manifest type")
    header = ELF_HEADER.unpack_from(data)
    text_index = next(i for i, s in indexed.items() if s["name"] == ".text")
    text_address = SECTION_HEADER.unpack_from(
        data, header[6] + text_index * header[11]
    )[3]
    if text_address or not header[4] & 1 or header[4] >= named[".text"]["size"]:
        raise ValueError("Entry must be a Thumb offset inside zero-based .text")
    imports, patches = set(), 0
    for section in sections:
        name = section["name"]
        if not name.startswith(".fast.rel.") or name.startswith(".fast.rel.ARM."):
            continue
        destination = named[name.removeprefix(".fast.rel")]
        if not destination["flags"] & 2:
            raise ValueError("Relocation destination is not resident")
        for _, internal, symbol, value, offsets in relocation_records(content(section)):
            if internal:
                target_section = indexed.get(symbol)
                if (
                    not target_section
                    or not target_section["flags"] & 2
                    or target_section["name"].startswith(".ARM.")
                    or (value & ~1) > target_section["size"]
                ):
                    raise ValueError(
                        "Relocation references an invalid resident section"
                    )
            elif symbol not in api:
                raise ValueError(f"Unresolved firmware import hash {symbol:08x}")
            else:
                imports.add(api[symbol])
            if any(offset + 4 > destination["size"] for offset in offsets):
                raise ValueError("Relocation writes outside section")
            patches += len(offsets)
    mode = "fast"
    cached_symbols = 0
    if not patches:
        mode = "streamed"
        records = normal_relocations(data)
        for rel in records:
            if not rel["internal"]:
                if gnu_hash(rel["target"]) not in api:
                    raise ValueError(f"Unresolved firmware import {rel['target']}")
                imports.add(rel["target"])
        patches = len(records)
        cached_symbols = len({r["symbol_id"] for r in records})
    return {
        "imports": sorted(imports),
        "relocation_writes": patches,
        "stack": stack,
        "mode": mode,
        "cached_symbols": cached_symbols,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fap", type=Path)
    parser.add_argument("--api", type=Path, required=True)
    parser.add_argument("--manifest-size", type=int, choices=(85, 86), required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--module-dir", type=Path)
    args = parser.parse_args()
    with args.api.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
        api = {
            gnu_hash(row["name"]): row["name"]
            for row in rows
            if row["status"] == "+" and row["entry"] in ("Function", "Variable")
        }
    versions = [row["name"] for row in rows if row["entry"] == "Version"]
    if len(versions) != 1:
        raise ValueError("SDK API table has no unique version")
    major, minor = (int(value) for value in versions[0].split(".", 1))
    expected_api = (major << 16) | minor
    data = args.fap.read_bytes()
    asset = next(s for s in read_sections(data) if s["name"] == ".fapassets")
    plugins = unpack_plugins(
        data[asset["offset"] : asset["offset"] + asset["size"]]
    )
    if args.module_dir:
        required = {
            "backend", "cert", "setup", "aux", "spi", "fliptdi",
            "export", "boxes", "store", "imports",
        }
        if set(plugins) != required:
            raise ValueError("The FAP requires exactly ten embedded processing/UI modules")
        for name, binary in plugins.items():
            if binary != (args.module_dir / f"tb2_{name}.fal").read_bytes():
                raise ValueError(f"Embedded {name} differs from its API-checked FAL")
    report = {
        "frontend": check_binary(data, api, expected_api, args.manifest_size, False),
        "backend": check_binary(
            plugins["backend"], api, expected_api, args.manifest_size, True
        ),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    if "setup" in plugins:
        report["setup"] = check_binary(
            plugins["setup"], api, expected_api, args.manifest_size, True
        )
        report["setup_sha256"] = hashlib.sha256(plugins["setup"]).hexdigest()
    report["modules"] = {}
    for name in plugins.keys() - {"setup", "backend"}:
        report["modules"][name] = check_binary(
            plugins[name], api, expected_api, args.manifest_size, True
        )
        report["modules"][name]["sha256"] = hashlib.sha256(plugins[name]).hexdigest()
    for name, module in [("backend", report["backend"]), *report["modules"].items()]:
        if name in {"backend", "cert"} and (
            module["mode"] != "streamed" or module["cached_symbols"] > 32
        ):
            raise ValueError(f"{name} requires streamed relocations and at most 32 symbols")
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        "LOADER ARTIFACT PASS: manifests, Thumb entry, resident targets, relocation bounds, strict imports"
    )


if __name__ == "__main__":
    main()
