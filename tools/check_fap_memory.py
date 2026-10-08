"""Check ARM FAP phase budgets, including the observed backend-preload shortage.

Pinned Unleashed elf_file.c preloads SHF_ALLOC and .fast.rel.* before freeing
relocations. .ARM.*, .rel.ARM.* and .fast.rel.ARM.* are ignored. Debug-link data
is also allocated. Sizes below are payloads, not a prediction of total heap:
allocator headers, alignment, dictionaries, trampolines, threads, UI, storage,
working data and fragmentation are deliberately NOT called measured here.
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ELF_HEADER = struct.Struct("<16sHHIIIIIHHHHHH")
SECTION_HEADER = struct.Struct("<IIIIIIIIII")
SHF_ALLOC = 2
SHT_NOBITS = 8
ARM_MACHINE = 40
IGNORED_PREFIXES = (".ARM.", ".rel.ARM.", ".fast.rel.ARM.")
DEFAULT_POLICY = Path(__file__).resolve().parents[1] / "config" / "fap_memory.json"
EXTRA_MODULES = {
    "spi", "cert", "aux", "catalog", "fliptdi", "export", "boxes", "store", "imports",
}
GUI_MODULES = {"aux", "catalog", "fliptdi", "boxes", "export", "imports"}


def read_sections(data: bytes) -> list[dict]:
    """Read bounded ELF32 little-endian ARM section headers; reject bad inputs."""
    if len(data) < ELF_HEADER.size:
        raise ValueError("Truncated ELF header")
    header = ELF_HEADER.unpack_from(data)
    if header[0][:7] != b"\x7fELF\x01\x01\x01" or header[2] != ARM_MACHINE:
        raise ValueError("Expected little-endian ARM ELF32")
    table, stride, count, names_index = header[6], header[11], header[12], header[13]
    if stride != SECTION_HEADER.size or not count or not 0 < names_index < count:
        raise ValueError("Unsupported section table")
    if table > len(data) or count * stride > len(data) - table:
        raise ValueError("Truncated section table")
    headers = [
        SECTION_HEADER.unpack_from(data, table + i * stride) for i in range(count)
    ]
    for section in headers:
        offset, length = section[4:6]
        if section[1] != SHT_NOBITS and (
            offset > len(data) or length > len(data) - offset
        ):
            raise ValueError("Section exceeds file")
    names_header = headers[names_index]
    names = data[names_header[4] : names_header[4] + names_header[5]]
    sections = []
    for index, section in enumerate(headers[1:], 1):
        end = names.find(b"\0", section[0])
        if section[0] >= len(names) or end < 0:
            raise ValueError("Invalid section name")
        sections.append(
            {
                "name": names[section[0] : end].decode("ascii"),
                "flags": section[2],
                "size": section[5],
                "alignment": section[8],
                "offset": section[4],
                "index": index,
                "type": section[1],
                "link": section[6],
                "info": section[7],
                "entry_size": section[9],
            }
        )
    return sections


def memory_report(sections: list[dict]) -> dict:
    """Follow the pinned loader's section-selection rules, including temporaries."""
    loaded = []
    for section in sections:
        name = section["name"]
        if name.startswith(IGNORED_PREFIXES):
            continue
        resident = bool(section["flags"] & SHF_ALLOC)
        if resident or name.startswith(".fast.rel.") or name == ".gnu_debuglink":
            loaded.append({**section, "resident": resident})
    if not any(s["name"] == ".text" and s["resident"] and s["size"] for s in loaded):
        raise ValueError("Missing executable .text payload")
    return {
        "resident_payload": sum(s["size"] for s in loaded if s["resident"]),
        "preload_payload": sum(s["size"] for s in loaded),
        "largest_section": max(s["size"] for s in loaded),
        "sections": loaded,
    }


def violations(report: dict, policy: dict) -> list[str]:
    """A larger artifact must not silently inherit an older hardware acceptance."""
    keys = ["resident_payload", "preload_payload", "largest_section"]
    if "browser_payload" in report:
        keys.append("browser_payload")
    errors = [
        f"{key}: {report[key]} > {policy[key + '_max']} bytes"
        for key in keys
        if report[key] > policy[key + "_max"]
    ]
    if (
        "backend" in report
        and report["backend"]["largest_section"] > policy["backend_section_max"]
    ):
        errors.append(
            f"backend_section: {report['backend']['largest_section']} > {policy['backend_section_max']} bytes"
        )
    if "backend" in report:
        backend = report["backend"]
        for field, limit in (
            ("preload_payload", "backend_preload_max"),
            ("cached_symbols", "backend_cached_symbols_max"),
        ):
            if field in backend and backend[field] > policy[limit]:
                errors.append(
                    f"backend_{field}: {backend[field]} > {policy[limit]} bytes/entries"
                )
    for name, module in report.get("modules", {}).items():
        for field, limit in (
            ("largest_section", "backend_section_max"),
            ("preload_payload", "backend_preload_max"),
            ("cached_symbols", "backend_cached_symbols_max"),
        ):
            if module.get(field, 0) > policy[limit]:
                errors.append(f"{name}_{field}: {module[field]} > {policy[limit]}")
    store = report.get("modules", {}).get("store")
    frontend = report.get("frontend")
    if store and store.get("preload_payload", 0) > policy["store_preload_max"]:
        errors.append(
            f"store_preload_payload: {store['preload_payload']} > {policy['store_preload_max']}"
        )
    if store and frontend:
        store_phase = frontend["resident_payload"] + store.get("preload_payload", 0)
        if store_phase > policy["store_phase_payload_max"]:
            errors.append(
                f"store_phase_payload: {store_phase} > {policy['store_phase_payload_max']}"
            )
    return errors


def phased_report(frontend: dict, backend: dict, setup: dict | None = None,
                  modules: dict | None = None) -> dict:
    """The browser must not carry the backend. Worker and UI coexist only for jobs."""
    report = {
        "resident_payload": frontend["resident_payload"] + backend["resident_payload"],
        "preload_payload": max(
            frontend["preload_payload"],
            frontend["resident_payload"] + backend["preload_payload"],
        ),
        "largest_section": max(frontend["largest_section"], backend["largest_section"]),
        "browser_payload": frontend["resident_payload"],
        "frontend": frontend,
        "backend": backend,
    }
    if setup:
        report["setup"] = setup
        report["browser_payload"] += setup["resident_payload"]
        report["resident_payload"] = max(report["resident_payload"], report["browser_payload"])
        report["preload_payload"] = max(report["preload_payload"], frontend["resident_payload"] + setup["preload_payload"])
        report["largest_section"] = max(report["largest_section"], setup["largest_section"])
    if modules:
        report["modules"] = modules
        for name, module in modules.items():
            resident = frontend["resident_payload"] + module["resident_payload"]
            report["resident_payload"] = max(report["resident_payload"], resident)
            report["preload_payload"] = max(report["preload_payload"],
                frontend["resident_payload"] + module["preload_payload"])
            report["largest_section"] = max(report["largest_section"], module["largest_section"])
            if name in GUI_MODULES:
                report["browser_payload"] = max(report["browser_payload"], resident)
    return report


def unpack_plugins(data: bytes) -> dict[str, bytes]:
    """Validate pinned FileBundler framing, paths and cache signature.

    MD5 is the firmware's cache key, not an authenticity guarantee. SHA-256 of
    the extracted FAL is recorded separately.
    """
    cursor = 0

    def take(size: int) -> bytes:
        nonlocal cursor
        if size > len(data) - cursor:
            raise ValueError("Truncated embedded backend assets")
        value = data[cursor : cursor + size]
        cursor += size
        return value

    def blob() -> bytes:
        return take(struct.unpack("<I", take(4))[0])

    magic, version, dirs, files = struct.unpack("<IIII", take(16))
    if (magic, version, dirs) != (0x4F4C5A44, 1, 1) or not 1 <= files <= 2 + len(EXTRA_MODULES):
        raise ValueError("Expected processing modules and one plugins directory")
    signature = blob()
    directory = blob()
    if directory != b"plugins\0":
        raise ValueError("Unexpected embedded asset path")
    digest = hashlib.md5(directory)
    plugins = {}
    for _ in range(files):
        filename, binary = blob(), blob()
        name = filename.replace(b"\\", b"/")
        allowed = {b"plugins/tb2_backend.fal\0": "backend", b"plugins/tb2_setup.fal\0": "setup"}
        allowed.update({f"plugins/tb2_{name}.fal\0".encode(): name for name in EXTRA_MODULES})
        if name not in allowed or allowed[name] in plugins:
            raise ValueError("Unexpected or duplicate embedded asset path")
        plugins[allowed[name]] = binary
        digest.update(filename + binary)
    if (
        cursor != len(data)
        or digest.digest() != signature or "backend" not in plugins
    ):
        raise ValueError("Embedded assets signature or length mismatch")
    return plugins


def unpack_backend_assets(data: bytes) -> bytes:
    """Compatibility accessor for old single-plugin fixtures/tools."""
    return unpack_plugins(data)["backend"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fap", type=Path)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--backend", type=Path)
    parser.add_argument("--setup", type=Path)
    args = parser.parse_args()
    data = args.fap.read_bytes()
    sections = read_sections(data)
    report = memory_report(sections)
    assets = [s for s in sections if s["name"] == ".fapassets"]
    if assets:
        section = assets[0]
        plugins = unpack_plugins(
            data[section["offset"] : section["offset"] + section["size"]]
        )
        backend_data = plugins["backend"]
        if args.backend and backend_data != args.backend.read_bytes():
            raise ValueError("Embedded backend differs from API-checked standalone FAL")
        backend = memory_report(read_sections(backend_data))
        if not any(s["name"].startswith(".fast.rel.") for s in backend["sections"]):
            from stream_backend import normal_relocations

            backend["cached_symbols"] = len(
                {r["symbol_id"] for r in normal_relocations(backend_data)}
            )
        backend["sha256"] = hashlib.sha256(backend_data).hexdigest()
        setup = None
        if "setup" in plugins:
            if args.setup and plugins["setup"] != args.setup.read_bytes():
                raise ValueError("Embedded setup differs from API-checked standalone FAL")
            setup = memory_report(read_sections(plugins["setup"]))
            setup["sha256"] = hashlib.sha256(plugins["setup"]).hexdigest()
        elif args.setup:
            raise ValueError("Required setup missing from FAP")
        modules = {}
        for name in plugins.keys() & EXTRA_MODULES:
            module = memory_report(read_sections(plugins[name]))
            if not any(s["name"].startswith(".fast.rel.") for s in module["sections"]):
                from stream_backend import normal_relocations

                module["cached_symbols"] = len({r["symbol_id"] for r in normal_relocations(plugins[name])})
            module["sha256"] = hashlib.sha256(plugins[name]).hexdigest()
            modules[name] = module
        report = phased_report(report, backend, setup, modules)
    elif args.backend:
        raise ValueError("Required backend missing from FAP")
    else:
        report["browser_payload"] = report["resident_payload"]
    report["sha256"] = hashlib.sha256(data).hexdigest()
    report["violations"] = violations(
        report, json.loads(args.policy.read_text(encoding="utf-8"))
    )
    report["scope"] = (
        "Artifact payload ceiling only; not a hardware or total-heap acceptance"
    )
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    if report["violations"]:
        print("FAP MEMORY FAIL: artifact violates current phase budgets")
        return 1
    print("FAP MEMORY PASS: artifact envelope only; hardware unverified")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError) as error:
        print(f"FAP MEMORY FAIL: {error}", file=sys.stderr)
        sys.exit(1)
