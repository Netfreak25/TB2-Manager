"""Audit compiled ARM frames on the UI-thread hardware status-save path.

This is a conservative path budget, not a device stack high-water measurement.
The named call chain crosses the SPI plugin and resident IO/log callbacks. Keep
1 KiB for firmware printf/storage/logging, the thread entry and exception frames.
The call path is manually selected for the pinned -Os build, not an exhaustive
call-graph analysis. A changed prologue or an outlined helper requires review.
"""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

SDK_RESERVE = 1024
PATH = {
    "tb2_probe": [
        "tb2_probe_app",
        "run_ui",
        "finish_worker",  # includes finish_hardware
        "operation_access",
        "file_open",
        "io_result",
        "log_event",
    ],
    "tb2_spi": ["operation", "tb2_operation_save", "tb2_operation_load", "tb2_operation_info"],
}
IO_PATH = ["file_open", "io_result", "log_event"]
AUDIT_PATHS = {
    "chip_compare": ("worker", {
        "tb2_probe": ["record_task_worker", "run_spi", *IO_PATH],
        # compare_contents is inlined; the streamed reader has no large stack buffer.
        "tb2_spi": ["run", "tb2_spi_operation_run", "tb2_spi_run", "read_chip"],
    }),
    "aio_reflash": ("worker", {
        "tb2_probe": ["hardware_worker", "spi_phase", "run_spi", *IO_PATH],
        # flash is inlined into tb2_spi_run in the pinned builds.
        "tb2_spi": ["run", "tb2_spi_operation_run", "tb2_spi_run", "verify",
                    "mbedtls_sha256_update", "mbedtls_internal_sha256_process"],
    }),
    "version_rename": ("worker", {
        "tb2_probe": ["record_task_worker", "store_access", *IO_PATH],
        "tb2_store": ["run", "tb2_store_run", "tb2_record_task_run", "version_save",
                      "tb2_record_write", "tb2_record_read", "read_slot"],
    }),
    "box_flash_identity": ("worker", {
        # archive_before_flash is inlined into hardware_worker in the pinned builds.
        "tb2_probe": ["hardware_worker", "record_publish", "inspect_identity_file", "run_spi", *IO_PATH],
        "tb2_spi": ["run", "tb2_identity_file", "tb2_reader_identity", "firmware_at",
                    "mbedtls_sha256_update", "mbedtls_internal_sha256_process"],
    }),
    "firmware_headers": ("worker", {
        "tb2_probe": ["record_task_worker", "run_spi"],
        "tb2_spi": ["tb2_spi_headers_run"],  # header_report is inlined into this frame.
    }),
    "history_save": ("gui", {
        "tb2_probe": ["tb2_probe_app", "run_ui", "finish_worker", "record_event", "store_access", *IO_PATH],
        "tb2_store": ["run", "tb2_store_run", "tb2_entry_save", "tb2_record_write", "tb2_record_read", "read_slot"],
    }),
    "restore_binding": ("gui", {
        "tb2_probe": ["tb2_probe_app", "run_ui", "record_restore_plan", "store_access", *IO_PATH],
        "tb2_store": ["run", "tb2_store_run", "restore_plan", "tb2_record_write", "tb2_record_read", "read_slot"],
    }),
    "job_list": ("gui", {
        "tb2_probe": ["tb2_probe_app", "run_ui", "invoke_setup", *IO_PATH],
#manager_tick is a stackless tail - jump wrapper in this pinned build.
        "tb2_setup": ["setup_run", "manager_tick.part.0", "tb2_operation_load", "tb2_operation_info", "read_exact"],
    }),
    "box_list": ("gui", {
        "tb2_probe": ["tb2_probe_app", "run_ui", "invoke_setup", *IO_PATH],
        "tb2_boxes": ["run", "tick", "tb2_entry_load", "tb2_record_read", "read_slot"],
    }),
    "record_export": ("worker", {
        "tb2_probe": ["record_task_worker", "store_access", *IO_PATH],
        "tb2_store": ["run", "tb2_store_run", "tb2_record_task_run", "tb2_record_archive", "archive_entries", "metadata", "member", "write_header", "write_bytes"],
    }),
    "record_import": ("worker", {
        "tb2_probe": ["record_task_worker", "store_access", *IO_PATH],
        "tb2_store": ["run", "tb2_store_run", "tb2_record_task_run", "tb2_record_import", "import_entries", "object.part.0", "tb2_object_put", "transfer"],
    }),
}


def frame_size(disassembly: str, name: str) -> int:
    # With normal -Os inlining the sole run_ui caller owns its entire frame.
    # Every audited run_ui path also includes tb2_probe_app; never count twice.
    if name == "run_ui" and not re.search(r"^[0-9a-f]+ <run_ui>:", disassembly, re.MULTILINE):
        frame_size(disassembly, "tb2_probe_app")  # Require the owning compiled frame.
        return 0
    match = re.search(rf"^[0-9a-f]+ <{re.escape(name)}>:\n(.*?)(?=\n[0-9a-f]+ <|\Z)",
                      disassembly, re.MULTILINE | re.DOTALL)
    if not match:
        raise ValueError(f"Missing ARM function: {name}")
    size = 0
    pushed = False
    for line in match[1].splitlines():
        if re.search(r"\s(?:blx?|b(?:\.[nw])?)\s", line):
            break
        registers = re.search(r"\s(?:push|stmdb)\s+(?:sp!,\s*)?\{([^}]+)\}", line)
        if registers:
            size += 4 * len(registers[1].split(","))
            pushed = True
        allocation = re.search(r"\ssub(?:w|\.w)?\s+sp,\s*(?:sp,\s*)?#(\d+)", line)
        if allocation:
            size += int(allocation[1])
        elif re.search(r"\s(?:sub\S*\s+sp|vpush\s|mov\S*\s+sp,)", line):
            raise ValueError(f"Unrecognized ARM stack adjustment: {name}: {line.strip()}")
    if not pushed or not size:
        raise ValueError(f"Unrecognized ARM prologue: {name}")
    return size


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firmware-root", type=Path, required=True)
    parser.add_argument("--binary-dir", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    manifest = (root / "application.fam").read_text(encoding="utf-8")
    limit = int(re.search(r"stack_size=(\d+)", manifest)[1])
    binary_dir = args.binary_dir or args.firmware_root / "build/f7-firmware/.extapps"
    objdump = args.firmware_root / "toolchain/x86_64-windows/bin/arm-none-eabi-objdump.exe"
    frames = {}
    hashes = {}
    assemblies = {}
    modules = set(PATH)
    for _, calls in AUDIT_PATHS.values():
        modules.update(calls)
    for module in sorted(modules):
        hashes[module] = hashlib.sha256((binary_dir / f"{module}_d.elf").read_bytes()).hexdigest()
        disassembly = subprocess.check_output([objdump, "-d", binary_dir / f"{module}_d.elf"], text=True)
        assemblies[module] = disassembly
        if module == "tb2_probe":
            for helper in ("finish_hardware",):
                if re.search(rf"^[0-9a-f]+ <{helper}(?:\.[^>]*)?>:", disassembly, re.MULTILINE):
                    raise ValueError(f"Previously inlined helper {helper} requires path review")
        for name in PATH.get(module, []):
            frames[f"{module}:{name}"] = frame_size(disassembly, name)
    total = sum(frames.values()) + SDK_RESERVE
    worker_limit = int(re.search(r"#define WORKER_STACK\s+(\d+)", (root / "src/app.c").read_text())[1])
    audits = {}
    for label, (thread, calls) in AUDIT_PATHS.items():
        measured = {}
        for module, names in calls.items():
            for name in names:
#- Os may add a.constprop /.part suffix.Ambiguous symbols fail
#instead of silently measuring the wrong static function.
                found = re.findall(rf"^[0-9a-f]+ <({re.escape(name)}(?:\.[^>]*)?)>:",
                                   assemblies[module], re.MULTILINE)
                if not found and module == "tb2_probe" and name == "run_ui" and "tb2_probe_app" in names:
                    measured["tb2_probe:run_ui (in tb2_probe_app)"] = frame_size(assemblies[module], name)
                    continue
                if len(found) != 1:
                    raise ValueError(f"Expected one ARM function: {module}:{name}; got {found}")
                measured[f"{module}:{found[0]}"] = frame_size(assemblies[module], found[0])
        budget = limit if thread == "gui" else worker_limit
        used = sum(measured.values()) + SDK_RESERVE
        audits[label] = {"thread": thread, "frames": measured, "budgeted_bytes": used,
                         "stack_bytes": budget, "passed": used <= budget}
        print(f"STACK PATH {label}: {used} / {budget}")
    report = {"frames": frames, "elf_sha256": hashes,
              "fap_sha256": hashlib.sha256((binary_dir / "tb2_probe.fap").read_bytes()).hexdigest(),
              "sdk_reserve": SDK_RESERVE, "budgeted_bytes": total,
              "stack_bytes": limit, "paths": audits,
              "passed": total <= limit and all(audit["passed"] for audit in audits.values()),
              "limitation": "Static ARM call-path budget; hardware acceptance still required."}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"STATUS STACK {'PASS' if report['passed'] else 'FAIL'}: "
          f"{sum(frames.values())} application bytes + {SDK_RESERVE} SDK reserve "
          f"= {total} / {limit}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
