# Repeatable memory regression gate

Double-click **TEST-MEMORY.cmd** in the project root. No conversation or source
analysis is required. It checks the current code and all three registered builds,
prints PASS/FAIL, and writes:

- `build/memory-suite/REPORT.txt`: compact human-readable result and headroom.
- `build/memory-suite/report.json`: machine-readable checks, timings and status.
- Individual command logs and fresh per-target memory/loader/stack reports.

The command exits with 0 only when every requested check passes; otherwise 1.
Missing tools, missing builds and outdated evidence are failures, never skips.
It does not build, publish, install, access device images or modify the SD card.

## Automated coverage

| Layer | What is checked |
| --- | --- |
| Box Flash | Read-only identity/artifact scans use SPI, not the large Core; archive access releases the held BIN first; existing/missing backup and partial-write retry |
| File lifetime | Preflight/details retain a valid handle without reopening it; historical details and abort/Flash handoff |
| Pure operations | Pure Dump/Flash do not load record/archive/slot processing, including retry and resume |
| Header query | Small SPI-only query; no Store/Core, UID, file or persistent job |
| AIO result | Modified output, same-chip UID, retained file handle, hash-pass counts and normal checks after binding loss |
| Version tools | Both stored slots, numeric name suggestion, display-only rename, transient full-chip comparison, Back and import handoff |
| Artifact memory | Existing resident, selection, preload, section, Store and symbol-cache limits on the actual embedded FAP modules |
| Loader | API imports, manifests, entry points, relocations and exact correspondence with the SDK's ten FALs |
| ARM stacks | Existing GUI/worker path budgets, including box-Flash identity, firmware headers, AIO reflash, chip comparison and rename |
| Provenance | FAP, debug ELF and report hashes match; saved source snapshot covers the current manifest/src/config/assets inputs |
| Gate self-test | Deliberately changed/added/deleted source, mismatched hashes, absent evidence, failed commands and over-budget values must fail |

The suite uses native Python and `cc`, or on Windows automatically probes WSL
for Python 3 and `cc`. It performs one cheap toolchain probe and does not retry a
known missing toolchain. ARM checks use the registered firmware SDK's objdump.

## Normal build integration

The existing `BUILD-Unleashed.cmd`, `BUILD-Momentum.cmd` and `BUILD-Official.cmd`
automatically run the host regressions before building. A failed regression stops
the build. After the existing APPCHK/loader/memory/stack gates, successful builds
register their paths and snapshots under `build/targets/<Target>/`.

On a fresh checkout, build each desired target once using its normal launcher.
There is no checked-in machine-specific SDK path. After changing an app build
input, rebuild the affected targets; the suite refuses to accept an older FAP.
Changing only tests or documentation does not require a new firmware build.

For automation or a focused check without the launcher's pause:

```powershell
python tools/test_memory_suite.py
python tools/test_memory_suite.py --target Unleashed
python tools/test_memory_suite.py --host-only
python tools/test_memory_suite.py --artifacts-only
```

Partial runs are explicitly labelled `host-only` or `artifacts-only`; they do not
claim full acceptance. Use `--output <directory>` to retain a separate run.

## Meaning of a pass

This is an automatic regression and artifact gate, **not a measurement of the
device's free heap, allocation fragmentation or every possible runtime path**.
Artifact sizes alone cannot detect an incorrect module loaded by a workflow.
Controller regressions therefore check module routing and file lifetimes too.
New memory incidents should add a small reproducer to this suite rather than
rely on repeated manual code inspection.

The report shows selection headroom even when limits pass. Hardware acceptance
remains separate, especially after changes to module lifetimes or runtime buffers.
No memory limits are raised by this suite.
