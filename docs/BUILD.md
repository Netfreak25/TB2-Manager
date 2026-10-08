# Building TB2 Manager 0.8.10

TB2 Manager uses separate pinned builds for Unleashed, Momentum, and the
official Flipper firmware. A FAP must be installed only on the firmware target
named in its filename.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7
- Git
- Python 3.11 or newer
- An Unleashed SDK checkout at commit
  `3c9be0fdd9d301a9436765099a2d1780b36a1795`
- A Momentum mntm-012 checkout at commit
  `e1784e7418d8b074e971983ceb6fef0f37e52ae4`
- An Official firmware 1.4.3 checkout at commit
  `8622f1a2b83d8f4918dd5fa3f43de963f6d6f819`
- Initialized SDK submodules
- A C compiler (`cc`), or WSL with Python 3 and `cc`, for the public host tests

The build verifies the SDK commit, API version, and pinned Mbed TLS revision. It
also fetches littlefs v2.11.2 at its pinned commit into the ignored `.deps/`
directory and prepares ignored dependency sources under `lib/`.

## Prepare the checkout

Replace `<repository-url>` with the clone URL of the repository you are using.

```powershell
git clone "<repository-url>" TB2-Manager
Set-Location TB2-Manager
python -m pip install -r requirements-build.txt
```

Obtain the required firmware checkout separately and use the exact commit listed
above. Do not build against a different API revision.

## Build

```powershell
.\tools\build.ps1 -FirmwareRoot 'C:\path\to\unleashed-unlshd-092'
.\tools\build.ps1 -FirmwareRoot 'C:\path\to\momentum-mntm-012' -Target Momentum
.\tools\build.ps1 -FirmwareRoot 'C:\path\to\official-1.4.3' -Target Official
```

For an interactive Windows build, double-click the matching launcher in the
repository root:

| Installed firmware | Build launcher |
|---|---|
| Unleashed unlshd-092 | `BUILD-Unleashed.cmd` |
| Momentum mntm-012 | `BUILD-Momentum.cmd` |
| Official firmware 1.4.3 | `BUILD-Official.cmd` |

Each launcher asks for the matching firmware checkout and then invokes the same
validated build pipeline.

The script stages the application inside the SDK, prepares the pinned
dependencies, builds the frontend and ten embedded modules with release settings,
checks the loader and memory contracts, and restores its mechanical SDK build
patches before returning.

The output is:

```text
dist/TB2-Manager-v0.8.10-Unleashed-092.fap
dist/TB2-Manager-v0.8.10-Momentum-012.fap
dist/TB2-Manager-v0.8.10-Official-1.4.3.fap
```

Copy the FAP to `/ext/apps/Tools/` on the Flipper SD card.

## Reproducibility and generated files

The following directories are generated locally and must not be committed:

```text
.deps/
lib/
build/
dist/
```

`application.fam`, `src/`, `config/`, `assets/`, `host/`, `tools/`, and
`third_party/` are source inputs. The Core Flasher browser page is intentionally a
tracked source file even though it is self-contained.

The tracked source includes synthetic host regressions. Build evidence remains in
ignored `build/` and `dist/` directories. Release binaries are attached separately;
they are not committed to the source tree. No device images or private test data
are required by the public regression suite.

Run `python tools/test_memory_suite.py` after building all three targets. The
builds also run their focused host tests, SDK lint, APPCHK, loader, memory and ARM
stack checks. See [the suite guide](MEMORY-TEST-SUITE.md). Additional clock checks
are `tools/test_core_clock.py` and `tools/test_direct_clock.py`; run them with
Python in an environment providing a C compiler.

The packed FAP contains exactly ten modules and no bundled device firmware.
Core/certificate streaming and Store relocation normalization are checked against
the pinned SDK packing format. These checks validate the produced artifacts;
they do not measure runtime heap fragmentation or device stack high-water usage.

## Target limits

The 0.8.10 build retains these limits:

| Limit | Maximum |
|---|---:|
| Processing phase | 106,000 bytes |
| Browser phase | 32,768 bytes |
| Backend preload | 92,160 bytes |
| Store preload | 65,536 bytes |
| Executable section | 49,152 bytes |
| Cached backend symbols | 32 |

Changing the SDK, optimization profile, module layout, cryptography
configuration, or linker behavior requires a new validation run.
