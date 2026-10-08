# TB2 Manager

TB2 Manager is an offline workshop application for reading, modifying, organizing,
and restoring supported Toniebox 2 SPI flash images with a Flipper Zero.

Version 0.8.10 has separate builds for **Unleashed unlshd-092 (API 88.4)**,
**Momentum mntm-012 (API 87.1)**, and **Official firmware 1.4.3 (API 87.1)**.
It supports the **Winbond W25Q128FV** 16 MiB flash chip. The current release is
**0.8.10 Beta 3**. Release FAPs are **unverified build candidates** until
complete device acceptance on their respective firmware targets.

## Supported hardware

| Component | Supported configuration |
|---|---|
| Flipper | Flipper Zero |
| Firmware | Unleashed unlshd-092, API 88.4; Momentum mntm-012, API 87.1; Official 1.4.3, API 87.1 |
| Flash chip | Winbond W25Q128FV, JEDEC `EF 40 18` |
| Capacity | 16,777,216 bytes |
| SPI | External 3.3 V GPIO; selectable 2, 4, 8 or 16 MHz; 2 MHz default |

Other flash chips and firmware API versions are not supported by these builds.
The JEDEC identifier selects the supported chip profile; the individual chip UID
is used to associate hardware with a box record.

## Features

- Full-chip dump with an explicit second-pass verification.
- Full-chip erase and write with erased-page skipping, followed by byte-for-byte verification.
- AIO workflow for Dump, Modify, archive export, and Flash.
- Persistent box records with aliases, chip UID association, versions, notes,
  secrets, package bindings, and workshop history.
- Readable per-box image names with separate original and modified revisions.
- Analysis of both MCUboot slots without claiming which slot is active.
- Guided and individual editors for hosts, ports, Wi-Fi profiles, and supported
  device settings.
- Certificate package import, export, controlled replacement, and restore.
- Retryable chip detection, read, verify, erase, write, and archive phases.
- Raw **Core Flasher** WebUSB SPI bridge and direct hardware-SPI test.
- Job history with saved results, resume, retry, logs, and clear state labels.

All processing is local. TB2 Manager does not contact, upload to, or configure a
remote server.

Direct Dump and Flash operations keep the configured SPI bus active for their
hardware phase while preserving a separate CS transaction for every command.
`Manage > Settings > Hardware` cycles through 2, 4, 8 and 16 MHz. Choose `Save`
to retain the selection across app restarts; Back discards the draft. This setting
also applies to direct identification, firmware-header queries, verification,
and the hardware phases of box workflows/AIO. Existing 2/4 MHz settings retain
their meaning. Core Flasher has its own independent default.

## Navigation

| Entry | Purpose |
|---|---|
| `Boxes` | Identify, create, open, import, and work with box records. |
| `Images` | Open the standalone BIN image browser. |
| `Actions` | Open Dump, Flash, Modify, AIO, and Core Flasher. |
| `Manage` | Open Jobs and Settings. |
| `Help` | Open instructions, wiring, and version information. |
| `Exit` | Close the application. |

Up and Down select an entry, OK opens or confirms it, and Back returns to the
parent menu. Back from the main menu exits the app.

## Dump, Flash, and AIO

### Dump

`Actions -> Dump` reads directly to the chosen BIN file without assigning a box,
inspecting firmware slots, or creating an archive. It detects the chip, reads all
16 MiB, syncs and closes the file, and displays `Dump saved`. Select `Verify dump`
to perform the full second read and comparison. A verified standalone dump is
complete; it does not create a second permanent image copy.

Dump started from a box record and AIO retain their box context. Their analysis,
box-record publication, and AIO continuation require `Dump verified`.
A partial or interrupted read is never presented as a verified dump.

### Flash

`Actions -> Flash` and `Images -> Flash` accept a fully readable file of exactly
16 MiB. They require neither a box record nor a secret and perform no automatic
backup, archive, certificate, or firmware-slot analysis. After file, chip, and
write-protection checks and explicit approval, the operation runs:

```text
Erase -> Write -> Verify
```

Only a complete byte-for-byte chip comparison produces `Flash verified`.
Write protection is reported but is not changed automatically.
Jobs, logs, direct chip binding, and targeted retry remain available. Standalone
intent persists across restart. Flash from a box version and AIO keep their
existing record and backup workflow; older jobs are not reclassified.

### AIO

AIO performs a verified dump, modification setup, image verification, TAR export,
and verified flash within one job. The original dump remains available. Valid
results are passed between phases so the app does not repeat a full check unless
the bound file, chip, or proof changed.

After successful AIO, `Flash dump` writes the **modified result** again to the
same chip UID. It is offered only with a reliable UID binding. A continuously
held, verified file handle avoids another archive, slot or full-file hash pass;
chip readiness, protection checks and complete post-write verification remain.
After losing that handle, the normal checks apply again.

`Import` opens the existing importer for that result and its box, with Modified
preselected. Version selection and preview remain; a duplicate opens the existing
version. The held file is closed before importing.

The application does not bundle device firmware. Supply your own image.
The app shows `Starting...` while preparing storage and loading its menu.

## Box records

Open `Boxes` to identify a connected box, open existing records, create
a record, or import a complete record archive. A box record provides:

```text
Overview
Dump chip
Modify
Versions
Restore
Secret
Notes
Import
Export
Edit alias
```

`Identify box` reads the chip UID live. A known UID can open its record directly.
An unknown UID is shown and can be used to create a new record. If no UID is
available, a record can be selected manually.

`Boxes -> Identify Firmware` reads only the two 32-byte MCUboot headers from the
connected chip. It shows Slot A and Slot B independently; `Details` includes each
build number. These are header values, not an active-slot determination or a
firmware verification. No box record, key or image file is required. `Retry`
repeats the query, and Back returns to Boxes. The direct-hardware SPI setting
also applies to this read-only query.

Each new box uses a readable folder below:

```text
/ext/apps_data/tb2_manager/images/<Box alias>/
```

Images follow this naming scheme:

```text
<Box>_<Version>.bin
<Box>_<Version>_r2.bin
<Box>_<Version>_mod.bin
<Box>_<Version>_mod_r2.bin
<Box>_<Version>_mod.tar
```

Original and modified images have separate revision sequences. A new dump is read
into a temporary file in its final box folder and published under its reserved
name after verification. It does not create a second permanent image copy.

The version picker offers the labels detected in MCUboot Slot A and Slot B plus a
manual entry. Both slot identities and fingerprints are retained. The app does not
infer the active slot.

### Versions and restore

Versions are grouped as original and modified. Any retained full image can be
flashed from its version menu. Original and manually confirmed working versions
are protected by default.

Version `Details` shows both saved slot versions, including build numbers. Older
records show their legacy firmware as Slot A and `Unknown` for Slot B. Opening
details does not scan the image or identify the active slot.

`Rename` edits only the version's display name. The proposed name uses the box
alias, the numerically highest known slot version, the stored Original/Modified
classification and revision. Unknown metadata keeps the previous name as the
editable suggestion. Actual BIN/TAR filenames, paths, hashes and job bindings
remain unchanged; Back discards the edit.

`Compare -> Image` retains the saved-version comparison. `Compare -> Connected
chip` reads the entire supported chip directly against the selected 16-MiB BIN
and reports `Identical` or `Different`. It creates no dump and updates no saved
verification or working flags. A read error is reported as an error, not a
difference. Back cancels, Retry starts a fresh comparison; no matching box UID
is required for this read-only operation.

Restore supports:

- `Original image`: flash a selected full original image.
- `Previous version`: flash another retained full version.
- `Certificates`: read the current chip and restore the three supported encrypted
  certificate files while preserving unrelated data.

Full-image restore does not require a secret. Certificate restore requires a
validated secret or AES key for the selected image and profile.

## Import and export

The box import menu provides:

- `Secrets`: import a text file containing an 8-byte box secret or 16-byte AES
  key. A new value remains a candidate until an image validates it.
- `Server certificates`: inspect an existing package directory or uncompressed
  TAR and bind it to a modified version or keep it unassigned.
- `Images`: import a 16 MiB BIN after hash, identity, type, version, revision,
  and destination-name review.

Imported source images remain unchanged. Identical content opens the existing
version instead of creating a duplicate. Original versions never inherit a server
package. Modified versions may inherit the most recent earlier package according
to numeric firmware version and revision.

A `.tb2box.tar` record export can include plaintext local secrets and private key
material. Handle it as sensitive workshop data. Diagnostic exports are redacted
and exclude images, secrets, certificate files, and raw settings.

## Modify and settings

Modify offers:

```text
Guided modify
Hosts & ports
Wi-Fi profiles
Device settings
Certificates
```

The guided workflow uses the same editors as the individual modes. A skipped
category is not parsed or changed.

TB2 Manager edits the logical `/settings` file inside LittleFS. It does not use a
fixed flash offset. Records are validated, the last duplicate key wins, changes
are written once in canonical form, and the file is remounted and read back after
replacement. Unrelated image data is checked for preservation. A no-op does not
create another version.

Supported settings include:

- Independent OTA and ICI hostnames and ports.
- Wi-Fi profiles 0-9 with SSID, security, password, priority, add, and delete.
- EU or US Wi-Fi region.
- Lifecycle states 01-08.
- Offline mode.
- ICI log levels Off, Error, Warning, Info, and Debug.

Profile 0 cannot be deleted. Selecting Open security removes its PSK. Existing
priority and last-used values are preserved during ordinary credential edits.
SSID and PSK values are not written to logs, record metadata, preferences, or
diagnostic exports.

Pure settings and port changes do not require a key. Certificate inspection,
restore, or certificate renewal after an actual hostname change may require one.
A port-only change does not alter certificates.

Result labels describe the proof that was actually completed:

| Label | Meaning |
|---|---|
| `Dump verified` | The saved dump matched a complete second chip read. |
| `Settings image verified` | The requested settings patch and preservation checks passed. |
| `Image verified` | The complete image checks, including required cryptographic checks, passed. |
| `Flash verified` | The complete written chip matched the approved source image. |
| `Saved state` | Historical stored evidence; not a current hardware verification. |

## Core Flasher

Core Flasher is an FT232H-compatible WebUSB bridge derived from FlipTDI. It uses
the same external hardware-SPI pins as Dump and Flash. Firmware
forwards CS, transmit and receive operations without interpreting flash opcodes.
Chip checks, write policy and destructive-command authorization belong to the
browser client.

The browser frontend owns backup verification, user confirmation, target-image
selection and final comparison. Failed writes stop as partial and unverified;
restoring a backup remains an explicit user action. The Flipper stores no second
backup and reports transport success only.

Open `Actions > Core Flasher` and choose:

- `Start USB bridge`
- `Test hardware SPI`
- `Settings`
- `Wiring`
- `About`

`Settings > Default SPI` cycles through 2, 4, 8 and 16 MHz. `Save` persists and reads back
`core-flasher.conf` in the app data directory; Back discards the draft. Missing or
invalid settings default to 2 MHz. This default applies to the bridge and its
hardware test only, independently of `Manage > Settings > Hardware`.

The browser can override this default with a complete MPSSE `0x86` 16-bit divisor.
`0x8A` selects the 60 MHz FTDI base and `0x8B` selects 12 MHz; the request is
`base / (2 * (divisor + 1))`. Base changes alone keep the app default until the
first complete divisor. The Flipper selects the highest available hardware clock
that does not exceed the request, without a 4 MHz cap. With a 64 MHz SPI kernel,
3.75 MHz maps to 2 MHz, 5 MHz to 4 MHz, and 30 MHz to 16 MHz. This is not exact
FT232H clock synthesis. Requests below the hardware minimum stop the bridge.

The USB screen displays the app default, browser request and applied clock.
Zero means no browser override or no transfer yet, respectively. A change during
CS-low takes effect at the next transaction; it does not toggle CS. USB/SIO reset
and bitmode restart restore the default, while RX/TX purge preserves the clock.
A fatal unsupported-clock error requires restarting the bridge. Status adds no
bytes to the MPSSE stream.

After starting the bridge, **Connect to WebUSB**.

## Wiring

The app includes the upstream 128x64 wiring diagram under `Help -> Wiring` and in
the Core Flasher menu.

| Flipper pin | Signal |
|---:|---|
| 2 | MOSI / DI |
| 3 | MISO / DO |
| 4 | CS |
| 5 | SCK / CLK |
| 8 | GND |
| 9 | 3.3 V |

Use 3.3 V only. Do not connect the flash chip to the Flipper's 5 V output.

## Installation

1. Download the FAP matching the installed firmware:
   `TB2-Manager-v0.8.10-beta.3-Unleashed-092.fap` or
   `TB2-Manager-v0.8.10-beta.3-Momentum-012.fap` or
   `TB2-Manager-v0.8.10-beta.3-Official-1.4.3.fap`.
2. Copy it to `/ext/apps/Tools/` on the Flipper SD card.
3. Start `TB2 Manager` from the Tools category.

The app creates `/ext/apps_data/tb2_manager` on first use. Existing data from
older application directories is not migrated or searched automatically.

## Build from source

Run **TEST-MEMORY.cmd** for automatic memory regression, loader, stack and
artifact checks across the registered builds. Results are saved in
`build/memory-suite/REPORT.txt`. The build scripts run the regressions automatically.
See the [memory test suite guide](docs/MEMORY-TEST-SUITE.md).

See [docs/BUILD.md](docs/BUILD.md) for the pinned SDK requirements and the complete
PowerShell build procedure. Replace `<repository-url>` with the clone URL of
the repository you are using:

```powershell
git clone "<repository-url>" TB2-Manager
Set-Location TB2-Manager
python -m pip install -r requirements-build.txt
.\tools\build.ps1 -FirmwareRoot 'C:\path\to\unleashed-unlshd-092'
.\tools\build.ps1 -FirmwareRoot 'C:\path\to\momentum-mntm-012' -Target Momentum
.\tools\build.ps1 -FirmwareRoot 'C:\path\to\official-1.4.3' -Target Official
```

On Windows, the repository root also contains one directly visible launcher per
distribution: `BUILD-Unleashed.cmd`, `BUILD-Momentum.cmd`, and
`BUILD-Official.cmd`. Double-click the matching launcher and enter the path to
its pinned firmware checkout.

The expected result is:

```text
dist/TB2-Manager-v0.8.10-Unleashed-092.fap
dist/TB2-Manager-v0.8.10-Momentum-012.fap
dist/TB2-Manager-v0.8.10-Official-1.4.3.fap
```

The public repository contains application and build source only. It does not
contain private keys, device images, workshop records, generated artifacts, or
device-derived test data.

## Release status

Release builds must pass the public host regressions, SDK lint, APPCHK, loader
validation, and unchanged memory and stack budgets for all three targets.
See the [build guide](docs/BUILD.md) and [memory test suite](docs/MEMORY-TEST-SUITE.md).
These checks do not replace hardware acceptance or measure runtime heap fragmentation.

Device acceptance covers Dump/Flash, box workflows, AIO result actions, imports,
settings edits, version comparison, and Core Flasher clock changes and readback.
Until completed, release artifacts remain **unverified build candidates**.

For repository and publication procedures, see [maintenance](docs/MAINTENANCE.md).

## License and attribution

TB2 Manager is licensed under the [GNU General Public License v3.0](LICENSE).
Adapted SPI Mem Manager and FlipTDI components remain covered by GPL-3.0. Mbed TLS
and littlefs use their respective upstream licenses. Exact revisions and source
provenance are documented in [NOTICE](NOTICE) and `third_party/`.
