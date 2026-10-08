param(
    [Parameter(Mandatory=$true)][string]$FirmwareRoot,
    [ValidateSet('Unleashed','Momentum','Official')][string]$Target = 'Unleashed'
)
$ErrorActionPreference = 'Stop'
& python "$PSScriptRoot/test_memory_suite.py" --host-only --output "$PSScriptRoot/../build/memory-suite-build"
if ($LASTEXITCODE -ne 0) { throw 'Memory workflow regressions failed; see build/memory-suite-build/REPORT.txt.' }
& "$PSScriptRoot/prepare.ps1" -FirmwareRoot $FirmwareRoot -Target $Target
$appRoot = Split-Path $PSScriptRoot -Parent
$version = [regex]::Match((Get-Content -LiteralPath "$appRoot/src/probe.h" -Raw), 'TB2_PROBE_VERSION\s+"(\d+\.\d+\.\d+)"').Groups[1].Value
if (!$version) { throw 'Missing application version.' }
$sdkRoot = (Resolve-Path -LiteralPath $FirmwareRoot).Path
$targetNames = @{
    Unleashed = 'Unleashed-092'
    Momentum = 'Momentum-012'
    Official = 'Official-1.4.3'
}
$artifactTarget = $targetNames[$Target]
$compact = if ($Target -eq 'Unleashed') { 0 } else { 1 }
$manifestSize = if ($Target -eq 'Momentum') { 86 } else { 85 }
$toolchainPython = Join-Path $sdkRoot 'toolchain/x86_64-windows/python/python.exe'
if (!(Test-Path -LiteralPath $toolchainPython)) {
    $bootstrapPythonUtf8 = $env:PYTHONUTF8
    $env:PYTHONUTF8 = '1'
    Push-Location $sdkRoot
    try {
        & ./fbt.cmd -h | Out-Null
        if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $toolchainPython)) {
            throw "$Target toolchain bootstrap failed."
        }
    } finally {
        Pop-Location
        $env:PYTHONUTF8 = $bootstrapPythonUtf8
    }
}
# API-87 targets need COMPACT=1 for -Os and write to f7-firmware-C.
# Unleashed already applies -Os to external apps with COMPACT=0.
$buildVariant = if ($compact) { 'f7-firmware-C' } else { 'f7-firmware' }
$targetOutput = Join-Path $sdkRoot "build/$buildVariant/.extapps"
$destination = Join-Path $sdkRoot 'applications_user/tb2_probe'
if (Test-Path -LiteralPath $destination) {
    $manifest = Join-Path $destination 'application.fam'
    if (!(Test-Path -LiteralPath $manifest) -or !(Select-String -LiteralPath $manifest -SimpleMatch 'appid="tb2_probe"' -Quiet)) {
        throw 'SDK staging directory is not owned by tb2_probe; refusing overwrite.'
    }
}
New-Item -ItemType Directory -Force -Path $destination | Out-Null
# Remove only obsolete builder files within this app's verified staging roots.
$staleFiles = @(
    (Join-Path $destination 'assets/firmware-0.40.8.bin.gz'),
    (Join-Path $destination 'files/firmware-0.40.8.parts.bin'),
    (Join-Path $destination 'src/firmware0408.c'),
    (Join-Path $destination 'src/firmware0408.h'),
    (Join-Path $destination 'src/firmware0408_backend.c'),
    (Join-Path $targetOutput 'tb2_probe/assets/plugins/tb2_firmware0408.fal'),
    (Join-Path $targetOutput 'tb2_probe/assets/firmware-0.40.8.parts.bin'),
    (Join-Path $targetOutput 'tb2_firmware0408.fal')
)
foreach ($staleFile in $staleFiles) {
    $full = [IO.Path]::GetFullPath($staleFile)
    if (!$full.StartsWith($destination + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -and
        !$full.StartsWith($targetOutput + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Obsolete builder path escaped app staging roots.'
    }
    if (Test-Path -LiteralPath $full -PathType Leaf) { Remove-Item -LiteralPath $full }
}

Copy-Item -LiteralPath "$appRoot/application.fam" -Destination $destination -Force
# SCons does not reliably discover MBEDTLS_CONFIG_FILE reached through -include.
# Bind both app and library command lines to the exact private config so a change
# cannot leave stale objects (including incompatible AES context layouts).
$configHash = (Get-FileHash -Algorithm SHA256 "$appRoot/config/mbedtls_config.h").Hash
$selectHash = (Get-FileHash -Algorithm SHA256 "$appRoot/config/tb2_config_select.h").Hash
$stagedManifest = Join-Path $destination 'application.fam'
$manifestText = Get-Content -LiteralPath $stagedManifest -Raw
$manifestText = $manifestText.Replace('TB2_PRIVATE_CONFIG_ID=0', "TB2_PRIVATE_CONFIG_ID_${configHash}_${selectHash}=1")
if ($Target -ne 'Unleashed') {
    $manifestText = $manifestText -replace '(?m)^\s*fap_exclude_libs=\["gcc"\],\r?\n', ''
    $manifestText = $manifestText.Replace(
        'sources=["lfs.c", "lfs_util.c"],',
        'sources=["lfs.c", "lfs_util.c", "api87_compat.c"],'
    )
}
[IO.File]::WriteAllText($stagedManifest, $manifestText, [Text.UTF8Encoding]::new($false))
foreach ($directory in @('src','lib','assets')) { Copy-Item -LiteralPath "$appRoot/$directory" -Destination $destination -Recurse -Force }
if ($Target -ne 'Unleashed') {
    Copy-Item -LiteralPath "$appRoot/tools/compat/api87_compat.c" -Destination "$destination/lib/littlefs/api87_compat.c" -Force
}
$oldSync = $env:FBT_NO_SYNC
$oldPath = $env:PATH
$env:FBT_NO_SYNC = '1'
$env:PATH = "$sdkRoot/toolchain/x86_64-windows/bin;$env:PATH"
$output = Join-Path $appRoot 'build'
New-Item -ItemType Directory -Force -Path $output | Out-Null
$sourceSnapshot = [ordered]@{}
foreach ($file in @((Get-Item -LiteralPath "$appRoot/application.fam")) + @(Get-ChildItem -LiteralPath "$appRoot/src","$appRoot/config","$appRoot/assets" -Recurse -File)) {
    $relative = $file.FullName.Substring($appRoot.Length + 1).Replace('\','/')
    $sourceSnapshot[$relative] = (Get-FileHash -LiteralPath $file.FullName).Hash.ToLowerInvariant()
}
if ($Target -ne 'Unleashed') {
    $compatFile = Get-Item -LiteralPath "$appRoot/tools/compat/api87_compat.c"
    $compatRelative = $compatFile.FullName.Substring($appRoot.Length + 1).Replace('\','/')
    $sourceSnapshot[$compatRelative] = (Get-FileHash -LiteralPath $compatFile.FullName).Hash.ToLowerInvariant()
}
# The pinned FBT's fap_exclude_libs filter assumes every LIBS entry is hashable;
# private libraries are SCons NodeLists. Apply one mechanical, build-only fix,
# then restore the exact original SDK bytes even when compilation fails.
$sdkToolPath = Join-Path $sdkRoot 'scripts/fbt_tools/fbt_extapps.py'
$sdkToolOriginal = [IO.File]::ReadAllBytes($sdkToolPath)
$sdkToolText = [Text.Encoding]::UTF8.GetString($sdkToolOriginal)
$sdkFilterOld = 'if lib not in excluded]'
$sdkFilterNew = 'if not isinstance(lib, str) or lib not in excluded]'
$sdkToolPatchedHash = $null
$streamTool = "$appRoot/tools/stream_backend.py".Replace('\','/')
$streamInputs = @('stream_backend.py','check_fap_loader.py','check_fap_memory.py')
$streamRevision = (($streamInputs | ForEach-Object { (Get-FileHash -LiteralPath "$appRoot/tools/$_").Hash.ToLowerInvariant() }) -join '-')
$sdkActionOld = '    return Action(actions)'
$sdkActionNew = @'
    if env["APP"].appid in ("tb2_backend", "tb2_cert"):
        actions.append(Action([["${PYTHON3}", r"@STREAM_TOOL@", "${TARGET}", "${OBJCOPY}", "--revision", "@STREAM_REVISION@"]], "STREAMBACKEND ${TARGET}"))
    if env["APP"].appid == "tb2_store":
        actions.append(Action([["${PYTHON3}", r"@STREAM_TOOL@", "${TARGET}", "${OBJCOPY}", "--revision", "@STREAM_REVISION@", "--fastfap", "${FBT_SCRIPT_DIR}/fastfap.py"]], "COMPACTSTORE ${TARGET}"))
    return Action(actions)
'@
$sdkActionNew = $sdkActionNew.Replace('@STREAM_TOOL@', $streamTool).Replace('@STREAM_REVISION@', $streamRevision)
$sdkLinkerPath = Join-Path $sdkRoot 'targets/f7/application_ext.ld'
$sdkLinkerOriginal = [IO.File]::ReadAllBytes($sdkLinkerPath)
$sdkLinkerText = [Text.Encoding]::UTF8.GetString($sdkLinkerOriginal)
$mathSection = Get-Content -LiteralPath "$appRoot/config/math_section.ld" -Raw
$sdkLinkerPatchedHash = $null
$sdkExtappsPath = Join-Path $sdkRoot 'site_scons/extapps.scons'
$sdkExtappsOriginal = [IO.File]::ReadAllBytes($sdkExtappsPath)
$sdkExtappsText = [Text.Encoding]::UTF8.GetString($sdkExtappsOriginal)
$sdkExtappsPatchedHash = $null
Push-Location $sdkRoot
try {
    if (!$sdkLinkerText.Contains('SECTIONS {') -or $sdkLinkerText.Contains('.tb2math')) { throw 'Unexpected SDK linker script; inspect before patching.' }
    [IO.File]::WriteAllBytes($sdkLinkerPath, [Text.Encoding]::UTF8.GetBytes($sdkLinkerText.Replace('SECTIONS {', "SECTIONS {`n$mathSection")))
    $sdkLinkerPatchedHash = (Get-FileHash -LiteralPath $sdkLinkerPath).Hash
    if ($sdkToolText.Contains($sdkFilterOld)) {
        $sdkToolText = $sdkToolText.Replace($sdkFilterOld, $sdkFilterNew)
    } elseif (!$sdkToolText.Contains($sdkFilterNew) -and $Target -eq 'Unleashed') {
        throw 'Unknown FBT library filter; inspect SDK instead of patching.'
    }
    if (($sdkToolText.Split(@($sdkActionOld), [StringSplitOptions]::None)).Count -ne 2) { throw 'Unexpected FBT packaging action; inspect before patching.' }
    [IO.File]::WriteAllBytes($sdkToolPath, [Text.Encoding]::UTF8.GetBytes($sdkToolText.Replace($sdkActionOld, $sdkActionNew)))
    $sdkToolPatchedHash = (Get-FileHash -LiteralPath $sdkToolPath).Hash
    if ($Target -ne 'Unleashed') {
        $gccLibrary = '        "gcc",'
        if (($sdkExtappsText.Split(@($gccLibrary), [StringSplitOptions]::None)).Count -ne 2) {
            throw "Unexpected $Target external-app libraries; inspect before patching."
        }
        # API 87.1 does not export popcount, so the staged compatibility object
        # supplies only that helper. Avoid pulling the rest of libgcc into every
        # module, which would exceed the unchanged phase budgets.
        [IO.File]::WriteAllBytes(
            $sdkExtappsPath,
            [Text.Encoding]::UTF8.GetBytes($sdkExtappsText.Replace("$gccLibrary`r`n", '').Replace("$gccLibrary`n", ''))
        )
        $sdkExtappsPatchedHash = (Get-FileHash -LiteralPath $sdkExtappsPath).Hash
    }
    'Current build lint evidence' | Set-Content -LiteralPath "$output/lint.log"
    & "$sdkRoot/toolchain/x86_64-windows/python/python.exe" scripts/lint.py check "$destination/src" 2>&1 | Tee-Object -FilePath "$output/lint.log" -Append
    if ($LASTEXITCODE -ne 0) { throw "Targeted $Target lint failed." }
    "$Target lint: exit 0 (app source only; unchanged dependencies excluded)." | Tee-Object -FilePath "$output/lint.log" -Append
    & python -m ruff check "$appRoot/tools/check_fap_memory.py" "$appRoot/tools/check_fap_loader.py" "$appRoot/tools/check_status_stack.py" "$streamTool" 2>&1 | Tee-Object -FilePath "$output/lint.log" -Append
    if ($LASTEXITCODE -ne 0) { throw 'Python build-tool lint failed.' }
    if (Test-Path -LiteralPath "$appRoot/tests/test_fap_memory.py") {
        & "$sdkRoot/toolchain/x86_64-windows/python/python.exe" scripts/lint.py check "$appRoot/tests" 2>&1 | Tee-Object -FilePath "$output/lint.log" -Append
        if ($LASTEXITCODE -ne 0) { throw 'UI/core host-test source lint failed.' }
        "$Target lint: exit 0 (host-test source)." | Tee-Object -FilePath "$output/lint.log" -Append
        & python -m ruff check "$appRoot/tests" 2>&1 | Tee-Object -FilePath "$output/lint.log" -Append
        if ($LASTEXITCODE -ne 0) { throw 'Python fixture lint failed.' }
        & "$PSScriptRoot/test-fliptdi-usb.ps1"
        # Python's unittest runner writes progress to stderr even on success. Under
        # PowerShell 7, ErrorActionPreference=Stop can turn that valid output into a
        # NativeCommandError before LASTEXITCODE is inspected.
        $buildErrorPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        & python -m unittest discover -s "$appRoot/tests" -p 'test_fap_*.py' -v 2>&1 | Tee-Object -FilePath "$output/memory-tests.log"
        $memoryTestExit = $LASTEXITCODE
        & python -m unittest discover -s "$appRoot/tests" -p 'test_fliptdi_contract.py' -v 2>&1 | Tee-Object -FilePath "$output/fliptdi-tests.log"
        $flipTdiTestExit = $LASTEXITCODE
        & python -m unittest discover -s "$appRoot/tests" -p 'test_status_stack.py' -v 2>&1 | Tee-Object -FilePath "$output/status-stack-tests.log"
        $stackTestExit = $LASTEXITCODE
        $ErrorActionPreference = $buildErrorPreference
        if ($memoryTestExit -ne 0) { throw 'FAP memory regression failed.' }
        if ($flipTdiTestExit -ne 0) { throw 'FlipTDI contract regression failed.' }
        if ($stackTestExit -ne 0) { throw 'ARM status-stack parser regression failed.' }
        & "$PSScriptRoot/test-loader-cache.ps1" -FirmwareRoot $sdkRoot
    } else {
        'Private host-test harness not present; continuing with SDK, loader, and memory checks.' |
            Tee-Object -FilePath "$output/lint.log" -Append
    }
    # Re-run the lightweight import validator, also for an otherwise up-to-date FAP.
    foreach ($binary in @('tb2_probe','tb2_backend','tb2_setup','tb2_spi','tb2_cert','tb2_aux','tb2_fliptdi','tb2_export','tb2_boxes','tb2_store','tb2_imports')) {
        $validationArtifact = Join-Path $targetOutput "$binary.impsyms"
        if (Test-Path -LiteralPath $validationArtifact) { Remove-Item -LiteralPath $validationArtifact }
    }
    $buildErrorPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & ./fbt.cmd fap_tb2_probe fap_tb2_backend fap_tb2_setup fap_tb2_spi fap_tb2_cert fap_tb2_aux fap_tb2_fliptdi fap_tb2_export fap_tb2_boxes fap_tb2_store fap_tb2_imports DEBUG=0 COMPACT=$compact STRICT_FAP_IMPORT_CHECK=1 2>&1 | Tee-Object -FilePath "$output/fbt.log"
    $fbtExit = $LASTEXITCODE
    $ErrorActionPreference = $buildErrorPreference
    if ($fbtExit -ne 0) { throw 'FAP build failed; inspect build/fbt.log before retrying.' }
    if (!(Select-String -LiteralPath "$output/fbt.log" -Pattern 'APPCHK' -Quiet)) { throw 'APPCHK not present in this build log; acceptance not recorded.' }
    foreach ($name in @('backend','cert','setup','aux','spi','fliptdi','export','boxes','store','imports')) {
        if (!(Select-String -LiteralPath "$output/fbt.log" -Pattern "APPCHK.*tb2_$name.fal" -Quiet)) { throw "Module APPCHK missing: $name" }
    }
    # Regression guard against stale private-library objects after config edits.
    foreach ($binary in @('tb2_probe','tb2_backend','tb2_setup','tb2_spi','tb2_cert','tb2_aux','tb2_fliptdi','tb2_export','tb2_boxes','tb2_store','tb2_imports')) {
        $debugElf = Join-Path $targetOutput "${binary}_d.elf"
        $producers = & "$sdkRoot/toolchain/x86_64-windows/bin/arm-none-eabi-readelf.exe" --debug-dump=info $debugElf | Select-String 'DW_AT_producer.*GNU C'
        if ($LASTEXITCODE -ne 0 -or !$producers) { throw 'Cannot verify ARM compiler optimization.' }
        foreach ($producer in $producers) {
            if ($producer.Line -notmatch ' -Os ' -or $producer.Line -match ' -O[g0123] ') { throw 'Non-size-optimized ARM object; refusing candidate.' }
        }
    }
    "OPTIMIZATION PASS: frontend and all ten modules use -Os; DEBUG=0 COMPACT=$compact for $Target." | Tee-Object -FilePath "$output/optimization.log"
    $frontSymbols = & "$sdkRoot/toolchain/x86_64-windows/bin/arm-none-eabi-nm.exe" -S (Join-Path $targetOutput 'tb2_probe_d.elf')
    if ($LASTEXITCODE -ne 0 -or ($frontSymbols | Where-Object { $_ -match '\s[TRDBtrdb]\s+(mbedtls_|lfs_|tb2_workflow_run|tb2_image_|setup_run|tb2_job_parse_config)' -and $_ -notmatch '\smbedtls_platform_zeroize$' })) { throw 'Processing/setup code linked into frontend; phases are not isolated.' }
    'FRONTEND ISOLATION PASS: only key zeroization remains; no crypto algorithms, LittleFS, image or workflow-run code in the UI ELF.' | Tee-Object -FilePath "$output/optimization.log" -Append
    $setupSymbols = & "$sdkRoot/toolchain/x86_64-windows/bin/arm-none-eabi-nm.exe" -S (Join-Path $targetOutput 'tb2_setup_d.elf')
    if ($LASTEXITCODE -ne 0 -or ($setupSymbols | Where-Object { $_ -match '\s[TRDBtrdb]\s+(mbedtls_|lfs_|tb2_workflow_run|tb2_image_|tb2_package_run)' -and $_ -notmatch '\smbedtls_platform_zeroize$' })) { throw 'Processing code linked into setup.' }
    'SETUP ISOLATION PASS: navigation/catalog/preferences/status and key zeroization only; no crypto algorithms/LittleFS/workflow code.' | Tee-Object -FilePath "$output/optimization.log" -Append
    $symbols = & "$sdkRoot/toolchain/x86_64-windows/bin/arm-none-eabi-nm.exe" -S (Join-Path $targetOutput 'tb2_backend_d.elf')
    foreach ($symbol in @('mbedtls_internal_sha256_process','mbedtls_internal_sha512_process')) {
        $line = $symbols | Where-Object { $_ -match "\s$symbol$" }
        if (!$line -or $line -notmatch '^\S+\s+([0-9a-fA-F]+)\s+\S+\s+') { throw "Missing compact hash symbol: $symbol" }
        if ([Convert]::ToInt32($Matches[1],16) -gt 1024) { throw "Stale or non-compact crypto object: $symbol" }
    }
    'PRIVATE CONFIG PASS: compact SHA256/SHA512 implementations are present in the actual linked ARM ELF.' | Tee-Object -FilePath "$output/private-config.log"
    $artifact = Join-Path $targetOutput 'tb2_probe.fap'
    if (!(Test-Path -LiteralPath $artifact)) { throw 'Expected FAP artifact missing.' }
    $backend = Join-Path $targetOutput 'tb2_backend.fal'
    $streamReport = Join-Path $targetOutput 'tb2_backend.stream.json'
    $streamEvidence = Get-Content -LiteralPath $streamReport -Raw | ConvertFrom-Json
    if ($streamEvidence.after_sha256 -ne (Get-FileHash -LiteralPath $backend).Hash.ToLowerInvariant() -or $streamEvidence.tool_revision -ne $streamRevision) { throw 'Streamed backend equivalence evidence missing/stale.' }
    Copy-Item -LiteralPath $streamReport -Destination "$output/stream.json" -Force
    $certStream = Get-Content -LiteralPath "$targetOutput/tb2_cert.stream.json" -Raw | ConvertFrom-Json
    if ($certStream.after_sha256 -ne (Get-FileHash -LiteralPath "$targetOutput/tb2_cert.fal").Hash.ToLowerInvariant() -or $certStream.tool_revision -ne $streamRevision) { throw 'Certificate streamed equivalence evidence missing/stale.' }
    Copy-Item -LiteralPath "$targetOutput/tb2_cert.stream.json" -Destination "$output/stream-cert.json" -Force
    & python "$appRoot/tools/check_fap_loader.py" $artifact --module-dir $targetOutput --api "$sdkRoot/targets/f7/api_symbols.csv" --manifest-size $manifestSize --report "$output/loader.json" 2>&1 | Tee-Object -FilePath "$output/loader.log"
    if ($LASTEXITCODE -ne 0) { throw 'Loader artifact check failed; no candidate published.' }
    & python "$appRoot/tools/check_fap_memory.py" $artifact --backend $backend --setup "$targetOutput/tb2_setup.fal" --report "$output/memory.json" 2>&1 | Tee-Object -FilePath "$output/memory.log"
    if ($LASTEXITCODE -ne 0) { throw 'FAP memory ceiling exceeded; no candidate published. Inspect build/memory.log.' }
    & python "$appRoot/tools/check_status_stack.py" --firmware-root $sdkRoot --binary-dir $targetOutput --report "$output/status-stack.json" 2>&1 | Tee-Object -FilePath "$output/status-stack.log"
    if ($LASTEXITCODE -ne 0) { throw 'Hardware status save exceeds UI stack budget; no candidate published.' }
    $dist = Join-Path $appRoot 'dist'
    New-Item -ItemType Directory -Force -Path $dist | Out-Null
    $releaseArtifact = "$dist/TB2-Manager-v$version-$artifactTarget.fap"
    Copy-Item -LiteralPath $artifact -Destination $releaseArtifact -Force
    foreach ($relative in $sourceSnapshot.Keys) {
        if ((Get-FileHash -LiteralPath "$appRoot/$relative").Hash.ToLowerInvariant() -ne $sourceSnapshot[$relative]) { throw "Source changed during build: $relative" }
    }
    $sourceSnapshot | ConvertTo-Json | Set-Content -LiteralPath "$output/source-snapshot.json" -Encoding utf8
    & "$sdkRoot/toolchain/x86_64-windows/bin/arm-none-eabi-size.exe" -A $artifact | Tee-Object -FilePath "$output/sections.txt"
    foreach ($name in @('backend','cert','setup','aux','spi','fliptdi','export','boxes','store','imports')) {
        & "$sdkRoot/toolchain/x86_64-windows/bin/arm-none-eabi-size.exe" -A (Join-Path $targetOutput "tb2_$name.fal") | Tee-Object -FilePath "$output/sections.txt" -Append
    }
    & python "$appRoot/tools/test_memory_suite.py" --register $output --target $Target --sdk $sdkRoot --fap $releaseArtifact
    if ($LASTEXITCODE -ne 0) { throw 'Memory-suite build evidence registration failed.' }
    Get-FileHash -Algorithm SHA256 $releaseArtifact
} finally {
    try {
        try {
            try {
                if ($sdkExtappsPatchedHash) {
                    if ((Get-FileHash -LiteralPath $sdkExtappsPath).Hash -ne $sdkExtappsPatchedHash) { throw 'SDK external-app config changed concurrently; refusing overwrite.' }
                    [IO.File]::WriteAllBytes($sdkExtappsPath, $sdkExtappsOriginal)
                }
            } finally {
                if ($sdkLinkerPatchedHash) {
                    if ((Get-FileHash -LiteralPath $sdkLinkerPath).Hash -ne $sdkLinkerPatchedHash) { throw 'SDK linker script changed concurrently; refusing overwrite.' }
                    [IO.File]::WriteAllBytes($sdkLinkerPath, $sdkLinkerOriginal)
                }
            }
        } finally {
            if ($sdkToolPatchedHash) {
                if ((Get-FileHash -LiteralPath $sdkToolPath).Hash -ne $sdkToolPatchedHash) { throw 'SDK tool changed concurrently; refusing to overwrite it.' }
                [IO.File]::WriteAllBytes($sdkToolPath, $sdkToolOriginal)
            }
        }
    } finally {
        Pop-Location
        $env:FBT_NO_SYNC = $oldSync
        $env:PATH = $oldPath
    }
}
