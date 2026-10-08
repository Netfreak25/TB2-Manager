param(
    [Parameter(Mandatory=$true)][string]$FirmwareRoot,
    [ValidateSet('Unleashed','Momentum','Official')][string]$Target = 'Unleashed'
)
$ErrorActionPreference = 'Stop'
$appRoot = Split-Path $PSScriptRoot -Parent
$sdkRoot = (Resolve-Path -LiteralPath $FirmwareRoot).Path
$targets = @{
    Unleashed = @{
        Commit = '3c9be0fdd9d301a9436765099a2d1780b36a1795'
        Api = '88.4'
        Description = 'Unleashed unlshd-092'
    }
    Momentum = @{
        Commit = 'e1784e7418d8b074e971983ceb6fef0f37e52ae4'
        Api = '87.1'
        Description = 'Momentum mntm-012'
    }
    Official = @{
        Commit = '8622f1a2b83d8f4918dd5fa3f43de963f6d6f819'
        Api = '87.1'
        Description = 'Official firmware 1.4.3'
    }
}
$targetConfig = $targets[$Target]
$expectedSdk = $targetConfig.Commit
$expectedCrypto = '107ea89daaefb9867ea9121002fbbdf926780e98'
$expectedLfs = 'adad0fbbcf5382c20978d07f94f9c13be9041c1b'
if ((git -C $sdkRoot rev-parse HEAD) -ne $expectedSdk) { throw "Wrong SDK: expected $($targetConfig.Description) pinned commit." }
$cryptoSource = Join-Path $sdkRoot 'lib/mbedtls'
if ((git -C $cryptoSource rev-parse HEAD) -ne $expectedCrypto) { throw 'Wrong Mbed TLS source revision.' }
if (git -C $cryptoSource status --porcelain) { throw 'Mbed TLS checkout has changes; refusing non-reproducible dependency.' }
$api = Get-Content -LiteralPath (Join-Path $sdkRoot 'targets/f7/api_symbols.csv') -TotalCount 2
if ($api[1] -ne "Version,+,$($targetConfig.Api),,") { throw "Expected SDK API $($targetConfig.Api)." }
$lfsSource = Join-Path $appRoot '.deps/littlefs'
if (!(Test-Path -LiteralPath (Join-Path $lfsSource '.git'))) {
    New-Item -ItemType Directory -Force -Path (Split-Path $lfsSource -Parent) | Out-Null
    git clone --depth 1 --branch v2.11.2 https://github.com/littlefs-project/littlefs.git $lfsSource
    if ($LASTEXITCODE -ne 0) { throw 'littlefs download failed.' }
}
if ((git -C $lfsSource rev-parse HEAD) -ne $expectedLfs) { throw 'Wrong littlefs revision.' }
if (git -C $lfsSource status --porcelain) { throw 'littlefs source has local changes.' }
$cryptoOutput = Join-Path $appRoot 'lib/crypto'
$lfsOutput = Join-Path $appRoot 'lib/littlefs'
New-Item -ItemType Directory -Force -Path "$cryptoOutput/library", "$cryptoOutput/include", $lfsOutput | Out-Null
Copy-Item -LiteralPath "$cryptoSource/include/mbedtls", "$cryptoSource/include/psa" -Destination "$cryptoOutput/include" -Recurse -Force
# Sources are explicit: no networking, RSA, TLS, PSA runtime or entropy daemon.
$cryptoFiles = @('aes','asn1parse','asn1write','base64','bignum','bignum_core','bignum_mod','bignum_mod_raw',
    'constant_time','ecp','ecp_curves','ecdsa','error','hkdf','md','oid','pem','pk','pk_wrap','pk_ecc','pkparse',
    'pkwrite','platform','platform_util','sha256','sha512','x509','x509_create','x509_crt','x509write','x509write_crt')
foreach ($name in $cryptoFiles) { Copy-Item -LiteralPath "$cryptoSource/library/$name.c" -Destination "$cryptoOutput/library" -Force }
Get-ChildItem -LiteralPath "$cryptoSource/library" -Filter '*.h' | Copy-Item -Destination "$cryptoOutput/library" -Force
Copy-Item -LiteralPath "$appRoot/config/mbedtls_config.h" -Destination "$cryptoOutput/include/tb2_mbedtls_config.h" -Force
Copy-Item -LiteralPath "$appRoot/config/tb2_config_select.h" -Destination "$cryptoOutput/include/tb2_config_select.h" -Force
Copy-Item -LiteralPath "$cryptoSource/LICENSE" -Destination "$cryptoOutput/LICENSE" -Force
foreach ($name in @('lfs.c','lfs.h','lfs_util.c','lfs_util.h','LICENSE.md')) {
    Copy-Item -LiteralPath "$lfsSource/$name" -Destination $lfsOutput -Force
}
# Upstream v2.11.2 accepts block_count=0 for discovery, but a directory pair
# without any superblock reaches seed % block_count. Fail closed instead.
# Apply only to the generated copy; the pinned dependency checkout stays intact.
$lfsPath = Join-Path $lfsOutput 'lfs.c'
$lfsText = Get-Content -LiteralPath $lfsPath -Raw
$guardAnchor = '    lfs->lookahead.start = lfs->seed % lfs->block_count;'
if (($lfsText.Split(@($guardAnchor), [StringSplitOptions]::None).Count - 1) -ne 1) { throw 'LittleFS mount guard anchor changed; audit required.' }
$guard = "    if (lfs->block_count == 0) {`n        err = LFS_ERR_CORRUPT;`n        goto cleanup;`n    }`n"
[IO.File]::WriteAllText($lfsPath, $lfsText.Replace($guardAnchor, $guard + $guardAnchor), [Text.UTF8Encoding]::new($false))
Write-Output "Prepared: $Target=$expectedSdk MbedTLS=$expectedCrypto littlefs=$expectedLfs API=$($targetConfig.Api)"
