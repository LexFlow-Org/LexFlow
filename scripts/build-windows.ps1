# Build on Windows x64 in a Visual Studio Developer PowerShell.
# No release upload, signing-key access, or application installation.
[CmdletBinding()]
param(
    [ValidateSet('nsis')][string]$Bundle = 'nsis',
    [switch]$SkipInstall
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:OS -ne 'Windows_NT') { throw 'Run this script on Windows x64.' }
# MSI is excluded until equivalent WebView2 AppContainer ACL installation and
# native installer tests exist. The checked postinstall hook is NSIS-specific.
$project = Split-Path -Parent $PSScriptRoot
$target = 'x86_64-pc-windows-msvc'
function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}
foreach ($program in @('node','npm.cmd','cargo','rustup','cl.exe')) {
    if (-not (Get-Command $program -ErrorAction SilentlyContinue)) {
        throw "Missing $program. Install Node.js 22+, Rust 1.88+, Visual Studio Build Tools with Desktop development with C++, and use Developer PowerShell."
    }
}
$cache = Join-Path ([IO.Path]::GetTempPath()) ('lexflow-windows-build-' + [guid]::NewGuid())
$bin = Join-Path $project 'src-tauri/binaries'
$licenses = Join-Path $project 'src-tauri/licenses'
$runtime = Join-Path $bin 'windows-qpdf'
New-Item -ItemType Directory -Force -Path $cache,$bin,$licenses,$runtime | Out-Null
if ((Get-Item -LiteralPath $runtime).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw 'qpdf runtime destination must not be a link.'
}
# Reject stale DLLs instead of silently including files from an earlier build.
$expectedQpdfDlls = @('concrt140.dll','msvcp140.dll','msvcp140_1.dll','msvcp140_2.dll','msvcp140_atomic_wait.dll','msvcp140_codecvt_ids.dll','qpdf30.dll','vcruntime140.dll','vcruntime140_1.dll')
foreach ($dll in Get-ChildItem -LiteralPath $runtime -Filter '*.dll' -File) {
    if ($expectedQpdfDlls -notcontains $dll.Name) {
        throw "Unexpected DLL in generated qpdf runtime directory: $($dll.Name). Review it before building."
    }
}
function Fetch-VerifiedArchive {
    param([string]$Name,[string]$Uri,[string]$Sha256)
    $archive = Join-Path $cache "$Name.zip"
    Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $archive
    if ((Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Sha256) {
        throw "Checksum mismatch for $Name; refusing to execute or bundle it."
    }
    $destination = Join-Path $cache $Name
    Expand-Archive -LiteralPath $archive -DestinationPath $destination
    return $destination
}
Push-Location $project
try {
    $typst = Fetch-VerifiedArchive 'typst' 'https://github.com/typst/typst/releases/download/v0.15.1/typst-x86_64-pc-windows-msvc.zip' '19ce3551153c2fe7ee9fa2f95208310c8f4d3209fedb699e0333faf8913f6736'
    $qpdf = Fetch-VerifiedArchive 'qpdf' 'https://github.com/qpdf/qpdf/releases/download/v12.4.1/qpdf-12.4.1-msvc64.zip' '3cd016cd433ef7232e42f4c13348a49cc14907a3c7278ef4f99120593126f7a6'
    $webviewCab = Join-Path $cache 'webview2.cab'
    Invoke-WebRequest -UseBasicParsing -Uri 'https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/0a4a34d9-ccaa-4cef-98b4-58cb313fbfeb/Microsoft.WebView2.FixedVersionRuntime.152.0.4191.62.x64.cab' -OutFile $webviewCab
    if ((Get-FileHash $webviewCab -Algorithm SHA256).Hash.ToLowerInvariant() -ne '2dc7d817ddce4d036f33684425c218f1ca2d073911136e5d3f8ce9b2340569b5') { throw 'WebView2 checksum mismatch.' }
    $signature = Get-AuthenticodeSignature -LiteralPath $webviewCab
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notlike '*O=Microsoft Corporation*') { throw 'WebView2 Microsoft signature is not valid.' }
    $webviewExtract = Join-Path $cache 'webview2'
    New-Item -ItemType Directory -Path $webviewExtract | Out-Null
    Invoke-Checked 'expand.exe' @('-F:*',$webviewCab,$webviewExtract)
    $webviewSource = Join-Path $webviewExtract 'Microsoft.WebView2.FixedVersionRuntime.152.0.4191.62.x64'
    $webviewTarget = Join-Path $bin 'windows-webview2'
    if (Test-Path $webviewTarget) {
        if ((Get-Item -LiteralPath $webviewTarget).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'WebView2 destination must not be a link.' }
        Remove-Item -LiteralPath $webviewTarget -Recurse -Force
    }
    Move-Item -LiteralPath $webviewSource -Destination $webviewTarget
    $typstDir = Join-Path $typst 'typst-x86_64-pc-windows-msvc'
    $qpdfDir = Join-Path $qpdf 'qpdf-12.4.1-msvc64/bin'
    $vendorDlls = @(Get-ChildItem -LiteralPath $qpdfDir -Filter '*.dll' -File)
    if ($vendorDlls.Count -ne $expectedQpdfDlls.Count -or @($vendorDlls | Where-Object { $expectedQpdfDlls -notcontains $_.Name }).Count -ne 0) {
        throw 'The pinned qpdf archive does not contain the expected runtime DLL set.'
    }
    Copy-Item (Join-Path $typstDir 'typst.exe') (Join-Path $bin "typst-$target.exe") -Force
    Copy-Item (Join-Path $qpdfDir 'qpdf.exe') (Join-Path $bin "qpdf-$target.exe") -Force
    # qpdf.exe requires qpdf30.dll and the supplied MSVC runtime DLLs.
    Copy-Item (Join-Path $qpdfDir '*.dll') $runtime -Force
    Copy-Item (Join-Path $typstDir 'LICENSE') (Join-Path $licenses 'typst-LICENSE.txt') -Force
    Copy-Item (Join-Path $typstDir 'NOTICE') (Join-Path $licenses 'typst-NOTICE.txt') -Force
    # qpdf and libjpeg-turbo license texts are versioned under src-tauri/licenses/qpdf.
    foreach ($name in @('qpdf-LICENSE.txt','qpdf-NOTICE.md','libjpeg-turbo-LICENSE.md','libjpeg-turbo-README.ijg')) {
        if (-not (Test-Path (Join-Path $licenses "qpdf/$name"))) { throw "Missing redistribution notice: $name" }
    }
    # Check the complete vendor runtime in its original directory first.
    Invoke-Checked (Join-Path $typstDir 'typst.exe') @('--version')
    Invoke-Checked (Join-Path $qpdfDir 'qpdf.exe') @('--version')
    Invoke-Checked 'rustup' @('target','add',$target)
    if (-not $SkipInstall) {
        Invoke-Checked 'npm.cmd' @('ci')
        Invoke-Checked 'npm.cmd' @('--prefix','client','ci')
    }
    Invoke-Checked 'npm.cmd' @('--prefix','client','test')
    Invoke-Checked 'npm.cmd' @('--prefix','client','run','lint')
    Invoke-Checked 'cargo' @('test','--locked','--lib','--manifest-path','src-tauri/Cargo.toml','--','--test-threads=1')
    Invoke-Checked (Join-Path $project 'node_modules/.bin/tauri.cmd') @('build','--target',$target,'--bundles',$Bundle,'--ci','--no-sign','--','--locked')
    $output = Join-Path $project "src-tauri/target/$target/release/bundle"
    if ($env:CARGO_TARGET_DIR) { $output = Join-Path $env:CARGO_TARGET_DIR "$target/release/bundle" }
    $artifacts = @(Get-ChildItem -Path $output -Recurse -File | Where-Object { $_.Name -like '*-setup.exe' })
    if ($artifacts.Count -eq 0) { throw 'Build returned without producing an installer.' }
    $artifacts | ForEach-Object { Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 } | Format-Table -AutoSize
    Write-Host 'Installer created with fixed WebView2 and qpdf runtime DLLs. No package was installed or published.'
    Write-Host 'Code signing was not requested. Test on clean Windows with networking disabled before delivery.'
} finally {
    Pop-Location
    Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue
}
