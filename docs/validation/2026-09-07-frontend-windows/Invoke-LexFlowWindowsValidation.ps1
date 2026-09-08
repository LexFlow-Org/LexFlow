#Requires -Version 5.1
<#
Standalone Windows-only validation. Default: prepare a Windows Sandbox .wsb;
never enables OS features, installs a VM, activates Windows or opens the sandbox.
Execution is allowed ONLY with -InsideDisposableVm and -DisposableVmConfirmed,
in a fresh disposable VM/Sandbox containing no LexFlow profile or running app.
Use a checkpoint and discard the guest after testing. Never use an everyday PC.
No credentials/licenses are requested: launch test stops at the activation screen.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$Installer,
  [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedSha256,
  [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+$')][string]$ExpectedVersion = '1.0.1',
  [switch]$InsideDisposableVm,
  [switch]$DisposableVmConfirmed,
  [ValidateSet('Disable','Enable')][string]$SandboxNetworking = 'Disable',
  [ValidateRange(10,120)][int]$SampleSeconds = 30,
  [string]$OutputDirectory
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Requires Windows; no native Windows test was run on macOS.' }
$installerPath = (Resolve-Path -LiteralPath $Installer).Path
$actualHash = (Get-FileHash -LiteralPath $installerPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $ExpectedSha256.ToLowerInvariant()) { throw 'Installer SHA-256 mismatch; installation denied.' }
function Write-Utf8([string]$Path, [string]$Text) {
  [IO.File]::WriteAllText($Path, $Text, [Text.UTF8Encoding]::new($false))
}
function Xml-Escape([string]$Text) { [Security.SecurityElement]::Escape($Text) }

if (-not $InsideDisposableVm) {
  $root = Join-Path ([IO.Path]::GetTempPath()) ('LexFlowSandbox-' + [guid]::NewGuid().ToString('N'))
  $inputDir = Join-Path $root 'Input'
  $outputDir = Join-Path $root 'Output'
  New-Item -ItemType Directory -Path $inputDir,$outputDir | Out-Null
  Copy-Item -LiteralPath $installerPath -Destination (Join-Path $inputDir 'LexFlow-setup.exe')
  Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $inputDir 'Validate.ps1')
  $command = 'powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File C:\LexFlowValidationInput\Validate.ps1 -Installer C:\LexFlowValidationInput\LexFlow-setup.exe -ExpectedSha256 ' + $actualHash + ' -ExpectedVersion ' + $ExpectedVersion + ' -InsideDisposableVm -DisposableVmConfirmed -SampleSeconds ' + $SampleSeconds + ' -OutputDirectory C:\LexFlowValidationOutput'
  # Only these newly created folders are shared. Input is read-only. There is no
  # mapping of the source tree, user profile, cloud folder, vault or license keys.
  $config = @"
<Configuration>
  <MemoryInMB>6144</MemoryInMB>
  <Networking>$SandboxNetworking</Networking>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <AudioInput>Disable</AudioInput><VideoInput>Disable</VideoInput>
  <PrinterRedirection>Disable</PrinterRedirection>
  <MappedFolders>
    <MappedFolder><HostFolder>$(Xml-Escape $inputDir)</HostFolder><SandboxFolder>C:\LexFlowValidationInput</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
    <MappedFolder><HostFolder>$(Xml-Escape $outputDir)</HostFolder><SandboxFolder>C:\LexFlowValidationOutput</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>
  </MappedFolders>
  <LogonCommand><Command>$(Xml-Escape $command)</Command></LogonCommand>
</Configuration>
"@
  $configPath = Join-Path $root 'LexFlow.wsb'
  Write-Utf8 $configPath $config
  $sandboxAvailable = [bool](Get-Command WindowsSandbox.exe -ErrorAction SilentlyContinue)
  $preflight = [ordered]@{ status='prepared_not_executed'; sandboxAvailable=$sandboxAvailable; installerSha256=$actualHash; config=$configPath; output=$outputDir; networking=$SandboxNetworking; instructions='Open the .wsb only when Windows Sandbox is already available and its disposable execution is authorized. On Windows ARM without Sandbox, run the guest mode inside a fresh UTM/QEMU VM after separately authorizing Windows installation and licensing.' }
  Write-Utf8 (Join-Path $root 'preflight.json') ($preflight | ConvertTo-Json -Depth 6)
  $preflight | ConvertTo-Json -Depth 6
  return
}

if (-not $DisposableVmConfirmed) { throw 'Installation requires explicit -DisposableVmConfirmed in an isolated disposable guest.' }
$computer = Get-CimInstance Win32_ComputerSystem
$isSandbox = $env:USERNAME -eq 'WDAGUtilityAccount'
if (-not $isSandbox -and ($computer.Model -notmatch 'Virtual|VMware|QEMU|UTM|Parallels|KVM|HVM')) {
  throw 'No recognized VM/Sandbox model. Refusing to install on a physical/everyday computer.'
}
# Check existence only. Never enumerate/read a real application profile.
foreach ($base in @([Environment]::GetFolderPath('ApplicationData'),[Environment]::GetFolderPath('LocalApplicationData'))) {
  if (Test-Path -LiteralPath (Join-Path $base 'com.pietrolongo.lexflow')) { throw 'Existing LexFlow profile found; guest is not clean. No profile was read or modified.' }
}
if (@(Get-Process -Name LexFlow,lexflow -ErrorAction SilentlyContinue).Count -gt 0) { throw 'LexFlow already running; aborting.' }
$runId = [guid]::NewGuid().ToString('N')
$runRoot = Join-Path $env:SystemDrive ('LexFlowValidation-' + $runId)
$installDir = Join-Path $runRoot 'App'
New-Item -ItemType Directory -Path $runRoot | Out-Null
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $runRoot 'Report' }
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$reportPath = Join-Path $OutputDirectory ('validation-' + $runId + '.json')
$report = [ordered]@{
  status='running'; startedUtc=[DateTime]::UtcNow.ToString('o'); installerSha256=$actualHash
  isolation=@{ disposableVmConfirmed=$true; sandbox=$isSandbox; model=$computer.Model; manufacturer=$computer.Manufacturer }
  environment=@{ os=(Get-CimInstance Win32_OperatingSystem).Caption; build=[Environment]::OSVersion.Version.ToString(); nativeArchitecture=$env:PROCESSOR_ARCHITECTURE; wow64Architecture=$env:PROCESSOR_ARCHITEW6432; processors=$computer.NumberOfLogicalProcessors; ramBytes=$computer.TotalPhysicalMemory }
  coverage='Fresh-profile installer, dependency checks and initial activation window only. No license, vault CRUD, import, biometrics or unlock is exercised.'
  networkMethod='TCP/UDP endpoint polling every about 500ms for app and descendant PIDs. Can miss short-lived traffic; no payload capture; not proof of zero network activity. Run a separate enabled-network guest for outbound behavior.'
  measurements=@(); tcpEndpoints=@(); udpEndpoints=@(); samplingErrors=@(); crashEvents=@()
}
$appProcess = $null
$observedIds = @{}
$tcpSeen = @{}
$udpSeen = @{}
$started = Get-Date
try {
  $timer = [Diagnostics.Stopwatch]::StartNew()
  # NSIS /D must be last; our generated destination has no spaces.
  $setup = Start-Process -FilePath $installerPath -ArgumentList @('/S',('/D=' + $installDir)) -Wait -PassThru
  $timer.Stop()
  $report.install = @{ milliseconds=$timer.Elapsed.TotalMilliseconds; exitCode=$setup.ExitCode }
  if ($setup.ExitCode -ne 0) { throw ('NSIS install failed with exit code ' + $setup.ExitCode) }
  $exe = Join-Path $installDir 'LexFlow.exe'
  if (-not (Test-Path -LiteralPath $exe)) { $exe = Join-Path $installDir 'lexflow.exe' }
  $version = (Get-Item -LiteralPath $exe).VersionInfo.FileVersion
  if ($version -ne $ExpectedVersion -and $version -ne ($ExpectedVersion + '.0')) { throw ('Unexpected executable version: ' + $version) }
  $dlls = @(Get-ChildItem -LiteralPath $installDir -Filter '*.dll' -File)
  if ($dlls.Count -ne 9) { throw ('Expected 9 qpdf/runtime DLLs at install root; found ' + $dlls.Count) }
  $runtimeDir = Join-Path $installDir 'binaries\windows-webview2'
  $runtimeExe = Join-Path $runtimeDir 'msedgewebview2.exe'
  if (-not (Test-Path -LiteralPath $runtimeExe)) { throw 'Fixed WebView2 runtime missing.' }
  $aclEntries = @((Get-Acl -LiteralPath $runtimeDir).Access)
  foreach ($sid in @('S-1-15-2-1','S-1-15-2-2')) {
    $matches = @($aclEntries | Where-Object {
      try { $entrySid = $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { $entrySid = '' }
      $entrySid -eq $sid -and $_.AccessControlType -eq 'Allow' -and
      ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadAndExecute) -eq [Security.AccessControl.FileSystemRights]::ReadAndExecute -and
      ($_.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ContainerInherit) -ne 0 -and
      ($_.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ObjectInherit) -ne 0
    })
    if ($matches.Count -eq 0) { throw ('Missing inheritable runtime RX ACL for ' + $sid) }
  }
  $report.package = @{ version=$version; exeSha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash; dlls=@($dlls | ForEach-Object { @{ name=$_.Name; sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash } }); fixedRuntimeVersion=(Get-Item -LiteralPath $runtimeExe).VersionInfo.FileVersion; runtimeFiles=@(Get-ChildItem -LiteralPath $runtimeDir -Recurse -File).Count; runtimeAcl='both package SIDs have inheritable RX' }
  $typst = Join-Path $installDir 'typst.exe'
  $qpdf = Join-Path $installDir 'qpdf.exe'
  $typstVersion = & $typst --version
  if ($LASTEXITCODE -ne 0) { throw 'Typst --version failed.' }
  $qpdfVersion = & $qpdf --version
  if ($LASTEXITCODE -ne 0) { throw 'qpdf --version failed.' }
  $source = Join-Path $runRoot 'synthetic.typ'
  $pdf = Join-Path $runRoot 'synthetic.pdf'
  Write-Utf8 $source '#set page(paper: "a4")
= LexFlow isolated validation
Synthetic document. No client, license or vault data.
'
  $timer.Restart()
  & $typst compile $source $pdf
  if ($LASTEXITCODE -ne 0) { throw 'Synthetic Typst compile failed.' }
  $compileMs = $timer.Elapsed.TotalMilliseconds
  $qpdfCheck = & $qpdf --check $pdf 2>&1
  if ($LASTEXITCODE -ne 0) { throw 'Synthetic PDF qpdf check failed.' }
  $report.sidecars = @{ typstVersion=($typstVersion -join "`n"); qpdfVersion=($qpdfVersion -join "`n"); syntheticCompileMs=$compileMs; pdfBytes=(Get-Item -LiteralPath $pdf).Length; qpdfCheck=($qpdfCheck -join "`n") }
  $timer.Restart()
  $appProcess = Start-Process -FilePath $exe -PassThru
  $observedIds[$appProcess.Id] = $true
  $firstWindowMs = $null
  do {
    $processes = @(Get-CimInstance Win32_Process)
    do {
      $added = $false
      foreach ($entry in $processes) {
        if ($observedIds.ContainsKey([int]$entry.ParentProcessId) -and -not $observedIds.ContainsKey([int]$entry.ProcessId)) { $observedIds[[int]$entry.ProcessId]=$true; $added=$true }
      }
    } while ($added)
    $sample = [ordered]@{ elapsedMs=$timer.Elapsed.TotalMilliseconds; processes=@() }
    foreach ($processId in @($observedIds.Keys)) {
      $proc = Get-Process -Id $processId -ErrorAction SilentlyContinue
      if ($proc) {
        $sample.processes += @{ id=$processId; name=$proc.ProcessName; cpuSeconds=$proc.TotalProcessorTime.TotalSeconds; workingSetBytes=$proc.WorkingSet64; privateBytes=$proc.PrivateMemorySize64 }
      }
    }
    $report.measurements += $sample
    try {
      foreach ($endpoint in @(Get-NetTCPConnection -ErrorAction Stop)) {
        if ($observedIds.ContainsKey([int]$endpoint.OwningProcess)) {
          $key = "$($endpoint.OwningProcess)/$($endpoint.LocalAddress):$($endpoint.LocalPort)/$($endpoint.RemoteAddress):$($endpoint.RemotePort)/$($endpoint.State)"
          $tcpSeen[$key] = @{ processId=$endpoint.OwningProcess; localAddress=$endpoint.LocalAddress; localPort=$endpoint.LocalPort; remoteAddress=$endpoint.RemoteAddress; remotePort=$endpoint.RemotePort; state=[string]$endpoint.State }
        }
      }
      foreach ($endpoint in @(Get-NetUDPEndpoint -ErrorAction Stop)) {
        if ($observedIds.ContainsKey([int]$endpoint.OwningProcess)) { $udpSeen["$($endpoint.OwningProcess)/$($endpoint.LocalAddress):$($endpoint.LocalPort)"] = @{ processId=$endpoint.OwningProcess; localAddress=$endpoint.LocalAddress; localPort=$endpoint.LocalPort } }
      }
    } catch { if ($report.samplingErrors.Count -eq 0) { $report.samplingErrors += $_.Exception.Message } }
    $appProcess.Refresh()
    if ($appProcess.HasExited) { throw ('Application exited during launch sample: ' + $appProcess.ExitCode) }
    if ($null -eq $firstWindowMs -and $appProcess.MainWindowHandle -ne 0) { $firstWindowMs=$timer.Elapsed.TotalMilliseconds }
    Start-Sleep -Milliseconds 500
  } while ($timer.Elapsed.TotalSeconds -lt $SampleSeconds)
  $report.launch = @{ firstNativeWindowMs=$firstWindowMs; sampleDurationMs=$timer.Elapsed.TotalMilliseconds; note='A native window handle does not certify visible WebView content. Inspect the activation screen manually inside the disposable guest.' }
  if ($null -eq $firstWindowMs) { throw 'No native application window observed.' }
  $crashes = @(Get-WinEvent -FilterHashtable @{ LogName='Application'; Id=1000,1001; StartTime=$started } -ErrorAction SilentlyContinue | Where-Object { $_.Message -match '(?i)lexflow|msedgewebview2' })
  $report.crashEvents = @($crashes | ForEach-Object { @{ time=$_.TimeCreated.ToUniversalTime().ToString('o'); id=$_.Id; provider=$_.ProviderName } })
  if ($crashes.Count -gt 0) { throw 'Application/WebView crash events observed.' }
  $report.status = if ($report.samplingErrors.Count -gt 0) { 'partial_network_sampling_unavailable' } else { 'checks_passed_manual_visual_review_required' }
} catch {
  $report.status = 'failed'
  $report.error = $_.Exception.Message
} finally {
  if ($appProcess -and -not $appProcess.HasExited) {
    [void]$appProcess.CloseMainWindow()
    if (-not $appProcess.WaitForExit(5000)) { $appProcess.Kill() }
  }
  $report.tcpEndpoints = @($tcpSeen.Values)
  $report.udpEndpoints = @($udpSeen.Values)
  $report.finishedUtc = [DateTime]::UtcNow.ToString('o')
  Write-Utf8 $reportPath ($report | ConvertTo-Json -Depth 12)
  Write-Output $reportPath
}
if ($report.status -eq 'failed') { exit 1 }
