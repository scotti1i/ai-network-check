$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$NodeBin = $null
$NodeCommand = Get-Command node -ErrorAction SilentlyContinue
if ($NodeCommand -and $env:SCT_NETWORK_FORCE_RUNTIME -ne '1') {
  $NodeMajor = & $NodeCommand.Source -p 'process.versions.node.split(String.fromCharCode(46))[0]'
  if ([int]$NodeMajor -ge 20) { $NodeBin = $NodeCommand.Source }
}
if (-not $NodeBin) {
  Write-Host '未找到 Node.js 20+，下载官方便携运行时（不修改 PATH、不需要管理员权限）。'
  $RuntimeVersion = 'v22.23.3'
  $RuntimeArch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { 'arm64' } else { 'x64' }
  $RuntimeName = "node-$RuntimeVersion-win-$RuntimeArch"
  $CacheDir = Join-Path $env:LOCALAPPDATA 'SCT-Network-Check'
  $NodeBin = Join-Path $CacheDir "$RuntimeName\node.exe"
  if (-not (Test-Path $NodeBin)) {
    New-Item -ItemType Directory -Force -Path $CacheDir | Out-Null
    $TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $TempDir | Out-Null
    try {
      $RuntimeFile = Join-Path $TempDir 'node.exe'
      $RuntimeRemote = "win-$RuntimeArch/node.exe"
      Invoke-WebRequest -UseBasicParsing -TimeoutSec 180 -Uri "https://nodejs.org/dist/$RuntimeVersion/$RuntimeRemote" -OutFile $RuntimeFile
      $Sums = (Invoke-WebRequest -UseBasicParsing -TimeoutSec 30 -Uri "https://nodejs.org/dist/$RuntimeVersion/SHASUMS256.txt").Content
      $Expected = (($Sums -split "`n" | Where-Object { $_.Trim().EndsWith(" $RuntimeRemote") }) -split '\s+')[0]
      $Actual = (Get-FileHash -Algorithm SHA256 $RuntimeFile).Hash
      if (-not $Expected -or $Actual.ToLowerInvariant() -ne $Expected.ToLowerInvariant()) { throw '运行时校验失败，停止执行。' }
      New-Item -ItemType Directory -Force -Path (Split-Path $NodeBin) | Out-Null
      Move-Item -LiteralPath $RuntimeFile -Destination $NodeBin -Force
    } finally { Remove-Item -LiteralPath $TempDir -Recurse -Force }
  }
}
& $NodeBin (Join-Path $PSScriptRoot 'src\cli.mjs') @args
exit $LASTEXITCODE
