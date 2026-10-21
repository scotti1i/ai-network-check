@echo off
chcp 65001 >nul
set "SCT_NETWORK_ROOT=%~dp0"
where node >nul 2>nul
if errorlevel 1 goto portable
node -e "process.exit(Number(process.versions.node.split('.')[0]) >= 20 ? 0 : 1)" >nul 2>nul
if errorlevel 1 goto portable
node "%~dp0src\cli.mjs" %*
goto done
:portable
powershell.exe -NoProfile -Command "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; $v='v22.23.3'; $a=if($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64'){'arm64'}else{'x64'}; $name='node-'+$v+'-win-'+$a; $cache=Join-Path $env:LOCALAPPDATA 'SCT-Network-Check'; $n=Join-Path $cache ($name+'\node.exe'); if(-not(Test-Path $n)){ Write-Host 'Preparing verified official Node.js runtime...'; $t=Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString()); New-Item -ItemType Directory -Path $t | Out-Null; try { $f=Join-Path $t 'node.exe'; $r='win-'+$a+'/node.exe'; Invoke-WebRequest -UseBasicParsing -TimeoutSec 180 ('https://nodejs.org/dist/'+$v+'/'+$r) -OutFile $f; $s=(Invoke-WebRequest -UseBasicParsing -TimeoutSec 30 ('https://nodejs.org/dist/'+$v+'/SHASUMS256.txt')).Content; $e=(($s -split [char]10 | Where-Object {$_.Trim().EndsWith(' '+$r)}) -split '\s+')[0]; if(-not $e -or (Get-FileHash -Algorithm SHA256 $f).Hash.ToLowerInvariant() -ne $e.ToLowerInvariant()){throw 'Runtime checksum mismatch'}; New-Item -ItemType Directory -Force -Path (Split-Path $n) | Out-Null; Move-Item -LiteralPath $f -Destination $n -Force } finally { Remove-Item -LiteralPath $t -Recurse -Force } }; & $n (Join-Path $env:SCT_NETWORK_ROOT 'src\cli.mjs'); exit $LASTEXITCODE"
:done
if errorlevel 1 (
  echo Check did not complete. See the message above.
  pause
)
