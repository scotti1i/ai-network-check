import { cp, mkdir, mkdtemp, readFile, writeFile, chmod, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { resolve, join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { createHash } from 'node:crypto'
import { VERSION } from '../src/core.mjs'

const execute = promisify(execFile)
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const output = resolve(process.argv[2] || join(root, 'dist'))
const versionDir = join(output, `v${VERSION}`)
await mkdir(versionDir, { recursive: true })
const stage = await mkdtemp(join(tmpdir(), 'sct-network-package-'))
try {
  for (const file of ['src', 'start.sh', 'start.ps1', '开始检测.command', '开始检测.cmd', 'README.md', 'LICENSE', 'package.json']) {
    await cp(join(root, file), join(stage, file), { recursive: true })
  }
  await cp(join(stage, '开始检测.cmd'), join(stage, 'run.cmd'))
  await chmod(join(stage, '开始检测.command'), 0o755)
  await chmod(join(stage, 'start.sh'), 0o755)
  const zipPath = join(versionDir, 'ai-network-check.zip'), tarPath = join(versionDir, 'ai-network-check.tar.gz')
  // rm 只删除已生成的同名归档，防止 zip 更新时保留旧条目。
  await Promise.all([rm(zipPath, { force: true }), rm(tarPath, { force: true })])
  await execute('zip', ['-X', '-q', '-r', zipPath, '.'], { cwd: stage })
  await execute('tar', ['-czf', tarPath, '-C', stage, '.'])
  const hash = async (path) => createHash('sha256').update(await readFile(path)).digest('hex')
  const zipHash = await hash(zipPath), tarHash = await hash(tarPath)
  await writeFile(join(versionDir, 'SHA256SUMS'), `${zipHash}  ai-network-check.zip\n${tarHash}  ai-network-check.tar.gz\n`)
  const base = `https://sctcamp.com/network-check/v${VERSION}`
  const bootstrap = `#!/usr/bin/env bash
set -eu
package_dir="$(mktemp -d "\${TMPDIR:-/tmp}/sct-network.XXXXXX")"
printf '\\n下载 SCT AI 工具环境自查 v${VERSION}…\\n'
curl --proto '=https' -fL --connect-timeout 15 --max-time 120 '${base}/ai-network-check.tar.gz' -o "$package_dir/tool.tar.gz"
if command -v shasum >/dev/null 2>&1; then archive_hash="$(shasum -a 256 "$package_dir/tool.tar.gz" | awk '{print $1}')"; else archive_hash="$(sha256sum "$package_dir/tool.tar.gz" | awk '{print $1}')"; fi
if [ "$archive_hash" != '${tarHash}' ]; then printf '工具包校验失败，停止运行。\\n'; exit 1; fi
tar -xzf "$package_dir/tool.tar.gz" -C "$package_dir"
bash "$package_dir/start.sh" "$@"
`
  const windowsBootstrap = `@echo off\r\nchcp 65001 >nul\r\npowershell.exe -NoProfile -Command "$ErrorActionPreference='Stop'; $d=Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString()); New-Item -ItemType Directory -Path $d | Out-Null; $z=Join-Path $d 'tool.zip'; Invoke-WebRequest -UseBasicParsing '${base}/ai-network-check.zip' -OutFile $z; if((Get-FileHash -Algorithm SHA256 $z).Hash.ToLowerInvariant() -ne '${zipHash}'){throw 'Package checksum mismatch'}; Expand-Archive -LiteralPath $z -DestinationPath $d -Force; & cmd.exe /c (Join-Path $d 'run.cmd'); exit $LASTEXITCODE"\r\nif errorlevel 1 pause\r\n`
  await writeFile(join(versionDir, 'start.sh'), bootstrap)
  await writeFile(join(versionDir, 'start.cmd'), windowsBootstrap)
  await writeFile(join(versionDir, 'release.json'), JSON.stringify({ version: VERSION, repository: 'https://github.com/scotti1i/ai-network-check', zipSHA256: zipHash, tarSHA256: tarHash }, null, 2))
  console.log(`已打包 v${VERSION} → ${versionDir}`)
} finally { await rm(stage, { recursive: true, force: true }) }
