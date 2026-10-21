#!/usr/bin/env node
import { mkdir, writeFile, access } from 'node:fs/promises'
import { homedir, platform } from 'node:os'
import { resolve, join } from 'node:path'
import { spawn } from 'node:child_process'
import { collect, VERSION } from './core.mjs'
import { renderHTML } from './html.mjs'

const args = process.argv.slice(2)
if (args.includes('--help')) {
  console.log('SCT AI 工具环境自查\nnode src/cli.mjs [--offline] [--no-open] [--output DIR]\n只读检查，不读取密钥或修改网络配置。报告保存在本机。')
  process.exit(0)
}
if (Number(process.versions.node.split('.')[0]) < 20) { console.error('需要 Node.js 20 或更新版本；请使用启动器。'); process.exit(1) }
const allowed = new Set(['--offline', '--no-open', '--output'])
for (let i = 0; i < args.length; i++) {
  if (!allowed.has(args[i])) { console.error('未知参数，请运行 --help。'); process.exit(1) }
  if (args[i] === '--output') {
    if (!args[i + 1] || args[i + 1].startsWith('--')) { console.error('--output 后需要报告目录。'); process.exit(1) }
    i++
  }
}
const now = new Date().toISOString().replace(/[:.]/g, '-')
let base = join(homedir(), 'Downloads')
try { await access(base) } catch { base = homedir() }
const outputAt = args.indexOf('--output')
const output = outputAt >= 0 ? resolve(args[outputAt + 1]) : join(base, 'SCT-Network-Reports', now)
console.log(`\nSCT AI 工具环境自查 v${VERSION}\n`)
console.log('只读检查；不读取账号凭据或对话，不修改系统设置。')
if (!args.includes('--offline')) console.log('将连接 SCT、Cloudflare、Anthropic 与 OpenAI 的公开端点；各端点会看到连接 IP。\n')
try {
  const report = await collect({ offline: args.includes('--offline'), onCheck: (item) => console.log(`[${item.status}] ${item.title}：${item.summary}`) })
  await mkdir(output, { recursive: true, mode: 0o700 })
  const htmlFile = join(output, 'network-report.html')
  await Promise.all([
    writeFile(join(output, 'network-report.json'), JSON.stringify(report, null, 2), { mode: 0o600 }),
    writeFile(htmlFile, renderHTML(report), { mode: 0o600 }),
  ])
  console.log(`\n报告已保存：${output}\n原始 JSON 含完整公网 IP，分享请用 HTML 页内的“导出脱敏 JSON”。\n网页对照：https://sctcamp.com/tools/network\n`)
  if (!args.includes('--no-open')) {
    const app = platform() === 'darwin' ? 'open' : platform() === 'win32' ? 'explorer.exe' : 'xdg-open'
    const child = spawn(app, [htmlFile], { detached: true, stdio: 'ignore', windowsHide: true })
    child.on('error', () => console.log('未自动打开浏览器，请手动打开报告目录中的 network-report.html。'))
    child.unref()
  }
} catch {
  console.error('检测未完成。请确认报告目录可写，并尝试 node src/cli.mjs --offline --no-open。错误原文未输出，以免意外包含本机路径或配置。')
  process.exitCode = 1
}
