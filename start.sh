#!/usr/bin/env bash
set -eu
root_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
node_bin=""
if [ "${SCT_NETWORK_FORCE_RUNTIME:-0}" != 1 ] && command -v node >/dev/null 2>&1 && node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 20 ? 0 : 1)' >/dev/null 2>&1; then
  node_bin="$(command -v node)"
else
  printf '\n未找到 Node.js 20+，下载官方便携运行时（只放在用户目录，不改 PATH）。\n'
  case "$(uname -s)" in Darwin) runtime_os=darwin;; Linux) runtime_os=linux;; *) printf '不支持的操作系统。\n'; exit 1;; esac
  case "$(uname -m)" in arm64|aarch64) runtime_arch=arm64;; x86_64|amd64) runtime_arch=x64;; *) printf '不支持的 CPU 架构。\n'; exit 1;; esac
  runtime_version=v22.23.3
  runtime_name="node-${runtime_version}-${runtime_os}-${runtime_arch}"
  runtime_cache="${XDG_CACHE_HOME:-${HOME}/.cache}/sct-network-check"
  mkdir -p "$runtime_cache"
  node_bin="$runtime_cache/$runtime_name/bin/node"
  if [ ! -x "$node_bin" ]; then
    temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/sct-node.XXXXXX")"
    trap 'rm -rf "$temp_dir"' EXIT
    curl --proto '=https' -fL --connect-timeout 15 --max-time 300 "https://nodejs.org/dist/${runtime_version}/${runtime_name}.tar.gz" -o "$temp_dir/runtime.tar.gz"
    curl --proto '=https' -fsSL --max-time 30 "https://nodejs.org/dist/${runtime_version}/SHASUMS256.txt" -o "$temp_dir/SHASUMS256.txt"
    expected_hash="$(awk -v file="$runtime_name.tar.gz" '$2 == file {print $1}' "$temp_dir/SHASUMS256.txt")"
    if command -v shasum >/dev/null 2>&1; then actual_hash="$(shasum -a 256 "$temp_dir/runtime.tar.gz" | awk '{print $1}')"; else actual_hash="$(sha256sum "$temp_dir/runtime.tar.gz" | awk '{print $1}')"; fi
    if [ -z "$expected_hash" ] || [ "$actual_hash" != "$expected_hash" ]; then printf '运行时校验失败，停止执行。\n'; exit 1; fi
    tar -xzf "$temp_dir/runtime.tar.gz" -C "$runtime_cache"
  fi
fi
"$node_bin" "$root_dir/src/cli.mjs" "$@"
