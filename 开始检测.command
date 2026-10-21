#!/usr/bin/env bash
cd -- "$(dirname -- "$0")" || exit 1
bash ./start.sh
exit_code=$?
printf '\n按回车关闭此窗口。'
read -r _unused
exit "$exit_code"
