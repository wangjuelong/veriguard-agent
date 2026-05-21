#!/usr/bin/env bash
#
# Veriguard Agent — local CI gate (本地优先 / 主 gate)
#
# 在 PR / push 前本机跑此脚本验证三大检查：
#
#   1. cargo fmt --check                                       (fastest, fail fast)
#   2. cargo clippy --all-targets --all-features -- -D warnings
#   3. cargo test --all-features
#
# Mirrors the gates enforced by `.github/workflows/ci.yml` (clippy gate after
# agent #12) —— GitHub CI 是备用 net；本地是默认主 gate。
#
# Baseline 状态（与 agent #11 + #10 一致）：
#   * clippy : 0 warning
#   * test   : 324 passed (319 unit + 5 integration)
#   * fmt    : clean (无 drift)
#
# 使用：
#
#   ./scripts/ci.sh
#
# 或加 git hook 之前：
#
#   ln -s ../../scripts/ci.sh .git/hooks/pre-push
#
# Exit code 0 → 可推；非 0 → 修了再推。

set -euo pipefail

# 切到 crate 根（脚本位置 ../）
cd "$(dirname "$0")/.."

run_step() {
  local name="$1"
  shift
  echo ""
  echo "==> $name"
  echo "    $*"
  if "$@"; then
    echo "    [PASS] $name"
  else
    local rc=$?
    echo "    [FAIL] $name (exit $rc)" >&2
    exit "$rc"
  fi
}

run_step "fmt-check"  cargo fmt --check
run_step "clippy"     cargo clippy --all-targets --all-features -- -D warnings
run_step "test"       cargo test --all-features

echo ""
echo "OK — 三项 gate 全过，可推 / 可开 PR"
