# veriguard-agent

**Veriguard 平台自有验证 Agent**——府谷电力 IPv6 安全验证系统招标 §9.2 自建模块。

## Upstream attribution

Forked from [OpenAEV-Platform/agent](https://github.com/OpenAEV-Platform/agent) at commit `531f9d120a92f1af3ce78b0c37a356738584af18` (release 2.3.5).

**Fork 后一次性脱钩**：两仓代码完全独立演化，不跟上游 patch / 不做 cherry-pick / 不强求协议兼容。上游归属仅作 LICENSE Apache 2.0 attribution 用途。

## Project context

本仓与 `wangjuelong/veriguard-implant` 协作，在 [`wangjuelong/Veriguard`](https://github.com/wangjuelong/Veriguard) 主仓（Java 后端）的指令下，完成 §3 边界 / §4 流量 / §5 主机三场景的真实模拟攻击。

详细设计：
- Spec: `docs/superpowers/specs/2026-05-14-veriguard-agent-implant-fork-c1-c2-design.md`
- Plan: `docs/superpowers/plans/2026-05-14-veriguard-agent-implant-fork-c1-c2-plan.md`

## Build

```bash
cargo build --release         # native build
cargo zigbuild --target x86_64-unknown-linux-gnu --release   # cross-compile
```

CI: `.github/workflows/release.yml` (matrix 6 binary: Linux/Win/macOS × x86_64/arm64)

## License

Apache 2.0 (inherited from upstream OpenAEV-Platform/agent).
