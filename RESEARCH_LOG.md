# Research log

Every change that relies on an external threat, technique, or benchmark records a
dated entry here: what we searched, the sources (with links), the conclusion, and the
**as-of** date. Newest first. (Shared research with the npm `llm-trust-guard` repo,
since the two packages track the same threat model.)

---

## 2026-06-09 — v0.10.3 — AST code analysis + JS parser landscape

**As-of date for the search:** 2026-06 (June 2026).

**Questions searched** — is regex the current best practice for code static analysis, or
AST? Best maintained JS/TS AST parser as of 2026 for a zero-dependency library?

**Sources**
- JS AST parsers 2026 (acorn vs babel vs espree): https://www.pkgpulse.com/guides/acorn-vs-babel-parser-vs-espree-javascript-ast-parsers-2026
- Oxc parser (Rust, fastest/most-conformant): https://oxc.rs/docs/learn/architecture/parser
- Oxc vs SWC 2026: https://www.pkgpulse.com/guides/oxc-vs-swc-rust-javascript-toolchain-2026

**Conclusions**
- Regex code analysis is **not** the 2026 state of the art — AST is. Decision: use Python
  **stdlib `ast`** (zero deps) for `CodeExecutionGuard`, catching sandbox-escape gadgets
  regex can't (measured 0/5 → 5/5; see RESULTS-v0.10.3.md).
- JS has **no stdlib parser**: acorn (~20M weekly, ~100KB, ESTree) is the minimal choice,
  oxc (Rust, ~3× SWC, modular `oxc_parser`) the fast one; both actively maintained
  (Shopify/Airbnb adopting Oxlint). Bundling any of them breaks the npm zero-dependency
  guarantee, so the **npm port keeps regex by default and will expose a pluggable
  parser-adapter** (mirroring the existing `DetectionClassifier` seam) — implementation
  deferred, logged as the next code-analysis step.
- We are NOT adding a runtime sandbox: that stays a host concern (gVisor/Firecracker/E2B/
  WASM). The guard remains the decision layer.

## 2026-06-08 — v0.10.2 — benign-context suppression (parity with npm 4.20.2)

**As-of date for the search:** 2026-06 (June 2026).

**Questions searched** — latest prompt-injection / jailbreak techniques 2026; FP
reduction via benign/negation context; whether benign-context suppression is endorsed;
agentic benchmarks (AgentDojo/InjecAgent); WildChat-1M currency & gating.

**Sources**
- AlignSentinel — alignment-aware detection: https://arxiv.org/pdf/2602.13597
- Google — prompt injections on the web (2026): https://blog.google/security/prompt-injections-web/
- Defense techniques 2026: https://tokenmix.ai/blog/prompt-injection-defense-techniques-2026
- ChatInject: https://arxiv.org/pdf/2509.22830
- AgentDojo: https://openreview.net/forum?id=m1YYAQjO3w · InjecAgent: https://arxiv.org/pdf/2403.02691
- WildChat-1M (ungated): https://huggingface.co/datasets/allenai/WildChat-1M

**Conclusions** — benign-vs-misaligned instruction distinction is the endorsed FP fix
(AlignSentinel/Google); paired FN risk addressed with an adversarial bypass probe +
suppression veto. WildChat-1M is the correct, ungated, still-standard FPR corpus; its
age is intentional (comparability with the published 2.73%). No WildChat FPR improvement
is claimed (measured flat). Future work logged: ChatInject role-tags → `ToolResultGuard`.
