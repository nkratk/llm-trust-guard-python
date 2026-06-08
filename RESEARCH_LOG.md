# Research log

Every change that relies on an external threat, technique, or benchmark records a
dated entry here: what we searched, the sources (with links), the conclusion, and the
**as-of** date. Newest first. (Shared research with the npm `llm-trust-guard` repo,
since the two packages track the same threat model.)

---

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
