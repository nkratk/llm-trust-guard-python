> **Docs-only patch.** Guard code unchanged from v0.21.0. Corpus numbers identical.

# Adversarial Benchmark Results — v0.21.1

Run date: 2026-07-06  
Python mirror of npm v4.32.0 (2026 literature gap-fill).  
Full corpus methodology and per-guard breakdown: [npm repo RESULTS-v4.31.0.md](https://github.com/nkratk/llm-trust-guard/blob/main/tests/adversarial/RESULTS-v4.31.0.md).  
Suite: 949 tests, all pass (931 excluding adversarial datasets).

---

## Changes in v0.21.1

Pattern-only release mirroring npm v4.32.0. Four guards updated with 2026 literature-gap patterns (arXiv:2601.07395 MCP-ITP, arXiv:2604.16543, arXiv:2605.28201, arXiv:2601.10923). No catalog groups added.

| Guard | Change | Recall (from npm corpus) |
|---|---|---|
| `agent_skill_guard.py` | +4 Semantic Compliance Hijacking patterns | **100%** (6 groups) |
| `agent_communication_guard.py` | +7 string-payload patterns + `isinstance` branch | **100%** (69 groups) |
| `memory_guard.py` | +4 Plant-Persist-Trigger patterns | **96.2%** (69 groups) |
| `rag_guard.py` | +2 HTML/image carrier patterns | **92.2%** (46 groups) |

---

## WildChat FPR gate (npm regression gate applies)

| Version | Blocked / 10,000 | FPR |
|---|---|---|
| Baseline (locked) | 494 | 4.94% |
| v0.21.1 | **494** | **4.94%** |

---

## npm↔Python parity gate

File: `tests/guard-parity-vectors.json`  
Vectors: 46 (Python-handled guards) | Previously: 32  
Python gate (`test_guard_parity.py`): **46/46 PASS**  
New handlers added: `AgentSkillGuard`, `AgentCommunicationGuard`

---

## Verification commands

```bash
# Full suite
python3 -m pytest tests/ -q --ignore=tests/adversarial/datasets

# Parity gate only
python3 -m pytest tests/test_guard_parity.py -v
```
