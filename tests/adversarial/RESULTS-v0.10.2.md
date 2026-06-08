# Results — v0.10.2 (benign-context suppression, parity with npm 4.20.2)

- **Date:** 2026-06-08
- **Library version:** 0.10.2 (Python) — parity with npm `llm-trust-guard` 4.20.2
- **Change:** `InputSanitizer.sanitize()` benign-context suppression + suppression veto
- **Harness:** `tests/test_benign_context.py` (curated benign + attack + bypass controls)

## TL;DR

Same change as npm 4.20.2 (see the canonical report with the WildChat measurement:
[`llm-trust-guard/tests/adversarial/RESULTS-v4.20.2.md`](https://github.com/nkratk/llm-trust-guard/blob/main/tests/adversarial/RESULTS-v4.20.2.md)).
Cancel soft `ignore_instructions` / `disregard_above` triggers when the object is a
benign technical noun **and** no instruction/rule/prompt/safety noun is present **and**
no exfiltration/execution/credential/money token is present.

## Results (measured)

| Set | n | Result | Source |
|---|---|---|---|
| Curated benign (coding-context) | 28 | 0 blocked (was 19 pre-change) | `test_benign_context.py` |
| Attack controls (must block) | 12 | 0 leaked | `test_benign_context.py` |
| Adversarial bypass (must block) | 10 | 0 leaked (veto) | `test_benign_context.py` |
| Full unit suite | — | **744 pass** (was 693) | `pytest --ignore=tests/adversarial` |
| Coverage | — | ~74% (floor 70%, enforced) | `pytest --cov` |

## WildChat note

The 10,000-prompt WildChat-1M fixture lives only in the npm repo (to avoid duplicating
10 MB across packages). The npm v4.20.2 measurement — **493/4.93% before and after, i.e.
unchanged on real consumer traffic** — applies to this identical logic. We do **not** claim
a WildChat FPR improvement; the measured win is on coding-context prompts (19→0 curated).

## Reproduce

```bash
# from llm-trust-guard-python/
python3 -m pytest tests/test_benign_context.py -q          # benign + attack + bypass
bash scripts/verify.sh                                     # full eval-gated pipeline
```

## Sources

See `RESEARCH_LOG.md` and the npm RESULTS-v4.20.2.md sources (AlignSentinel 2602.13597, etc.).
