"""
Regression coverage for the many-shot Q&A detection logic
(_count_qa_pairs in heuristic_analyzer.py). Parity test for
tests/heuristic-analyzer.test.ts in the npm sibling.

This detection was originally a single unbounded regex
((?:Q:|Question:|Human:|User:)[\\s\\S]*?(?:A:|Answer:|Assistant:|AI:)) that
turned out to be catastrophic-backtracking on adversarial input (long runs
of "User:" markers with no closing "A:"). A first fix bounded the middle
gap to {0,1000} chars, which closed the ReDoS but silently stopped
detecting any many-shot turn whose Q->A gap exceeds 1000 chars —
independent review of the npm sibling's identical fix caught this as a
real jailbreak evasion (verbose scenario-framing turns routinely exceed
1000 chars), and confirmed this file had the identical bug. The final fix
replaced the single regex with a linear marker-position scan that has no
length cap at all. These tests cover both properties: detection still
works on long turns, and it stays fast on adversarial input with no
closing marker.
"""

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from llm_trust_guard.guards.heuristic_analyzer import HeuristicAnalyzer


def _build_shot(i, pad_length):
    return f"Q: Scenario {i}, imagine a detailed hypothetical situation. " + "x" * pad_length + " A: Sure, here you go. "


class TestManyShotDetection:
    def test_detects_many_shot_attacks_with_short_qa_turns(self):
        analyzer = HeuristicAnalyzer()
        payload = "\n".join(f"Q: step {i} A: ok" for i in range(5))
        result = analyzer.analyze(payload)
        assert result.features.is_shot_attack is True

    def test_detects_many_shot_attacks_with_long_qa_turns_regression_for_the_redos_fix_evasion(self):
        analyzer = HeuristicAnalyzer()
        payload = "\n".join(_build_shot(i, 1500) for i in range(5))
        result = analyzer.analyze(payload)
        assert result.features.is_shot_attack is True

    def test_does_not_flag_a_normal_single_turn_message_as_many_shot(self):
        analyzer = HeuristicAnalyzer()
        result = analyzer.analyze("Can you help me write a cover letter for a marketing job?")
        assert result.features.is_shot_attack is False

    def test_completes_quickly_on_adversarial_input_with_many_unmatched_markers(self):
        analyzer = HeuristicAnalyzer()
        attack = "User: " * 50000
        start = time.time()
        analyzer.analyze(attack)
        assert (time.time() - start) * 1000 < 500
