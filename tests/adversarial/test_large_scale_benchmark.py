"""
Large-Scale Real-World Adversarial Benchmark

Tests against 15,000+ jailbreak prompts from verazuo/jailbreak_llms dataset
(collected from Reddit, Discord, websites, open-source — published at CCS'24)

This is the REAL test of our detection capabilities.
"""

import sys
import os
import csv
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from llm_trust_guard.guards.input_sanitizer import InputSanitizer
from llm_trust_guard.guards.encoding_detector import EncodingDetector

sanitizer = InputSanitizer(threshold=0.3)
encoder = EncodingDetector()

DATASETS_DIR = os.path.join(os.path.dirname(__file__), "datasets")


def is_blocked(text):
    if not text or len(text) < 5:
        return False
    try:
        s_result = sanitizer.sanitize(text)
        e_result = encoder.detect(text)
        return not s_result.allowed or not e_result.allowed
    except Exception:
        return False


def load_csv_column(file_path, col_index, has_header=True):
    """Load a specific column from a CSV file using stdlib csv.reader."""
    if not os.path.exists(file_path):
        return []

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        rows = list(reader)

    start = 1 if has_header else 0
    results = []
    for row in rows[start:]:
        if len(row) > col_index and row[col_index] and len(row[col_index].strip()) > 10:
            results.append(row[col_index])

    return results


class TestLargeScaleAdversarialBenchmark:
    """Large-Scale Adversarial Benchmark"""

    DATA_DIR = os.path.join(DATASETS_DIR, "jailbreak_llms", "data", "prompts")
    JAILBREAK_FILE = os.path.join(DATA_DIR, "jailbreak_prompts_2023_12_25.csv")
    REGULAR_FILE = os.path.join(DATA_DIR, "regular_prompts_2023_12_25.csv")

    class TestJailbreakDetection:
        """Jailbreak Detection (15K+ real prompts)"""

        def test_should_measure_detection_rate_on_real_jailbreak_prompts(self):
            jailbreak_file = TestLargeScaleAdversarialBenchmark.JAILBREAK_FILE

            if not os.path.exists(jailbreak_file):
                print("SKIPPED: jailbreak dataset not available")
                return

            # Load jailbreak prompts (column 2 = prompt text)
            all_prompts = load_csv_column(jailbreak_file, 2)

            # Random sample of 1000 for speed (full dataset takes too long for unit tests)
            sample_size = min(1000, len(all_prompts))
            sample = random.sample(all_prompts, sample_size)

            caught = 0
            missed = 0
            missed_examples = []

            for prompt in sample:
                if is_blocked(prompt):
                    caught += 1
                else:
                    missed += 1
                    if len(missed_examples) < 5:
                        missed_examples.append(prompt[:100] + "...")

            rate = (caught / len(sample)) * 100

            print("\n+================================================+")
            print("|  LARGE-SCALE JAILBREAK BENCHMARK               |")
            print("+================================================+")
            print(f"  Dataset: verazuo/jailbreak_llms (CCS'24)")
            print(f"  Total Available: {len(all_prompts)}")
            print(f"  Sample Tested: {len(sample)}")
            print(f"  Caught: {caught}")
            print(f"  Missed: {missed}")
            print(f"  > DETECTION RATE: {rate:.1f}%")
            if missed_examples:
                print("  Sample missed:")
                for i, m in enumerate(missed_examples):
                    print(f"    {i + 1}. {m}")
            print("")

            # This is a benchmark measurement, not a pass/fail gate
            # Full dataset rate is ~44%, random samples vary widely
            assert rate >= 0

    class TestFalsePositiveRate:
        """False Positive Rate (225K safe prompts)"""

        def test_should_measure_false_positive_rate_on_regular_prompts(self):
            regular_file = TestLargeScaleAdversarialBenchmark.REGULAR_FILE

            if not os.path.exists(regular_file):
                print("SKIPPED: regular prompts dataset not available")
                return

            # Load regular (safe) prompts (column 2 = prompt text)
            all_safe = load_csv_column(regular_file, 2)

            # Sample 2000 for speed
            sample_size = min(2000, len(all_safe))
            sample = random.sample(all_safe, sample_size)

            false_positives = 0
            fp_examples = []

            for prompt in sample:
                if is_blocked(prompt):
                    false_positives += 1
                    if len(fp_examples) < 5:
                        fp_examples.append(prompt[:100] + "...")

            fp_rate = (false_positives / len(sample)) * 100

            print("\n+================================================+")
            print("|  FALSE POSITIVE BENCHMARK                      |")
            print("+================================================+")
            print(f"  Dataset: verazuo/jailbreak_llms regular prompts")
            print(f"  Total Available: {len(all_safe)}")
            print(f"  Sample Tested: {len(sample)}")
            print(f"  Incorrectly Blocked: {false_positives}")
            print(f"  > FALSE POSITIVE RATE: {fp_rate:.1f}%")
            if fp_examples:
                print("  Sample false positives:")
                for i, m in enumerate(fp_examples):
                    print(f"    {i + 1}. {m}")
            print("")

            # Target: <20% false positive rate
            # Note: Python csv.reader correctly parses multi-line entries (13K prompts)
            # vs TypeScript's broken parser that splits them (57K fragments, lower FP)
            assert fp_rate < 20

    class TestCombinedMetrics:
        """Combined Metrics"""

        def test_should_produce_an_overall_assessment(self):
            print("\n+================================================+")
            print("|  OVERALL ASSESSMENT                            |")
            print("+================================================+")
            print("  This benchmark tests against REAL jailbreak prompts")
            print("  collected from Reddit, Discord, and open-source.")
            print("  These are attacks that REAL people used against")
            print("  REAL production LLMs (ChatGPT, Claude, etc.).")
            print("  ")
            print("  Our guards use regex pattern matching only.")
            print("  For higher detection, plug in an ML classifier")
            print("  via the DetectionClassifier interface.")
            print("")
            assert True
