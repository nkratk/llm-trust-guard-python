"""
DriftDetector (L14)

Detects behavioral drift from intended agent purpose.
Monitors for rogue agent behavior and goal misalignment.

Threat Model:
- ASI10: Rogue Agents
- Goal misalignment
- Behavioral drift over time

Protection Capabilities:
- Baseline behavior profiling
- Anomaly detection
- Goal alignment verification
- Continuous monitoring
- Alert thresholds
"""

from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Literal, Optional, Tuple


@dataclass
class BehaviorSample:
    timestamp: float
    tools: List[str]
    topics: List[str]
    sentiment: float
    response_length: int
    response_time: float
    had_error: bool
    satisfaction: Optional[float] = None
    goal_indicators: Optional[Dict[str, float]] = None
    custom_metrics: Optional[Dict[str, float]] = None


@dataclass
class BaselineProfile:
    tool_distribution: Dict[str, float]
    topic_distribution: Dict[str, float]
    avg_sentiment: float
    sentiment_std_dev: float
    avg_response_length: float
    response_length_std_dev: float
    avg_response_time: float
    response_time_std_dev: float
    error_rate: float
    avg_satisfaction: float
    sample_count: int
    last_updated: float


@dataclass
class DriftIndicator:
    type: str
    severity: Literal["low", "medium", "high", "critical"]
    description: str
    current_value: str
    baseline_value: str
    deviation: float


@dataclass
class BaselineComparison:
    tool_drift: float = 0.0
    topic_drift: float = 0.0
    sentiment_drift: float = 0.0
    response_length_drift: float = 0.0
    response_time_drift: float = 0.0
    error_rate_drift: float = 0.0


@dataclass
class DriftAnalysis:
    drift_score: int
    is_drifting: bool
    indicators: List[DriftIndicator]
    baseline_comparison: BaselineComparison
    recommendations: List[str]
    goal_alignment: Optional[float] = None


@dataclass
class DriftDetectorResult:
    allowed: bool
    reason: str
    request_id: str
    analysis: DriftAnalysis
    requires_review: bool
    kill_switch_recommended: bool


@dataclass
class DriftDetectorConfig:
    minimum_samples: int = 20
    anomaly_threshold: float = 2.5
    baseline_window: int = 24 * 60 * 60 * 1000  # 24 hours
    auto_update_baseline: bool = True
    alert_threshold: float = 60
    check_goal_alignment: bool = True
    on_drift: Optional[Callable[[str, DriftAnalysis], None]] = None
    on_recovery: Optional[Callable[[str], None]] = None


def _now_ms() -> float:
    return time.time() * 1000


class DriftDetector:
    def __init__(self, config: Optional[DriftDetectorConfig] = None) -> None:
        self._config = config or DriftDetectorConfig()
        self._samples: Dict[str, List[BehaviorSample]] = {}
        self._baselines: Dict[str, BaselineProfile] = {}
        self._drift_state: Dict[str, bool] = {}
        self._goal_definitions: Dict[str, Dict[str, Tuple[float, float]]] = {}

    def record_sample(self, agent_id: str, sample: BehaviorSample) -> None:
        # Cap agent entries to prevent unbounded growth
        if agent_id not in self._samples and len(self._samples) > 10_000:
            oldest = next(iter(self._samples))
            del self._samples[oldest]

        agent_samples = self._samples.get(agent_id, [])
        agent_samples.append(sample)

        # Clean old samples outside window
        cutoff = _now_ms() - self._config.baseline_window
        filtered = [s for s in agent_samples if s.timestamp > cutoff]
        self._samples[agent_id] = filtered

        # Update baseline if we have enough samples and auto-update is enabled
        if self._config.auto_update_baseline and len(filtered) >= self._config.minimum_samples:
            baseline = self._baselines.get(agent_id)
            if not baseline or _now_ms() - baseline.last_updated > self._config.baseline_window / 4:
                self.update_baseline(agent_id)

    def analyze(
        self,
        agent_id: str,
        current_sample: Optional[BehaviorSample] = None,
        request_id: Optional[str] = None,
    ) -> DriftDetectorResult:
        req_id = request_id or f"drift-{int(_now_ms())}"

        if current_sample:
            self.record_sample(agent_id, current_sample)

        samples = self._samples.get(agent_id, [])
        baseline = self._baselines.get(agent_id)

        # Not enough data
        if len(samples) < self._config.minimum_samples or not baseline:
            return DriftDetectorResult(
                allowed=True,
                reason="Insufficient data for drift detection",
                request_id=req_id,
                analysis=DriftAnalysis(
                    drift_score=0,
                    is_drifting=False,
                    indicators=[],
                    baseline_comparison=BaselineComparison(),
                    recommendations=["Collecting baseline data..."],
                ),
                requires_review=False,
                kill_switch_recommended=False,
            )

        # Get recent samples for comparison
        recent_samples = samples[-10:]
        analysis = self._perform_analysis(agent_id, recent_samples, baseline)

        # Check for state change
        was_drifting = self._drift_state.get(agent_id, False)
        is_drifting = analysis.is_drifting

        if is_drifting and not was_drifting:
            self._drift_state[agent_id] = True
            if self._config.on_drift:
                self._config.on_drift(agent_id, analysis)
        elif not is_drifting and was_drifting:
            self._drift_state[agent_id] = False
            if self._config.on_recovery:
                self._config.on_recovery(agent_id)

        # Decision
        should_block = analysis.drift_score >= 80
        requires_review = analysis.drift_score >= self._config.alert_threshold
        kill_switch = analysis.drift_score >= 90

        if should_block:
            reason = f"Agent drift detected: score {analysis.drift_score}"
        elif is_drifting:
            reason = f"Warning: drift score {analysis.drift_score}"
        else:
            reason = "Agent behavior within normal parameters"

        return DriftDetectorResult(
            allowed=not should_block,
            reason=reason,
            request_id=req_id,
            analysis=analysis,
            requires_review=requires_review,
            kill_switch_recommended=kill_switch,
        )

    def set_baseline(self, agent_id: str, baseline: BaselineProfile) -> None:
        self._baselines[agent_id] = baseline

    def get_baseline(self, agent_id: str) -> Optional[BaselineProfile]:
        return self._baselines.get(agent_id)

    def update_baseline(self, agent_id: str) -> None:
        samples = self._samples.get(agent_id, [])
        if len(samples) < self._config.minimum_samples:
            return
        baseline = self._calculate_baseline(samples)
        self._baselines[agent_id] = baseline

    def define_goals(
        self,
        agent_id: str,
        goals: Dict[str, Dict[str, float]],
    ) -> None:
        """goals: {name: {target: float, tolerance: float}}"""
        self._goal_definitions[agent_id] = {
            k: (v["target"], v["tolerance"]) for k, v in goals.items()
        }

    def is_drifting(self, agent_id: str) -> bool:
        return self._drift_state.get(agent_id, False)

    def get_drifting_agents(self) -> List[str]:
        return [aid for aid, drifting in self._drift_state.items() if drifting]

    def reset_agent(self, agent_id: str) -> None:
        self._samples.pop(agent_id, None)
        self._baselines.pop(agent_id, None)
        self._drift_state.pop(agent_id, None)
        self._goal_definitions.pop(agent_id, None)

    def get_sample_count(self, agent_id: str) -> int:
        return len(self._samples.get(agent_id, []))

    # --- Private methods ---

    def _calculate_baseline(self, samples: List[BehaviorSample]) -> BaselineProfile:
        # Tool distribution
        tool_counts: Dict[str, int] = {}
        for sample in samples:
            for tool in sample.tools:
                tool_counts[tool] = tool_counts.get(tool, 0) + 1
        total_tools = sum(tool_counts.values())
        tool_distribution = {t: c / (total_tools or 1) for t, c in tool_counts.items()}

        # Topic distribution
        topic_counts: Dict[str, int] = {}
        for sample in samples:
            for topic in sample.topics:
                topic_counts[topic] = topic_counts.get(topic, 0) + 1
        total_topics = sum(topic_counts.values())
        topic_distribution = {t: c / (total_topics or 1) for t, c in topic_counts.items()}

        # Numerical metrics
        sentiments = [s.sentiment for s in samples]
        response_lengths = [float(s.response_length) for s in samples]
        response_times = [s.response_time for s in samples]
        errors = sum(1 for s in samples if s.had_error)
        satisfactions = [s.satisfaction for s in samples if s.satisfaction is not None]

        return BaselineProfile(
            tool_distribution=tool_distribution,
            topic_distribution=topic_distribution,
            avg_sentiment=_mean(sentiments),
            sentiment_std_dev=_std_dev(sentiments),
            avg_response_length=_mean(response_lengths),
            response_length_std_dev=_std_dev(response_lengths),
            avg_response_time=_mean(response_times),
            response_time_std_dev=_std_dev(response_times),
            error_rate=errors / len(samples),
            avg_satisfaction=_mean(satisfactions) if satisfactions else 0,
            sample_count=len(samples),
            last_updated=_now_ms(),
        )

    def _perform_analysis(
        self,
        agent_id: str,
        recent_samples: List[BehaviorSample],
        baseline: BaselineProfile,
    ) -> DriftAnalysis:
        indicators: List[DriftIndicator] = []
        drift_score = 0.0

        # Calculate recent metrics
        recent_tool_dist = self._calculate_distribution(recent_samples, "tools")
        recent_topic_dist = self._calculate_distribution(recent_samples, "topics")
        recent_sentiment = _mean([s.sentiment for s in recent_samples])
        recent_response_length = _mean([float(s.response_length) for s in recent_samples])
        recent_response_time = _mean([s.response_time for s in recent_samples])
        recent_error_rate = sum(1 for s in recent_samples if s.had_error) / len(recent_samples)

        # Tool drift
        tool_drift = _distribution_divergence(baseline.tool_distribution, recent_tool_dist)
        if tool_drift > 0.3:
            severity: Literal["low", "medium", "high", "critical"] = "high" if tool_drift > 0.6 else ("medium" if tool_drift > 0.4 else "low")
            indicators.append(DriftIndicator(
                type="tool_distribution",
                severity=severity,
                description="Tool usage pattern has shifted significantly",
                current_value=json.dumps(recent_tool_dist),
                baseline_value=json.dumps(baseline.tool_distribution),
                deviation=tool_drift,
            ))
            drift_score += tool_drift * 30

        # Topic drift
        topic_drift = _distribution_divergence(baseline.topic_distribution, recent_topic_dist)
        if topic_drift > 0.3:
            severity = "high" if topic_drift > 0.6 else ("medium" if topic_drift > 0.4 else "low")
            indicators.append(DriftIndicator(
                type="topic_distribution",
                severity=severity,
                description="Topic focus has shifted significantly",
                current_value=json.dumps(recent_topic_dist),
                baseline_value=json.dumps(baseline.topic_distribution),
                deviation=topic_drift,
            ))
            drift_score += topic_drift * 25

        # Sentiment drift
        sentiment_deviation = abs(recent_sentiment - baseline.avg_sentiment) / (baseline.sentiment_std_dev or 0.1)
        if sentiment_deviation > self._config.anomaly_threshold:
            severity = "high" if sentiment_deviation > 4 else ("medium" if sentiment_deviation > 3 else "low")
            indicators.append(DriftIndicator(
                type="sentiment",
                severity=severity,
                description="Sentiment has deviated from baseline",
                current_value=f"{recent_sentiment:.2f}",
                baseline_value=f"{baseline.avg_sentiment:.2f}",
                deviation=sentiment_deviation,
            ))
            drift_score += min(sentiment_deviation * 5, 25)

        # Response length drift
        length_deviation = abs(recent_response_length - baseline.avg_response_length) / (baseline.response_length_std_dev or 100)
        if length_deviation > self._config.anomaly_threshold:
            severity = "high" if length_deviation > 4 else ("medium" if length_deviation > 3 else "low")
            indicators.append(DriftIndicator(
                type="response_length",
                severity=severity,
                description="Response length has changed significantly",
                current_value=f"{recent_response_length:.0f}",
                baseline_value=f"{baseline.avg_response_length:.0f}",
                deviation=length_deviation,
            ))
            drift_score += min(length_deviation * 3, 15)

        # Response time drift
        time_deviation = abs(recent_response_time - baseline.avg_response_time) / (baseline.response_time_std_dev or 100)
        if time_deviation > self._config.anomaly_threshold:
            severity = "high" if time_deviation > 4 else ("medium" if time_deviation > 3 else "low")
            indicators.append(DriftIndicator(
                type="response_time",
                severity=severity,
                description="Response time has changed significantly",
                current_value=f"{recent_response_time:.0f}ms",
                baseline_value=f"{baseline.avg_response_time:.0f}ms",
                deviation=time_deviation,
            ))
            drift_score += min(time_deviation * 3, 15)

        # Error rate drift
        error_rate_diff = recent_error_rate - baseline.error_rate
        if error_rate_diff > 0.1:
            severity = "critical" if error_rate_diff > 0.3 else ("high" if error_rate_diff > 0.2 else "medium")
            indicators.append(DriftIndicator(
                type="error_rate",
                severity=severity,
                description="Error rate has increased significantly",
                current_value=f"{recent_error_rate * 100:.1f}%",
                baseline_value=f"{baseline.error_rate * 100:.1f}%",
                deviation=error_rate_diff,
            ))
            drift_score += error_rate_diff * 100

        # Goal alignment check
        goal_alignment: Optional[float] = None
        if self._config.check_goal_alignment:
            goals = self._goal_definitions.get(agent_id)
            if goals and any(s.goal_indicators for s in recent_samples):
                goal_alignment = self._check_goal_alignment(recent_samples, goals, indicators)
                if goal_alignment < 0.7:
                    drift_score += (1 - goal_alignment) * 30

        # Cap drift score
        drift_score_int = min(100, round(drift_score))

        return DriftAnalysis(
            drift_score=drift_score_int,
            is_drifting=drift_score_int >= self._config.alert_threshold,
            indicators=indicators,
            baseline_comparison=BaselineComparison(
                tool_drift=tool_drift,
                topic_drift=topic_drift,
                sentiment_drift=sentiment_deviation,
                response_length_drift=length_deviation,
                response_time_drift=time_deviation,
                error_rate_drift=error_rate_diff,
            ),
            goal_alignment=goal_alignment,
            recommendations=_generate_recommendations(indicators, drift_score_int),
        )

    def _calculate_distribution(
        self,
        samples: List[BehaviorSample],
        attr: str,
    ) -> Dict[str, float]:
        counts: Dict[str, int] = {}
        for sample in samples:
            for item in getattr(sample, attr):
                counts[item] = counts.get(item, 0) + 1
        total = sum(counts.values())
        return {k: v / (total or 1) for k, v in counts.items()}

    def _check_goal_alignment(
        self,
        samples: List[BehaviorSample],
        goals: Dict[str, Tuple[float, float]],
        indicators: List[DriftIndicator],
    ) -> float:
        alignment_sum = 0.0
        goal_count = 0

        for goal_name, (target, tolerance) in goals.items():
            values = [
                s.goal_indicators[goal_name]
                for s in samples
                if s.goal_indicators and goal_name in s.goal_indicators
            ]
            if not values:
                continue

            avg_value = _mean(values)
            deviation = abs(avg_value - target)
            alignment = max(0, 1 - deviation / tolerance)

            alignment_sum += alignment
            goal_count += 1

            if alignment < 0.7:
                severity: Literal["low", "medium", "high", "critical"]
                if alignment < 0.3:
                    severity = "critical"
                elif alignment < 0.5:
                    severity = "high"
                else:
                    severity = "medium"

                indicators.append(DriftIndicator(
                    type=f"goal_{goal_name}",
                    severity=severity,
                    description=f"Goal '{goal_name}' alignment is low",
                    current_value=f"{avg_value:.2f}",
                    baseline_value=f"{target:.2f}",
                    deviation=deviation,
                ))

        return alignment_sum / goal_count if goal_count > 0 else 1.0


# --- Module-level utility functions ---

def _mean(values: List[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _std_dev(values: List[float]) -> float:
    if len(values) < 2:
        return 0.0
    avg = _mean(values)
    square_diffs = [(v - avg) ** 2 for v in values]
    return math.sqrt(_mean(square_diffs))


def _distribution_divergence(
    baseline: Dict[str, float],
    current: Dict[str, float],
) -> float:
    """Simplified Jensen-Shannon divergence."""
    all_keys = set(list(baseline.keys()) + list(current.keys()))
    divergence = 0.0

    for key in all_keys:
        p = baseline.get(key, 0.001)
        q = current.get(key, 0.001)
        m = (p + q) / 2

        if p > 0:
            divergence += p * math.log2(p / m)
        if q > 0:
            divergence += q * math.log2(q / m)

    return divergence / 2  # Normalized to [0, 1]


def _generate_recommendations(indicators: List[DriftIndicator], drift_score: int) -> List[str]:
    recommendations: List[str] = []

    if drift_score >= 90:
        recommendations.append("CRITICAL: Consider activating kill switch for this agent")
    if drift_score >= 70:
        recommendations.append("Immediate review of agent behavior required")

    critical_indicators = [i for i in indicators if i.severity in ("critical", "high")]
    for indicator in critical_indicators:
        if indicator.type == "tool_distribution":
            recommendations.append("Review tool access permissions")
        elif indicator.type == "topic_distribution":
            recommendations.append("Verify agent is operating within intended domain")
        elif indicator.type == "error_rate":
            recommendations.append("Investigate root cause of increased errors")
        elif indicator.type == "sentiment":
            recommendations.append("Review recent interactions for quality issues")
        elif indicator.type.startswith("goal_"):
            recommendations.append(f"Review goal alignment for {indicator.type.replace('goal_', '')}")

    if not recommendations:
        recommendations.append("Agent behavior is within normal parameters")

    return recommendations
