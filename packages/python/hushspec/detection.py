from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from hushspec.evaluate import (
    Decision,
    EvaluationAction,
    EvaluationResult,
    evaluate,
)
from hushspec.schema import HushSpec





class DetectionCategory(str, Enum):

    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_EXFILTRATION = "data_exfiltration"


@dataclass
class MatchedPattern:
    name: str
    weight: float
    matched_text: Optional[str] = None


@dataclass
class DetectionResult:
    detector_name: str
    category: DetectionCategory
    score: float
    matched_patterns: list[MatchedPattern] = field(default_factory=list)
    explanation: Optional[str] = None





class Detector(ABC):

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def category(self) -> DetectionCategory: ...

    @abstractmethod
    def detect(self, input_text: str) -> DetectionResult: ...





class DetectorRegistry:

    def __init__(self) -> None:
        self._detectors: list[Detector] = []

    def register(self, detector: Detector) -> None:
        self._detectors.append(detector)

    @classmethod
    def with_defaults(cls) -> "DetectorRegistry":
        registry = cls()
        registry.register(RegexInjectionDetector())
        registry.register(RegexExfiltrationDetector())
        return registry

    def detect_all(self, input_text: str) -> list[DetectionResult]:
        return [d.detect(input_text) for d in self._detectors]





@dataclass
class _DetectionPattern:
    name: str
    regex: re.Pattern[str]
    weight: float
    category: DetectionCategory





class RegexInjectionDetector(Detector):

    def __init__(self) -> None:
        self._patterns: list[_DetectionPattern] = [
            _DetectionPattern(
                name="ignore_instructions",
                regex=re.compile(
                    r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts)",
                    re.IGNORECASE,
                ),
                weight=0.4,
                category=DetectionCategory.PROMPT_INJECTION,
            ),
            _DetectionPattern(
                name="new_instructions",
                regex=re.compile(
                    r"(new|updated|revised)\s+instructions?\s*:", re.IGNORECASE
                ),
                weight=0.3,
                category=DetectionCategory.PROMPT_INJECTION,
            ),
            _DetectionPattern(
                name="system_prompt_extract",
                regex=re.compile(
                    r"(reveal|show|display|print|output)\s+(your|the)\s+(system\s+)?(prompt|instructions|rules)",
                    re.IGNORECASE,
                ),
                weight=0.4,
                category=DetectionCategory.PROMPT_INJECTION,
            ),
            _DetectionPattern(
                name="role_override",
                regex=re.compile(
                    r"you\s+are\s+now\s+(a|an|the)\s+", re.IGNORECASE
                ),
                weight=0.3,
                category=DetectionCategory.PROMPT_INJECTION,
            ),
            _DetectionPattern(
                name="pretend_mode",
                regex=re.compile(
                    r"(pretend|imagine|act\s+as\s+if|suppose)\s+(you|that|we)",
                    re.IGNORECASE,
                ),
                weight=0.2,
                category=DetectionCategory.PROMPT_INJECTION,
            ),
            _DetectionPattern(
                name="jailbreak_dan",
                regex=re.compile(
                    r"(DAN|do\s+anything\s+now|developer\s+mode|jailbreak)",
                    re.IGNORECASE,
                ),
                weight=0.5,
                category=DetectionCategory.JAILBREAK,
            ),
            _DetectionPattern(
                name="delimiter_injection",
                regex=re.compile(
                    r"(---+|===+|```)\s*(system|assistant|user)\s*[:\n]",
                    re.IGNORECASE,
                ),
                weight=0.4,
                category=DetectionCategory.PROMPT_INJECTION,
            ),
            _DetectionPattern(
                name="encoding_evasion",
                regex=re.compile(
                    r"(base64|rot13|hex|url.?encod|unicode)\s*(decod|encod|convert)",
                    re.IGNORECASE,
                ),
                weight=0.1,
                category=DetectionCategory.PROMPT_INJECTION,
            ),
        ]

    @property
    def name(self) -> str:
        return "regex_injection"

    @property
    def category(self) -> DetectionCategory:
        return DetectionCategory.PROMPT_INJECTION

    def detect(self, input_text: str) -> DetectionResult:
        matched_patterns: list[MatchedPattern] = []
        total_weight = 0.0

        for pattern in self._patterns:
            m = pattern.regex.search(input_text)
            if m:
                total_weight += pattern.weight
                matched_patterns.append(
                    MatchedPattern(
                        name=pattern.name,
                        weight=pattern.weight,
                        matched_text=m.group(0),
                    )
                )

        score = min(total_weight, 1.0)

        explanation: Optional[str] = None
        if matched_patterns:
            names = ", ".join(p.name for p in matched_patterns)
            explanation = (
                f"matched {len(matched_patterns)} injection/jailbreak pattern(s): {names}"
            )

        return DetectionResult(
            detector_name=self.name,
            category=self.category,
            score=score,
            matched_patterns=matched_patterns,
            explanation=explanation,
        )





class RegexExfiltrationDetector(Detector):

    def __init__(self) -> None:
        self._patterns: list[_DetectionPattern] = [
            _DetectionPattern(
                name="ssn",
                regex=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
                weight=0.8,
                category=DetectionCategory.DATA_EXFILTRATION,
            ),
            _DetectionPattern(
                name="credit_card",
                regex=re.compile(
                    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"
                ),
                weight=0.8,
                category=DetectionCategory.DATA_EXFILTRATION,
            ),
            _DetectionPattern(
                name="email_address",
                regex=re.compile(
                    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
                ),
                weight=0.3,
                category=DetectionCategory.DATA_EXFILTRATION,
            ),
            _DetectionPattern(
                name="api_key_pattern",
                regex=re.compile(
                    r"(api[_\-]?key|secret[_\-]?key|access[_\-]?token)\s*[:=]\s*\S+",
                    re.IGNORECASE,
                ),
                weight=0.6,
                category=DetectionCategory.DATA_EXFILTRATION,
            ),
            _DetectionPattern(
                name="private_key",
                regex=re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"),
                weight=0.9,
                category=DetectionCategory.DATA_EXFILTRATION,
            ),
        ]

    @property
    def name(self) -> str:
        return "regex_exfiltration"

    @property
    def category(self) -> DetectionCategory:
        return DetectionCategory.DATA_EXFILTRATION

    def detect(self, input_text: str) -> DetectionResult:
        matched_patterns: list[MatchedPattern] = []
        total_weight = 0.0

        for pattern in self._patterns:
            m = pattern.regex.search(input_text)
            if m:
                total_weight += pattern.weight
                matched_patterns.append(
                    MatchedPattern(
                        name=pattern.name,
                        weight=pattern.weight,
                        matched_text=m.group(0),
                    )
                )

        score = min(total_weight, 1.0)

        explanation: Optional[str] = None
        if matched_patterns:
            names = ", ".join(p.name for p in matched_patterns)
            explanation = (
                f"matched {len(matched_patterns)} exfiltration pattern(s): {names}"
            )

        return DetectionResult(
            detector_name=self.name,
            category=self.category,
            score=score,
            matched_patterns=matched_patterns,
            explanation=explanation,
        )





@dataclass
class DetectionConfig:
    enabled: bool = True
    prompt_injection_threshold: float = 0.5
    jailbreak_threshold: float = 0.5
    exfiltration_threshold: float = 0.5


@dataclass
class EvaluationWithDetection:
    evaluation: EvaluationResult
    detections: list[DetectionResult] = field(default_factory=list)
    detection_decision: Optional[Decision] = None


def _check_thresholds(
    detections: list[DetectionResult], config: DetectionConfig
) -> Optional[Decision]:
    should_deny = False

    for result in detections:
        if result.category == DetectionCategory.PROMPT_INJECTION:
            threshold = config.prompt_injection_threshold
        elif result.category == DetectionCategory.JAILBREAK:
            threshold = config.jailbreak_threshold
        else:
            threshold = config.exfiltration_threshold

        if result.score >= threshold:
            should_deny = True

    return Decision.DENY if should_deny else None


def evaluate_with_detection(
    spec: HushSpec,
    action: EvaluationAction,
    registry: DetectorRegistry,
    config: Optional[DetectionConfig] = None,
) -> EvaluationWithDetection:
    if config is None:
        config = DetectionConfig()

    evaluation = evaluate(spec, action)

    if not config.enabled:
        return EvaluationWithDetection(evaluation=evaluation)

    content = action.content or ""
    if not content:
        return EvaluationWithDetection(evaluation=evaluation)

    detections = registry.detect_all(content)
    detection_decision = _check_thresholds(detections, config)

    if detection_decision == Decision.DENY and evaluation.decision != Decision.DENY:
        final_eval = EvaluationResult(
            decision=Decision.DENY,
            matched_rule="detection",
            reason="content exceeded detection threshold",
            origin_profile=evaluation.origin_profile,
            posture=evaluation.posture,
        )
    else:
        final_eval = evaluation

    return EvaluationWithDetection(
        evaluation=final_eval,
        detections=detections,
        detection_decision=detection_decision,
    )
