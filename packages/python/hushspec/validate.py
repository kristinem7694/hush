from __future__ import annotations

import re
from dataclasses import dataclass, field

from datetime import date

from hushspec.extensions import DetectionLevel, TransitionTrigger
from hushspec.schema import Classification, HushSpec, LifecycleState
from hushspec.version import is_supported

_CAPABILITY_NAMES = frozenset(
    {"file_access", "file_write", "egress", "shell", "tool_call", "patch", "custom"}
)

_BUDGET_NAMES = frozenset(
    {"file_writes", "egress_calls", "shell_commands", "tool_calls", "patches", "custom_calls"}
)

_DURATION_PATTERN = re.compile(r"^\d+[smhd]$")
_DETECTION_LEVEL_ORDER = {
    DetectionLevel.SAFE: 0,
    DetectionLevel.SUSPICIOUS: 1,
    DetectionLevel.HIGH: 2,
    DetectionLevel.CRITICAL: 3,
}


@dataclass
class ValidationError:
    code: str
    message: str

    def __str__(self) -> str:
        return self.message


@dataclass
class ValidationResult:
    errors: list[ValidationError] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return not self.errors


def validate(spec: HushSpec) -> ValidationResult:
    errors: list[ValidationError] = []
    warnings: list[str] = []

    if not is_supported(spec.hushspec):
        errors.append(
            ValidationError("unsupported_version", f"unsupported hushspec version: {spec.hushspec}")
        )

    if spec.rules is not None:
        _validate_rules(spec.rules, errors)

        if (
            spec.rules.forbidden_paths is None
            and spec.rules.path_allowlist is None
            and spec.rules.egress is None
            and spec.rules.secret_patterns is None
            and spec.rules.patch_integrity is None
            and spec.rules.shell_commands is None
            and spec.rules.tool_access is None
            and spec.rules.computer_use is None
            and spec.rules.remote_desktop_channels is None
            and spec.rules.input_injection is None
        ):
            warnings.append("no rules configured")
    else:
        warnings.append("no rules section present")

    if spec.extensions is not None:
        _validate_posture(spec.extensions, errors, warnings)
        _validate_origins(spec.extensions, errors)
        _validate_detection(spec.extensions, errors, warnings)

    _validate_governance(spec, warnings)

    return ValidationResult(errors=errors, warnings=warnings)


def _validate_rules(rules: object, errors: list[ValidationError]) -> None:
    from hushspec.rules import Rules

    assert isinstance(rules, Rules)

    if rules.secret_patterns is not None:
        seen: set[str] = set()
        for pattern in rules.secret_patterns.patterns:
            if pattern.name in seen:
                errors.append(
                    ValidationError(
                        "duplicate_pattern_name",
                        f"duplicate secret pattern name: {pattern.name}",
                    )
                )
            seen.add(pattern.name)
            _validate_regex(
                pattern.pattern,
                f"secret_patterns.patterns.{pattern.name}",
                errors,
            )

    if rules.patch_integrity is not None:
        if rules.patch_integrity.max_imbalance_ratio <= 0.0:
            errors.append(
                ValidationError(
                    "invalid_ratio",
                    "rules.patch_integrity.max_imbalance_ratio must be > 0",
                )
            )
        for index, pattern in enumerate(rules.patch_integrity.forbidden_patterns):
            _validate_regex(
                pattern,
                f"rules.patch_integrity.forbidden_patterns[{index}]",
                errors,
            )

    if rules.shell_commands is not None:
        for index, pattern in enumerate(rules.shell_commands.forbidden_patterns):
            _validate_regex(
                pattern,
                f"rules.shell_commands.forbidden_patterns[{index}]",
                errors,
            )

    if rules.tool_access is not None and rules.tool_access.max_args_size == 0:
        errors.append(
            ValidationError(
                "invalid_max_args_size",
                "rules.tool_access.max_args_size must be >= 1",
            )
        )


def _validate_posture(ext: object, errors: list[ValidationError], warnings: list[str]) -> None:
    from hushspec.extensions import Extensions

    assert isinstance(ext, Extensions)

    if ext.posture is None:
        return

    posture = ext.posture

    if not posture.states:
        errors.append(
            ValidationError(
                "empty_states",
                "posture.states must define at least one state",
            )
        )

    if posture.initial not in posture.states:
        errors.append(
            ValidationError(
                "invalid_posture_initial",
                f"posture.initial '{posture.initial}' does not reference a defined state",
            )
        )

    for state_name, state in posture.states.items():
        for capability in state.capabilities:
            if capability not in _CAPABILITY_NAMES:
                warnings.append(
                    f"posture.states.{state_name}.capabilities includes unknown capability '{capability}'"
                )

        for budget_key, value in state.budgets.items():
            if value < 0:
                errors.append(
                    ValidationError(
                        "negative_budget",
                        f"posture.states.{state_name}.budgets.{budget_key} must be non-negative, got {value}",
                    )
                )
            if budget_key not in _BUDGET_NAMES:
                warnings.append(
                    f"posture.states.{state_name}.budgets uses unknown budget key '{budget_key}'"
                )

    for index, transition in enumerate(posture.transitions):
        if transition.from_state != "*" and transition.from_state not in posture.states:
            errors.append(
                ValidationError(
                    "invalid_transition_from",
                    f"posture.transitions[{index}].from '{transition.from_state}' does not reference a defined state",
                )
            )

        if transition.to == "*":
            errors.append(
                ValidationError(
                    "invalid_transition_to",
                    f"posture.transitions[{index}].to cannot be '*'",
                )
            )
        elif transition.to not in posture.states:
            errors.append(
                ValidationError(
                    "invalid_transition_to",
                    f"posture.transitions[{index}].to '{transition.to}' does not reference a defined state",
                )
            )

        if transition.on != TransitionTrigger.TIMEOUT:
            if transition.after is not None and not _is_valid_duration(transition.after):
                errors.append(
                    ValidationError(
                        "invalid_duration",
                        f"posture.transitions[{index}].after must match ^\\d+[smhd]$",
                    )
                )

        if transition.on == TransitionTrigger.TIMEOUT:
            if transition.after is None:
                errors.append(
                    ValidationError(
                        "missing_timeout_after",
                        f"posture.transitions[{index}]: timeout trigger requires 'after' field",
                    )
                )
            elif not _is_valid_duration(transition.after):
                errors.append(
                    ValidationError(
                        "invalid_duration",
                        f"posture.transitions[{index}].after must match ^\\d+[smhd]$",
                    )
                )


def _validate_origins(ext: object, errors: list[ValidationError]) -> None:
    from hushspec.extensions import Extensions

    assert isinstance(ext, Extensions)

    if ext.origins is None:
        return

    origins = ext.origins

    posture_states: set[str] | None = None
    if ext.posture is not None:
        posture_states = set(ext.posture.states)

    seen_ids: set[str] = set()
    for index, profile in enumerate(origins.profiles):
        if profile.id in seen_ids:
            errors.append(
                ValidationError(
                    "duplicate_origin_profile_id",
                    f"duplicate origin profile id: '{profile.id}'",
                )
            )
        seen_ids.add(profile.id)

        if profile.posture is not None:
            if posture_states is None:
                errors.append(
                    ValidationError(
                        "invalid_origin_posture",
                        f"origins.profiles[{index}].posture requires extensions.posture to be defined",
                    )
                )
            elif profile.posture not in posture_states:
                errors.append(
                    ValidationError(
                        "invalid_origin_posture",
                        f"origins.profiles[{index}].posture '{profile.posture}' does not reference a defined posture state",
                    )
                )


def _validate_detection(
    ext: object, errors: list[ValidationError], warnings: list[str]
) -> None:
    from hushspec.extensions import Extensions

    assert isinstance(ext, Extensions)

    if ext.detection is None:
        return

    detection = ext.detection

    if detection.prompt_injection is not None:
        pi = detection.prompt_injection

        if pi.max_scan_bytes == 0:
            errors.append(
                ValidationError(
                    "invalid_max_scan_bytes",
                    "detection.prompt_injection.max_scan_bytes must be >= 1",
                )
            )

        warn_level = pi.warn_at_or_above or DetectionLevel.SUSPICIOUS
        block_level = pi.block_at_or_above or DetectionLevel.HIGH
        if _DETECTION_LEVEL_ORDER[block_level] < _DETECTION_LEVEL_ORDER[warn_level]:
            warnings.append(
                "detection.prompt_injection: block_at_or_above is less strict than warn_at_or_above"
            )

    if detection.jailbreak is not None:
        jb = detection.jailbreak

        if jb.block_threshold is not None and jb.block_threshold > 100:
            errors.append(
                ValidationError(
                    "out_of_range",
                    "detection.jailbreak.block_threshold must be between 0 and 100",
                )
            )
        if jb.warn_threshold is not None and jb.warn_threshold > 100:
            errors.append(
                ValidationError(
                    "out_of_range",
                    "detection.jailbreak.warn_threshold must be between 0 and 100",
                )
            )
        if jb.max_input_bytes == 0:
            errors.append(
                ValidationError(
                    "invalid_max_input_bytes",
                    "detection.jailbreak.max_input_bytes must be >= 1",
                )
            )

        block_threshold = jb.block_threshold if jb.block_threshold is not None else 80
        warn_threshold = jb.warn_threshold if jb.warn_threshold is not None else 50
        if block_threshold < warn_threshold:
            warnings.append(
                "detection.jailbreak: block_threshold is lower than warn_threshold"
            )

    if detection.threat_intel is not None:
        ti = detection.threat_intel

        if ti.similarity_threshold is not None:
            if not (0.0 <= ti.similarity_threshold <= 1.0):
                errors.append(
                    ValidationError(
                        "out_of_range",
                        "detection.threat_intel.similarity_threshold must be between 0.0 and 1.0",
                    )
                )

        if ti.top_k == 0:
            errors.append(
                ValidationError(
                    "invalid_top_k",
                    "detection.threat_intel.top_k must be >= 1",
                )
            )


# Pattern that detects regex features outside the RE2 subset.
#
# HushSpec requires all regex patterns to be RE2-compatible to prevent ReDoS
# attacks. Python's ``re`` module uses a backtracking engine that is vulnerable
# to catastrophic backtracking with certain pattern constructs.  By restricting
# patterns to the RE2 subset we ensure safe O(mn) evaluation across all SDKs.
#
# Disallowed features:
# - Backreferences: \1, \2, ..., \k<name>
# - Lookahead: (?=...), (?!...)
# - Lookbehind: (?<=...), (?<!...)
# - Atomic groups: (?>...)
# - Possessive quantifiers: *+, ++, ?+
# - Conditional patterns: (?(...)...|...)
# - Recursive patterns: (?R), (?1), (?2), ...
# - Named backreferences: (?P=name)
# - Subroutine calls: \g<name>
_RE2_DISALLOWED = re.compile(
    r"\\[1-9]|\\k<|\(\?[=!]|\(\?<[=!]|\(\?>|\*\+|\+\+|\?\+|\(\?\(|\(\?R\)|\(\?\d+\)|\(\?P=|\\g<"
)


def is_safe_regex(pattern: str) -> bool:
    """Check whether a regex pattern is safe for evaluation (RE2-compatible).

    Returns ``True`` if the pattern uses only RE2-compatible features.
    Returns ``False`` if the pattern contains backreferences, lookaround,
    atomic groups, possessive quantifiers, or other non-RE2 features.
    """
    return _RE2_DISALLOWED.search(pattern) is None


def _validate_regex(pattern: str, path: str, errors: list[ValidationError]) -> None:
    try:
        re.compile(pattern)
    except re.error as e:
        errors.append(
            ValidationError(
                "invalid_regex",
                f"{path} must be a valid regular expression: {e}",
            )
        )
        return

    if not is_safe_regex(pattern):
        errors.append(
            ValidationError(
                "non_re2_regex",
                f"{path}: pattern uses features not in the RE2 subset "
                "(backreferences, lookaround, etc.) which may cause ReDoS",
            )
        )


def _is_valid_duration(value: str) -> bool:
    return bool(_DURATION_PATTERN.match(value))


def _validate_governance(spec: HushSpec, warnings: list[str]) -> None:
    if spec.metadata is None:
        return

    metadata = spec.metadata

    if metadata.lifecycle_state is not None:
        if metadata.lifecycle_state in (LifecycleState.DEPRECATED, LifecycleState.ARCHIVED):
            warnings.append(
                f"policy lifecycle state is '{metadata.lifecycle_state.value}'"
            )

    if metadata.expiry_date is not None:
        today = date.today().isoformat()
        if metadata.expiry_date < today:
            warnings.append(
                f"policy expiry_date '{metadata.expiry_date}' is in the past"
            )

    if metadata.approved_by is not None and metadata.approval_date is None:
        warnings.append("approved_by is set but approval_date is missing")

    if metadata.classification == Classification.RESTRICTED and metadata.approved_by is None:
        warnings.append("classification is 'restricted' but no approved_by is set")
