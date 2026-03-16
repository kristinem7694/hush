from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from hushspec import parse
from hushspec.evaluate import (
    Decision,
    EvaluationAction,
    OriginContext,
    PostureContext,
    evaluate,
)

FIXTURES_ROOT = Path(__file__).parent.parent.parent.parent / "fixtures"

EVALUATION_DIRS = ["core/evaluation", "posture/evaluation", "origins/evaluation"]


def _build_origin(data: dict) -> OriginContext:
    return OriginContext(
        provider=data.get("provider"),
        tenant_id=data.get("tenant_id"),
        space_id=data.get("space_id"),
        space_type=data.get("space_type"),
        visibility=data.get("visibility"),
        external_participants=data.get("external_participants"),
        tags=data.get("tags", []),
        sensitivity=data.get("sensitivity"),
        actor_role=data.get("actor_role"),
    )


def _build_posture(data: dict) -> PostureContext:
    return PostureContext(
        current=data.get("current"),
        signal=data.get("signal"),
    )


def _build_action(data: dict) -> EvaluationAction:
    origin = _build_origin(data["origin"]) if "origin" in data else None
    posture = _build_posture(data["posture"]) if "posture" in data else None
    return EvaluationAction(
        type=data["type"],
        target=data.get("target"),
        content=data.get("content"),
        origin=origin,
        posture=posture,
        args_size=data.get("args_size"),
    )


def _collect_evaluation_cases():
    cases = []
    for eval_dir in EVALUATION_DIRS:
        dir_path = FIXTURES_ROOT / eval_dir
        if not dir_path.exists():
            continue
        for yaml_file in sorted(dir_path.glob("*.yaml")):
            with open(yaml_file) as f:
                fixture = yaml.safe_load(f)
            for case in fixture["cases"]:
                test_id = (
                    f"{yaml_file.relative_to(FIXTURES_ROOT)}::{case['description']}"
                )
                cases.append(
                    pytest.param(
                        fixture["policy"],
                        case,
                        id=test_id,
                    )
                )
    return cases


@pytest.mark.parametrize("policy,case", _collect_evaluation_cases())
def test_evaluation(policy: dict, case: dict):
    ok, spec_or_err = parse(yaml.dump(policy))
    assert ok, f"Failed to parse policy: {spec_or_err}"
    spec = spec_or_err

    action = _build_action(case["action"])
    result = evaluate(spec, action)

    expected = case["expect"]
    assert result.decision.value == expected["decision"], (
        f"{case['description']}: expected decision={expected['decision']}, "
        f"got {result.decision.value}"
    )

    if "matched_rule" in expected:
        assert result.matched_rule == expected["matched_rule"], (
            f"{case['description']}: expected matched_rule={expected['matched_rule']}, "
            f"got {result.matched_rule}"
        )

    if "origin_profile" in expected:
        assert result.origin_profile == expected["origin_profile"], (
            f"{case['description']}: expected origin_profile={expected['origin_profile']}, "
            f"got {result.origin_profile}"
        )

    if "posture" in expected:
        assert result.posture is not None, (
            f"{case['description']}: expected posture but got None"
        )
        assert result.posture.current == expected["posture"]["current"], (
            f"{case['description']}: expected posture.current={expected['posture']['current']}, "
            f"got {result.posture.current}"
        )
        assert result.posture.next == expected["posture"]["next"], (
            f"{case['description']}: expected posture.next={expected['posture']['next']}, "
            f"got {result.posture.next}"
        )
