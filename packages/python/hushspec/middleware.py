from __future__ import annotations

import json
from typing import Callable, Optional, TYPE_CHECKING

from hushspec.evaluate import Decision, EvaluationAction, EvaluationResult, evaluate
from hushspec.parse import parse_or_raise
from hushspec.schema import HushSpec

if TYPE_CHECKING:
    from hushspec.observer import EvaluationObserver

WarnHandler = Callable[[EvaluationResult, EvaluationAction], bool]


class HushSpecDenied(Exception):
    def __init__(self, result: EvaluationResult) -> None:
        self.result = result
        reason = result.reason or result.matched_rule or "policy denial"
        super().__init__(f"Action denied: {reason}")


class HushGuard:
    """Fail-closed policy guard: wraps evaluate / check / enforce semantics."""

    def __init__(
        self,
        policy: HushSpec,
        on_warn: Optional[WarnHandler] = None,
        observer: Optional["EvaluationObserver"] = None,
    ) -> None:
        self._policy = policy
        self._on_warn: WarnHandler = on_warn or (lambda _r, _a: False)
        self._observable_evaluator = None
        self._policy_hash: Optional[str] = None
        if observer is not None:
            from hushspec.observer import ObservableEvaluator
            from hushspec.receipt import compute_policy_hash
            self._observable_evaluator = ObservableEvaluator()
            self._observable_evaluator.add_observer(observer)
            self._policy_hash = compute_policy_hash(policy)
            self._observable_evaluator.notify_policy_loaded(policy.name, self._policy_hash)

    @classmethod
    def from_file(
        cls,
        path: str,
        on_warn: Optional[WarnHandler] = None,
        observer: Optional["EvaluationObserver"] = None,
    ) -> HushGuard:
        with open(path) as f:
            spec = parse_or_raise(f.read())
        return cls(spec, on_warn, observer=observer)

    @classmethod
    def from_yaml(
        cls,
        yaml_str: str,
        on_warn: Optional[WarnHandler] = None,
        observer: Optional["EvaluationObserver"] = None,
    ) -> HushGuard:
        spec = parse_or_raise(yaml_str)
        return cls(spec, on_warn, observer=observer)

    def evaluate(self, action: EvaluationAction) -> EvaluationResult:
        if self._observable_evaluator is not None:
            return self._observable_evaluator.evaluate(self._policy, action)
        return evaluate(self._policy, action)

    def check(self, action: EvaluationAction) -> bool:
        result = self.evaluate(action)
        if result.decision == Decision.ALLOW:
            return True
        if result.decision == Decision.WARN:
            return self._on_warn(result, action)
        return False

    def enforce(self, action: EvaluationAction) -> None:
        result = self.evaluate(action)
        if result.decision == Decision.DENY:
            raise HushSpecDenied(result)
        if result.decision == Decision.WARN and not self._on_warn(result, action):
            raise HushSpecDenied(result)

    @staticmethod
    def map_tool_call(
        tool_name: str,
        args: Optional[dict] = None,
    ) -> EvaluationAction:
        return EvaluationAction(
            type="tool_call",
            target=tool_name,
            args_size=len(json.dumps(args)) if args is not None else None,
        )

    @staticmethod
    def map_file_read(path: str) -> EvaluationAction:
        return EvaluationAction(type="file_read", target=path)

    @staticmethod
    def map_file_write(path: str, content: Optional[str] = None) -> EvaluationAction:
        return EvaluationAction(type="file_write", target=path, content=content)

    @staticmethod
    def map_egress(domain: str) -> EvaluationAction:
        return EvaluationAction(type="egress", target=domain)

    @staticmethod
    def map_shell_command(command: str) -> EvaluationAction:
        return EvaluationAction(type="shell_command", target=command)

    def swap_policy(self, new_policy: HushSpec) -> None:
        previous_hash = self._policy_hash
        self._policy = new_policy
        if self._observable_evaluator is not None:
            from hushspec.receipt import compute_policy_hash
            self._policy_hash = compute_policy_hash(new_policy)
            self._observable_evaluator.notify_policy_reloaded(
                new_policy.name,
                self._policy_hash,
                previous_hash,
            )
