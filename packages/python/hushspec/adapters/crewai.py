from __future__ import annotations

from typing import Callable, Optional

from hushspec.evaluate import EvaluationAction
from hushspec.middleware import HushGuard


def secure_tool(
    guard: HushGuard,
    tool_name: Optional[str] = None,
    action_type: str = "tool_call",
) -> Callable:
    """Decorator for CrewAI tool functions with HushSpec enforcement.

    Usage::

        guard = HushGuard.from_yaml(policy_yaml)

        @secure_tool(guard, tool_name="web_search")
        def web_search(query: str) -> str:
            ...

    If ``tool_name`` is omitted the wrapped function's ``__name__`` is used.
    Raises :class:`~hushspec.middleware.HushSpecDenied` when the policy denies
    the action.
    """

    def decorator(func: Callable) -> Callable:
        name = tool_name or getattr(func, "__name__", "unknown")

        def wrapper(*args, **kwargs):  # type: ignore[no-untyped-def]
            action = EvaluationAction(type=action_type, target=name)
            guard.enforce(action)
            return func(*args, **kwargs)

        wrapper.__name__ = func.__name__  # type: ignore[attr-defined]
        wrapper.__doc__ = func.__doc__
        wrapper.__wrapped__ = func  # type: ignore[attr-defined]
        return wrapper

    return decorator
