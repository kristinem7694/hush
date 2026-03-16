from __future__ import annotations

from typing import Callable, Optional

from hushspec.evaluate import EvaluationAction
from hushspec.middleware import HushGuard


def hush_tool(
    guard: HushGuard,
    tool_name: Optional[str] = None,
    action_type: str = "tool_call",
) -> Callable:
    """Decorator that wraps a LangChain tool function with HushSpec enforcement.

    Usage::

        guard = HushGuard.from_yaml(policy_yaml)

        @hush_tool(guard, tool_name="web_search")
        def web_search(query: str) -> str:
            ...

    If ``tool_name`` is omitted the wrapped function's ``__name__`` is used.
    Raises :class:`~hushspec.middleware.HushSpecDenied` when the policy denies
    the action.
    """

    def decorator(func: Callable) -> Callable:
        name = tool_name or func.__name__

        def wrapper(*args, **kwargs):  # type: ignore[no-untyped-def]
            action = EvaluationAction(type=action_type, target=name)
            guard.enforce(action)
            return func(*args, **kwargs)

        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper

    return decorator
