from __future__ import annotations

import json

from hushspec.evaluate import EvaluationAction, EvaluationResult
from hushspec.middleware import HushGuard


def map_openai_tool_call(
    function_name: str,
    function_args: str | dict,
) -> EvaluationAction:
    if isinstance(function_args, str):
        args_size = len(function_args)
        json.loads(function_args)
    else:
        args_size = len(json.dumps(function_args))

    return EvaluationAction(
        type="tool_call",
        target=function_name,
        args_size=args_size,
    )


def create_openai_guard(guard: HushGuard):

    def handler(
        function_name: str,
        function_args: str | dict,
    ) -> EvaluationResult:
        action = map_openai_tool_call(function_name, function_args)
        return guard.evaluate(action)

    return handler
