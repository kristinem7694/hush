from __future__ import annotations

import json
from typing import Optional
from urllib.parse import urlparse

from hushspec.evaluate import EvaluationAction, EvaluationResult
from hushspec.middleware import HushGuard


def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.hostname or url
    except Exception:
        return url


def map_mcp_tool_call(
    tool_name: str,
    args: Optional[dict] = None,
) -> EvaluationAction:
    args = args or {}

    mappings = {
        "read_file": lambda a: EvaluationAction(
            type="file_read",
            target=a.get("path", ""),
        ),
        "write_file": lambda a: EvaluationAction(
            type="file_write",
            target=a.get("path", ""),
            content=a.get("content"),
        ),
        "list_directory": lambda a: EvaluationAction(
            type="file_read",
            target=a.get("path", ""),
        ),
        "run_command": lambda a: EvaluationAction(
            type="shell_command",
            target=a.get("command", ""),
        ),
        "execute": lambda a: EvaluationAction(
            type="shell_command",
            target=a.get("command", ""),
        ),
        "fetch": lambda a: EvaluationAction(
            type="egress",
            target=extract_domain(a.get("url", "")),
        ),
        "http_request": lambda a: EvaluationAction(
            type="egress",
            target=extract_domain(a.get("url", "")),
        ),
    }

    mapper = mappings.get(tool_name)
    if mapper is not None:
        return mapper(args)

    return EvaluationAction(
        type="tool_call",
        target=tool_name,
        args_size=len(json.dumps(args)) if args else None,
    )


def create_mcp_guard(guard: HushGuard):

    def handler(
        tool_name: str,
        args: Optional[dict] = None,
    ) -> EvaluationResult:
        action = map_mcp_tool_call(tool_name, args)
        return guard.evaluate(action)

    return handler
