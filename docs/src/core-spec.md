# HushSpec Core Specification

The full normative specification is at [`spec/hushspec-core.md`](https://github.com/backbay-labs/hush/blob/main/spec/hushspec-core.md).

## Document Structure

A HushSpec document is a YAML file with these top-level fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `hushspec` | string | Yes | Spec version (e.g., `"0.1.0"`) |
| `name` | string | No | Human-readable policy name |
| `description` | string | No | Policy description |
| `extends` | string | No | Base policy reference |
| `merge_strategy` | string | No | `replace`, `merge`, or `deep_merge` (default) |
| `rules` | object | No | Security rule declarations |
| `extensions` | object | No | Optional extension modules |

## Validation Rules

- The `hushspec` field **MUST** be present
- Unknown fields **MUST** be rejected (fail-closed)
- All string patterns in `forbidden_paths`, `egress`, etc. use glob syntax
- All patterns in `secret_patterns`, `patch_integrity`, `shell_commands` use regex syntax
- Secret pattern `name` fields **MUST** be unique within the array

## 10 Core Rules

1. **forbidden_paths** — Block access to sensitive filesystem paths
2. **path_allowlist** — Allowlist-based path access control
3. **egress** — Network egress control by domain
4. **secret_patterns** — Detect secrets in content
5. **patch_integrity** — Validate patch/diff safety
6. **shell_commands** — Block dangerous shell commands
7. **tool_access** — Control tool/MCP invocations
8. **computer_use** — Control computer use agent actions
9. **remote_desktop_channels** — Control remote desktop side channels
10. **input_injection** — Control input injection capabilities

See the [Rules Reference](rules-reference.md) for detailed field documentation.
