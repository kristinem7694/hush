# Action Types

HushSpec defines a standard taxonomy of action types that rules evaluate against:

| Action Type | Description | Relevant Rules |
|-------------|-------------|----------------|
| `file_read` | Reading a file | `forbidden_paths`, `path_allowlist` |
| `file_write` | Writing a file | `forbidden_paths`, `path_allowlist`, `secret_patterns` |
| `egress` | Network egress request | `egress` |
| `shell_command` | Shell command execution | `shell_commands`, `forbidden_paths` |
| `tool_call` | Tool/MCP invocation | `tool_access` |
| `patch_apply` | Applying a patch/diff | `patch_integrity`, `forbidden_paths` |
| `computer_use` | CUA action | `computer_use`, `remote_desktop_channels`, `input_injection` |
| `input_inject` | Input injection | `input_injection` |
| `custom` | Custom action type | Engine-specific |

## Decision Types

Rules produce one of three decisions:

| Decision | Meaning |
|----------|---------|
| `allow` | Action is permitted |
| `warn` | Action is permitted but flagged (e.g., `require_confirmation`) |
| `deny` | Action is blocked |

When multiple rules evaluate the same action, the **most restrictive** decision wins: `deny` > `warn` > `allow`.
