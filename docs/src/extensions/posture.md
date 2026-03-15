# Posture Extension

The full normative specification is at [`spec/hushspec-posture.md`](https://github.com/backbay-labs/hush/blob/main/spec/hushspec-posture.md).

## Overview

The Posture extension adds a declarative state machine for capability and budget management. An agent starts in an `initial` state and transitions between states based on triggers (violations, timeouts, approvals, budget exhaustion). Each state declares available capabilities and optional budget limits.

Posture is declared under `extensions.posture` in a HushSpec document.

## Key Concepts

- **States** define which capabilities are available and impose budget ceilings on operation counts.
- **Transitions** define how the agent moves between states, triggered by events like `critical_violation`, `timeout`, or `user_approval`.
- **Budgets** are hard limits on cumulative operations (e.g., max 100 file writes per session). When exhausted, the corresponding action type is denied.
- **Capabilities** narrow the set of permitted action types. If a state lists capabilities, only those action types are allowed.

## Example

A 3-state posture configuration: normal operation, restricted mode after a violation, and full lockdown on critical violations.

```yaml
extensions:
  posture:
    initial: "standard"
    states:
      standard:
        description: "Normal operating mode"
        capabilities:
          - file_access
          - file_write
          - egress
          - tool_call
        budgets:
          file_writes: 100
          egress_calls: 50
          tool_calls: 200
      restricted:
        description: "Limited mode after violation"
        capabilities:
          - file_access
          - tool_call
        budgets:
          tool_calls: 10
      locked:
        description: "No operations permitted"
        capabilities: []
    transitions:
      - from: "standard"
        to: "restricted"
        on: any_violation
      - from: "*"
        to: "locked"
        on: critical_violation
      - from: "restricted"
        to: "standard"
        on: user_approval
      - from: "standard"
        to: "restricted"
        on: timeout
        after: "1h"
      - from: "standard"
        to: "restricted"
        on: budget_exhausted
```

## Standard Capabilities

`file_access`, `file_write`, `egress`, `shell`, `tool_call`, `patch`, `custom`

## Standard Triggers

`user_approval`, `user_denial`, `critical_violation`, `any_violation`, `timeout`, `budget_exhausted`, `pattern_match`
