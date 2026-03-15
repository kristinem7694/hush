# Origins Extension

The full normative specification is at [`spec/hushspec-origins.md`](https://github.com/backbay-labs/hush/blob/main/spec/hushspec-origins.md).

## Overview

The Origins extension provides origin-aware policy projection. When an agent receives work from different sources -- Slack channels, GitHub repositories, email threads, Discord servers -- different security profiles can apply based on the source context.

Origin profiles **narrow** the base policy. They can only make rules more restrictive, never more permissive. The base policy remains the security floor.

Origins is declared under `extensions.origins` in a HushSpec document.

## Key Concepts

- **Profiles** match incoming requests by provider, space type, visibility, tags, and other criteria.
- **Match priority** is deterministic: exact `space_id` match wins first, then most specific match by field count, then provider-only, then default profile, then `default_behavior` fallback.
- **Composition** uses intersection for allowlists and union for blocklists, ensuring the most restrictive rule always wins.
- **Bridge policy** controls cross-origin data flow between contexts.
- **Data policy** controls external sharing, redaction, and sensitive output blocking.

## Example

```yaml
extensions:
  origins:
    default_behavior: "deny"
    profiles:
      - id: "eng-private"
        match:
          provider: slack
          space_type: channel
          visibility: private
          tags: ["engineering"]
        tool_access:
          allow: ["read_file", "write_file", "search"]
        data:
          allow_external_sharing: false
        bridge:
          allow_cross_origin: true
          allowed_targets:
            - provider: github
              space_type: pull_request
          require_approval: false
        explanation: "Full access for private engineering channels"

      - id: "shared-external"
        match:
          provider: slack
          external_participants: true
        tool_access:
          allow: ["read_file", "search"]
          block: ["deploy"]
        data:
          redact_before_send: true
          block_sensitive_outputs: true
        bridge:
          allow_cross_origin: false
        explanation: "Restricted access for shared channels"
```

## Standard Providers

`slack`, `teams`, `github`, `jira`, `email`, `discord`, `webhook`, `custom`

## Composition Rules

- **Allowlists**: intersection of base and origin profile (tool must appear in both)
- **Blocklists**: union of base and origin profile (blocked by either means blocked)
- **Defaults**: if either specifies `"block"`, the effective default is `"block"`
- **Budgets**: the smaller value wins
