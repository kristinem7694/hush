# HushSpec Origins Extension Specification

**Version:** 0.1.0
**Status:** Draft
**Date:** 2026-03-15
**Companion to:** HushSpec Core v0.1.0

---

## 1. Overview

The Origins extension provides origin-aware policy projection. When an agent receives work from different sources -- Slack channels, GitHub repositories, email threads, Discord servers -- the origins extension allows different security profiles to apply based on the source context. Each origin profile can narrow base policy rules, set an initial posture state, impose budgets, and control cross-origin data flow.

Origins is declared under `extensions.origins` in a HushSpec document. When a conformant engine supports the origins extension, incoming requests MUST be matched against origin profiles before rule evaluation begins. The matched profile's constraints are applied as additional restrictions on top of the base policy.

### 1.1 Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

### 1.2 Design Principle

Origin profiles NARROW the base policy. They can only make the policy more restrictive, never more permissive. This ensures that the base policy remains the security floor.

---

## 2. Schema

The origins extension is declared under `extensions.origins`:

```yaml
extensions:
  origins:
    default_behavior: <"deny"|"minimal_profile">  # OPTIONAL. Default: "deny".
    profiles:
      - id: <string>                     # REQUIRED. Unique profile identifier.
        match:                           # OPTIONAL. Matching criteria.
          provider: <provider>           # OPTIONAL. Source provider.
          tenant_id: <string>            # OPTIONAL. Tenant/workspace ID.
          space_id: <string>             # OPTIONAL. Channel/room/repo ID.
          space_type: <space_type>       # OPTIONAL. Type of space.
          visibility: <visibility>       # OPTIONAL. Visibility level.
          external_participants: <bool>  # OPTIONAL. External users present.
          tags: [<string>...]            # OPTIONAL. All must match (AND).
          sensitivity: <string>          # OPTIONAL. Sensitivity classification.
          actor_role: <string>           # OPTIONAL. Role of the requesting actor.
        posture: <state_name>            # OPTIONAL. Initial posture state.
        tool_access:                     # OPTIONAL. Tool access overrides.
          allow: [<string>...]
          block: [<string>...]
          require_confirmation: [<string>...]
          default: <"allow"|"block">
          max_args_size: <integer>
        egress:                          # OPTIONAL. Egress overrides.
          allow: [<string>...]
          block: [<string>...]
          default: <"allow"|"block">
        data:                            # OPTIONAL. Data handling controls.
          allow_external_sharing: <bool>
          redact_before_send: <bool>
          block_sensitive_outputs: <bool>
        budgets:                         # OPTIONAL. Budget overrides.
          tool_calls: <integer>
          egress_calls: <integer>
          shell_commands: <integer>
        bridge:                          # OPTIONAL. Cross-origin controls.
          allow_cross_origin: <bool>
          allowed_targets:
            - provider: <provider>
              space_type: <space_type>
              tags: [<string>...]
              visibility: <visibility>
          require_approval: <bool>
        explanation: <string>            # OPTIONAL. Why this profile exists.
```

### 2.1 `default_behavior`

The `default_behavior` field controls what happens when no profile matches an incoming request. It MUST be one of:

- **`"deny"`** (default): Requests from unmatched origins are denied entirely. This is the fail-closed default.
- **`"minimal_profile"`**: Requests from unmatched origins proceed under the base policy with no origin-specific extensions. Engines SHOULD log a warning when this fallback activates.

### 2.2 `profiles`

The `profiles` field is an array of origin profile objects, each with a unique `id`. Profiles are evaluated in match priority order (see Section 3), not array order.

---

## 3. Match Priority

When an incoming request carries origin context, the engine MUST determine which profile applies using the following deterministic priority order:

1. **Exact `space_id` match (highest priority).** If a profile's `match.space_id` equals the request's space ID, that profile is selected. If multiple profiles match by `space_id`, the first in document order wins.

2. **Most specific match by field count.** Among profiles without `space_id` or whose `space_id` does not match, the profile with the greatest number of matching `match` fields is selected. Each non-null `match` field that equals the corresponding request field counts as one match point. `tags` counts as one match point only if ALL tags in the profile are present in the request.

3. **Provider-only match.** A profile matching only on `provider` is less specific than one matching `provider` + `space_type`.

4. **Default profile (empty match).** A profile with an empty or absent `match` object matches all requests at the lowest specificity. At most one default profile SHOULD exist.

5. **`default_behavior` fallback.** If no profile matches at all, the `default_behavior` field applies.

In case of a tie in match specificity (same number of matching fields, no `space_id` match), the first profile in document order wins.

---

## 4. Composition Semantics

Origin profiles NARROW the base policy. The most restrictive rule wins at every level.

### 4.1 Tool Access Composition

- **Allowlists:** The effective allowlist is the INTERSECTION of the base `rules.tool_access.allow` and the origin profile's `tool_access.allow`. A tool must appear in both to be allowed.
- **Blocklists:** The effective blocklist is the UNION of the base `rules.tool_access.block` and the origin profile's `tool_access.block`. A tool blocked by either is blocked.
- **Require confirmation:** The effective set is the UNION of both `require_confirmation` lists.
- **Default:** If either the base or origin specifies `"block"`, the effective default is `"block"`.
- **Max args size:** The smaller of the two values applies, if both are specified.

### 4.2 Egress Composition

- **Allowlists:** The effective allowlist is the INTERSECTION of the base `rules.egress.allow` and the origin profile's `egress.allow`.
- **Blocklists:** The effective blocklist is the UNION of the base `rules.egress.block` and the origin profile's `egress.block`.
- **Default:** If either specifies `"block"`, the effective default is `"block"`.

### 4.3 Budget Composition

When both the base posture and the origin profile specify budgets for the same key, the smaller value applies. Origin budgets cannot increase base budgets.

### 4.4 Posture Composition

If an origin profile specifies a `posture` state, it overrides the base posture `initial` state for requests from that origin. The referenced state MUST exist in the posture extension's `states` map.

---

## 5. Providers

### 5.1 Standard Providers

| Provider   | Description                               |
|------------|-------------------------------------------|
| `slack`    | Slack workspace.                          |
| `teams`    | Microsoft Teams.                          |
| `github`   | GitHub (issues, PRs, discussions).        |
| `jira`     | Atlassian Jira.                           |
| `email`    | Email (any provider).                     |
| `discord`  | Discord server.                           |
| `webhook`  | Generic webhook source.                   |
| `custom`   | Engine-defined provider.                  |

Engines MAY support additional providers as strings. Unknown providers SHOULD NOT cause document rejection.

### 5.2 Space Types

| Space Type       | Description                          |
|------------------|--------------------------------------|
| `channel`        | Chat channel (Slack, Teams, Discord).|
| `group`          | Group chat or group DM.             |
| `dm`             | Direct message.                      |
| `thread`         | Threaded conversation.               |
| `issue`          | Issue tracker entry.                 |
| `ticket`         | Support/service ticket.              |
| `pull_request`   | Pull/merge request.                  |
| `email_thread`   | Email conversation thread.           |

### 5.3 Visibility Levels

| Visibility         | Description                                    |
|--------------------|------------------------------------------------|
| `private`          | Visible only to invited members.               |
| `internal`         | Visible within the organization.               |
| `public`           | Visible to anyone.                             |
| `external_shared`  | Shared channel with external participants.     |

---

## 6. Data Policy

The `data` object controls how content is handled when flowing through or out of the origin context.

| Field                     | Type    | Default | Description                                                |
|---------------------------|---------|---------|------------------------------------------------------------|
| `allow_external_sharing`  | boolean | `false` | Whether content may be shared outside the origin context.  |
| `redact_before_send`      | boolean | `false` | Whether sensitive content must be redacted before output.  |
| `block_sensitive_outputs` | boolean | `false` | Whether outputs containing sensitive patterns are blocked. |

Data policy fields default to `false` (restrictive). The detection of "sensitive content" for `redact_before_send` and `block_sensitive_outputs` is governed by the core `rules.secret_patterns` configuration and any active detection extension. Engines MUST document their redaction strategy.

---

## 7. Bridge Policy

The `bridge` object controls whether and how data may flow between origin contexts.

| Field              | Type                  | Default | Description                                      |
|--------------------|-----------------------|---------|--------------------------------------------------|
| `allow_cross_origin` | boolean             | `false` | Whether cross-origin data flow is permitted.     |
| `allowed_targets`  | array of BridgeTarget | `[]`    | Specific targets permitted for cross-origin flow.|
| `require_approval` | boolean               | `false` | Whether cross-origin flow requires approval.     |

### 7.1 Bridge Target

Each entry in `allowed_targets` specifies a permitted destination:

| Field        | Type            | Required | Description                             |
|--------------|-----------------|----------|-----------------------------------------|
| `provider`   | string          | OPTIONAL | Target provider.                        |
| `space_type` | string          | OPTIONAL | Target space type.                      |
| `tags`       | array of string | OPTIONAL | Required tags on the target (AND).      |
| `visibility` | string          | OPTIONAL | Required visibility level of the target.|

A bridge target matches if all specified fields match. Absent fields are wildcards.

### 7.2 Bridge Semantics

When `allow_cross_origin` is `false`, no data from this origin context may flow to another origin context. When `true`, data may flow only to destinations matching an entry in `allowed_targets`. If `allowed_targets` is empty and `allow_cross_origin` is `true`, data may flow to any origin (no target restriction). If `require_approval` is `true`, all cross-origin flows require user/operator approval before proceeding.

---

## 8. Validation Requirements

Conformant validators MUST enforce the following:

1. **Profile ID uniqueness.** All `id` values within `profiles` MUST be unique. Duplicate IDs MUST cause document rejection.

2. **Default behavior enum.** `default_behavior` MUST be one of `"deny"` or `"minimal_profile"`. Invalid values MUST cause document rejection.

3. **Provider enum.** Provider values SHOULD be one of the standard providers. Unknown providers SHOULD produce warnings but MUST NOT cause document rejection.

4. **Posture state reference.** If a profile specifies a `posture` state, that state MUST exist in `extensions.posture.states`. If the posture extension is absent, profiles MUST NOT specify `posture`.

5. **Budget values.** Budget values MUST be non-negative integers. Negative values MUST cause document rejection.

6. **Unknown fields.** Unknown fields within origin profile objects, match objects, data objects, and bridge objects MUST cause document rejection.

7. **Tags type.** The `tags` field MUST be an array of strings. Empty arrays are valid.

---

## 9. Merge Semantics

When a child document extends a base document that contains origins configuration, the following merge rules apply under `deep_merge` strategy:

### 9.1 Profiles

Child profiles override base profiles by `id`. If a child defines a profile with the same `id` as a base profile, the child's profile entirely replaces the base's profile. New child profiles (with IDs not present in the base) are appended. Base profiles whose IDs are not present in the child are preserved.

### 9.2 Default Behavior

If the child defines `default_behavior`, it overrides the base's value. If the child does not define it, the base's value is preserved.

### 9.3 Replace and Merge Strategies

Under `replace` strategy, the child's origins object entirely replaces the base's. Under `merge` strategy, the child's origins object entirely replaces the base's (since origins is a single block under extensions).

---

## Appendix A. Example

```yaml
hushspec: "0.1.0"
name: "origin-aware-policy"

rules:
  tool_access:
    enabled: true
    allow:
      - "read_file"
      - "write_file"
      - "search"
      - "deploy"
    default: "block"

  egress:
    enabled: true
    allow:
      - "api.openai.com"
      - "**.googleapis.com"
    default: "block"

extensions:
  posture:
    initial: "standard"
    states:
      standard:
        capabilities: [file_access, file_write, egress, tool_call]
        budgets:
          tool_calls: 200
      restricted:
        capabilities: [file_access, tool_call]
        budgets:
          tool_calls: 20

  origins:
    default_behavior: "deny"
    profiles:
      - id: "eng-private"
        match:
          provider: slack
          space_type: channel
          visibility: private
          tags: ["engineering"]
        posture: "standard"
        tool_access:
          allow: ["read_file", "write_file", "search", "deploy"]
        egress:
          allow: ["api.openai.com", "**.googleapis.com"]
        data:
          allow_external_sharing: false
          redact_before_send: false
        bridge:
          allow_cross_origin: true
          allowed_targets:
            - provider: github
              space_type: pull_request
          require_approval: false
        explanation: "Full access for private engineering channels"

      - id: "shared-channel"
        match:
          provider: slack
          external_participants: true
        posture: "restricted"
        tool_access:
          allow: ["read_file", "search"]
          block: ["deploy"]
        egress:
          allow: ["api.openai.com"]
        data:
          allow_external_sharing: false
          redact_before_send: true
          block_sensitive_outputs: true
        budgets:
          tool_calls: 20
          egress_calls: 10
        bridge:
          allow_cross_origin: false
        explanation: "Restricted access for shared channels with external participants"

      - id: "github-pr"
        match:
          provider: github
          space_type: pull_request
        posture: "standard"
        tool_access:
          allow: ["read_file", "write_file", "search"]
        data:
          allow_external_sharing: false
        explanation: "Code review context, no deploy"
```
