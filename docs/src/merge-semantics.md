# Merge Semantics

HushSpec supports policy inheritance via the `extends` field. When a child policy extends a base, the `merge_strategy` controls how they combine.

## Strategies

### `deep_merge` (default)

Child rules override base rules at the individual rule level. If the child defines `rules.egress`, it replaces the base's `rules.egress` entirely. Rules not defined in the child are preserved from the base.

### `merge`

Same behavior as `deep_merge` in HushSpec v0. (The distinction will matter when extensions add nested merge semantics.)

### `replace`

The child document entirely replaces the base. No fields from the base are preserved.

## Example

```yaml
# base.yaml
hushspec: "0.1.0"
name: base
rules:
  egress:
    allow: ["a.com"]
    default: block
  forbidden_paths:
    patterns: ["**/.ssh/**"]
```

```yaml
# child.yaml
hushspec: "0.1.0"
name: child
extends: base.yaml
rules:
  egress:
    allow: ["b.com"]
    default: allow
```

Result: `egress` uses child's config (`b.com`, allow). `forbidden_paths` preserved from base.

## Note on Merge Helpers

HushSpec does **not** support `additional_*` or `remove_*` fields. These are engine-specific features. If you need additive pattern management, use your engine's native format.
