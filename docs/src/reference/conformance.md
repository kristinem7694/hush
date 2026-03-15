# Conformance Levels

HushSpec defines four conformance levels. Each level subsumes all requirements of the levels below it.

## Level 0: Parser

A Level 0 implementation can:

- Parse valid HushSpec YAML documents into a structured representation
- Reject syntactically invalid YAML
- Reject documents missing the required `hushspec` field

This is the minimum bar for any tool that reads HushSpec documents.

## Level 1: Validator

A Level 1 implementation additionally:

- Validates all field types and constraints (booleans are booleans, integers are integers)
- Rejects documents with unknown fields at any nesting level
- Validates enum values (`severity`, `mode`, `default`, `merge_strategy`)
- Enforces uniqueness constraints (e.g., secret pattern `name` fields)
- Validates numeric constraints (non-negative integers, positive ratios)
- Validates regex syntax in pattern fields

This level is required for linters, schema validators, and policy authoring tools.

## Level 2: Merger

A Level 2 implementation additionally:

- Resolves `extends` references (via at least one resolution strategy: filesystem, URL, registry, or built-in)
- Correctly implements all three merge strategies (`deep_merge`, `merge`, `replace`)
- Detects and rejects circular inheritance

This level is required for any tool that supports policy composition.

## Level 3: Evaluator

A Level 3 implementation additionally:

- Accepts an action (type + context) and a resolved HushSpec document
- Produces a correct `allow`, `warn`, or `deny` decision per the rule semantics
- Implements decision precedence (`deny` > `warn` > `allow`)
- Passes the HushSpec conformance test vectors (published separately)

This is the full engine level. Clawdstrike is a Level 3 implementation.
