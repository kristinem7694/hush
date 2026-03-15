import { describe, it, expect } from 'vitest';
import { parse, parseOrThrow } from '../src/parse.js';
import { validate } from '../src/validate.js';
import { merge } from '../src/merge.js';

describe('posture extension', () => {
  it('parses valid posture', () => {
    const spec = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  posture:
    initial: standard
    states:
      restricted:
        capabilities: [file_access]
      standard:
        capabilities: [file_access, egress]
        budgets:
          file_writes: 50
      elevated:
        capabilities: [file_access, egress, shell]
    transitions:
      - from: restricted
        to: standard
        on: user_approval
      - from: "*"
        to: restricted
        on: critical_violation
      - from: elevated
        to: standard
        on: timeout
        after: "1h"
`);
    expect(spec.extensions?.posture?.initial).toBe('standard');
    expect(Object.keys(spec.extensions?.posture?.states ?? {})).toHaveLength(3);
    expect(spec.extensions?.posture?.transitions).toHaveLength(3);
    const result = validate(spec);
    expect(result.valid).toBe(true);
  });

  it('rejects invalid initial state', () => {
    const spec = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  posture:
    initial: nonexistent
    states:
      valid:
        capabilities: []
`);
    const result = validate(spec);
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('invalid_posture_initial');
  });

  it('rejects timeout without after', () => {
    const spec = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  posture:
    initial: a
    states:
      a:
        capabilities: []
      b:
        capabilities: []
    transitions:
      - from: a
        to: b
        on: timeout
`);
    const result = validate(spec);
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('missing_timeout_after');
  });
});

describe('origins extension', () => {
  it('parses valid origins', () => {
    const spec = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  origins:
    default_behavior: deny
    profiles:
      - id: incident-room
        match:
          provider: slack
          tags: [incident]
        posture: elevated
        budgets:
          tool_calls: 200
        explanation: Incident response
      - id: external
        match:
          visibility: external_shared
        data:
          redact_before_send: true
`);
    expect(spec.extensions?.origins?.profiles).toHaveLength(2);
    const result = validate(spec);
    expect(result.valid).toBe(true);
  });

  it('rejects duplicate profile ids', () => {
    const spec = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  origins:
    profiles:
      - id: dup
        match:
          provider: slack
      - id: dup
        match:
          provider: teams
`);
    const result = validate(spec);
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe('duplicate_origin_profile_id');
  });
});

describe('detection extension', () => {
  it('parses valid detection', () => {
    const spec = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  detection:
    prompt_injection:
      enabled: true
      warn_at_or_above: suspicious
      block_at_or_above: high
    jailbreak:
      block_threshold: 40
      warn_threshold: 15
    threat_intel:
      pattern_db: "builtin:s2bench-v1"
      similarity_threshold: 0.85
`);
    expect(spec.extensions?.detection?.prompt_injection?.enabled).toBe(true);
    const result = validate(spec);
    expect(result.valid).toBe(true);
  });

  it('warns on inverted thresholds', () => {
    const spec = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  detection:
    jailbreak:
      block_threshold: 10
      warn_threshold: 50
`);
    const result = validate(spec);
    expect(result.valid).toBe(true);
    expect(result.warnings.length).toBeGreaterThan(0);
  });

  it('rejects out-of-range similarity', () => {
    const spec = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  detection:
    threat_intel:
      similarity_threshold: 1.5
`);
    const result = validate(spec);
    expect(result.valid).toBe(false);
  });
});

describe('unknown extensions', () => {
  it('rejects unknown extension keys', () => {
    const result = parse(`
hushspec: "0.1.0"
extensions:
  unknown_ext:
    enabled: true
`);
    expect(result.ok).toBe(false);
  });
});

describe('extension merge', () => {
  it('child posture overrides base', () => {
    const base = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  posture:
    initial: a
    states:
      a:
        capabilities: [file_access]
`);
    const child = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  posture:
    initial: b
    states:
      b:
        capabilities: [egress]
`);
    const merged = merge(base, child);
    expect(merged.extensions?.posture?.initial).toBe('b');
  });

  it('merges origin profiles by id', () => {
    const base = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  origins:
    default_behavior: deny
    profiles:
      - id: existing
        explanation: base
`);
    const child = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  origins:
    profiles:
      - id: existing
        explanation: overridden
      - id: new-one
        explanation: appended
`);
    const merged = merge(base, child);
    expect(merged.extensions?.origins?.profiles).toHaveLength(2);
    const existing = merged.extensions?.origins?.profiles?.find(p => p.id === 'existing');
    expect(existing?.explanation).toBe('overridden');
  });

  it('base extensions preserved when child has none', () => {
    const base = parseOrThrow(`
hushspec: "0.1.0"
extensions:
  detection:
    jailbreak:
      block_threshold: 40
`);
    const child = parseOrThrow('hushspec: "0.1.0"\n');
    const merged = merge(base, child);
    expect(merged.extensions?.detection?.jailbreak?.block_threshold).toBe(40);
  });
});

describe('full document with rules + extensions', () => {
  it('parses and validates', () => {
    const spec = parseOrThrow(`
hushspec: "0.1.0"
name: complete
rules:
  egress:
    allow: ["api.openai.com"]
    default: block
extensions:
  posture:
    initial: std
    states:
      std:
        capabilities: [egress]
  detection:
    prompt_injection:
      block_at_or_above: high
`);
    const result = validate(spec);
    expect(result.valid).toBe(true);
    expect(spec.rules?.egress).toBeDefined();
    expect(spec.extensions?.posture).toBeDefined();
    expect(spec.extensions?.detection).toBeDefined();
  });
});
