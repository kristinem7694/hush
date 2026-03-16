import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseOrThrow } from '../src/parse.js';
import { resolve, resolveFromFile, createCompositeLoader } from '../src/resolve.js';
import { loadBuiltin, BUILTIN_NAMES } from '../src/builtin.js';

describe('resolve', () => {
  it('resolves extends chains from the filesystem', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'hushspec-resolve-'));
    writeFileSync(
      path.join(dir, 'base.yaml'),
      `
hushspec: "0.1.0"
name: base
rules:
  tool_access:
    allow: [read_file]
    default: block
`,
    );
    writeFileSync(
      path.join(dir, 'child.yaml'),
      `
hushspec: "0.1.0"
extends: base.yaml
name: child
rules:
  egress:
    allow: [api.example.com]
    default: allow
`,
    );

    const result = resolveFromFile(path.join(dir, 'child.yaml'));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.extends).toBeUndefined();
      expect(result.value.name).toBe('child');
      expect(result.value.rules?.tool_access?.allow).toEqual(['read_file']);
      expect(result.value.rules?.tool_access?.default).toBe('block');
      expect(result.value.rules?.egress?.allow).toEqual(['api.example.com']);
      expect(result.value.rules?.egress?.default).toBe('allow');
    }

    rmSync(dir, { recursive: true, force: true });
  });

  it('detects circular extends chains', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'hushspec-cycle-'));
    writeFileSync(
      path.join(dir, 'a.yaml'),
      `
hushspec: "0.1.0"
extends: b.yaml
`,
    );
    writeFileSync(
      path.join(dir, 'b.yaml'),
      `
hushspec: "0.1.0"
extends: a.yaml
`,
    );

    const result = resolveFromFile(path.join(dir, 'a.yaml'));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('circular extends detected');
    }

    rmSync(dir, { recursive: true, force: true });
  });

  it('supports custom loaders with canonical source ids', () => {
    const child = parseOrThrow(`
hushspec: "0.1.0"
extends: parent
rules:
  egress:
    allow: [api.example.com]
    default: block
`);

    const result = resolve(child, {
      source: 'memory://child',
      load(reference) {
        expect(reference).toBe('parent');
        return {
          source: 'memory://parent',
          spec: parseOrThrow(`
hushspec: "0.1.0"
name: parent
`),
        };
      },
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.extends).toBeUndefined();
      expect(result.value.name).toBe('parent');
    }
  });
});

describe('builtin loader', () => {
  it('resolves all 6 built-in rulesets', () => {
    for (const name of BUILTIN_NAMES) {
      const spec = loadBuiltin(name);
      expect(spec).not.toBeNull();
      expect(spec!.name).toBe(name);
      expect(spec!.hushspec).toBe('0.1.0');
    }
  });

  it('resolves with builtin: prefix', () => {
    for (const name of BUILTIN_NAMES) {
      const spec = loadBuiltin(`builtin:${name}`);
      expect(spec).not.toBeNull();
      expect(spec!.name).toBe(name);
    }
  });

  it('returns null for unknown builtins', () => {
    expect(loadBuiltin('nonexistent')).toBeNull();
    expect(loadBuiltin('builtin:nonexistent')).toBeNull();
  });
});

describe('extends: builtin', () => {
  it('extends builtin:default end-to-end', () => {
    const child = parseOrThrow(`
hushspec: "0.1.0"
extends: builtin:default
name: my-custom-policy
rules:
  egress:
    allow: [custom.example.com]
    default: allow
`);

    const result = resolve(child, { source: 'memory://child' });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.extends).toBeUndefined();
      expect(result.value.name).toBe('my-custom-policy');
      expect(result.value.rules?.forbidden_paths).toBeDefined();
      expect(result.value.rules?.secret_patterns).toBeDefined();
      expect(result.value.rules?.tool_access).toBeDefined();
      expect(result.value.rules?.egress?.allow).toContain('custom.example.com');
      expect(result.value.rules?.egress?.default).toBe('allow');
    }
  });

  it('extends builtin:strict end-to-end', () => {
    const child = parseOrThrow(`
hushspec: "0.1.0"
extends: builtin:strict
name: custom-strict
`);

    const result = resolve(child, { source: 'memory://child' });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.name).toBe('custom-strict');
      expect(result.value.rules?.tool_access?.default).toBe('block');
    }
  });

  it('composite loader rejects HTTP URLs', () => {
    const loader = createCompositeLoader();
    expect(() => loader('https://example.com/policy.yaml')).toThrow('HTTP-based policy loading');
    expect(() => loader('http://example.com/policy.yaml')).toThrow('HTTP-based policy loading');
  });
});
