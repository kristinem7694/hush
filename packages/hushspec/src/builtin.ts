import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import type { HushSpec } from './schema.js';

export const BUILTIN_NAMES = [
  'default',
  'strict',
  'permissive',
  'ai-agent',
  'cicd',
  'remote-desktop',
] as const;

export type BuiltinName = (typeof BUILTIN_NAMES)[number];

function findRulesetsDir(): string | null {
  let dir = process.cwd();
  for (let i = 0; i < 10; i++) {
    const candidate = path.join(dir, 'rulesets');
    if (existsSync(path.join(candidate, 'default.yaml'))) {
      return candidate;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }

  return null;
}

let _rulesetsDir: string | null | undefined;

function getRulesetsDir(): string | null {
  if (_rulesetsDir === undefined) {
    _rulesetsDir = findRulesetsDir();
  }
  return _rulesetsDir;
}

/**
 * Parsed directly with YAML.parse (no regex validation) because builtins
 * may contain RE2/PCRE patterns like `(?i)` that aren't valid JS regex.
 */
export function loadBuiltin(name: string): HushSpec | null {
  const resolved = name.startsWith('builtin:') ? name.slice(8) : name;

  if (!(BUILTIN_NAMES as readonly string[]).includes(resolved)) {
    return null;
  }

  const rulesetsDir = getRulesetsDir();
  if (!rulesetsDir) {
    return null;
  }

  const filePath = path.join(rulesetsDir, `${resolved}.yaml`);
  let content: string;
  try {
    content = readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }

  try {
    const doc = YAML.parse(content) as HushSpec;
    if (!doc || typeof doc !== 'object' || !doc.hushspec) {
      return null;
    }
    return doc;
  } catch {
    return null;
  }
}
