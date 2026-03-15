import YAML from 'yaml';
import type { HushSpec } from './schema.js';

const KNOWN_TOP_LEVEL_KEYS = new Set([
  'hushspec', 'name', 'description', 'extends', 'merge_strategy', 'rules', 'extensions',
]);

const KNOWN_RULE_KEYS = new Set([
  'forbidden_paths', 'path_allowlist', 'egress', 'secret_patterns',
  'patch_integrity', 'shell_commands', 'tool_access', 'computer_use',
  'remote_desktop_channels', 'input_injection',
]);

const KNOWN_EXTENSION_KEYS = new Set([
  'posture', 'origins', 'detection',
]);

/** Result of parsing a YAML string into a HushSpec document. */
export type ParseResult =
  | { ok: true; value: HushSpec }
  | { ok: false; error: string };

/**
 * Parse a YAML string into a HushSpec document.
 *
 * Returns an ok/error result. Rejects unknown top-level fields
 * and unknown rules (fail-closed).
 */
export function parse(yaml: string): ParseResult {
  let doc: unknown;
  try {
    doc = YAML.parse(yaml);
  } catch (e) {
    return { ok: false, error: `YAML parse error: ${e instanceof Error ? e.message : String(e)}` };
  }

  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    return { ok: false, error: 'HushSpec document must be a YAML mapping' };
  }

  const obj = doc as Record<string, unknown>;

  // Check for unknown top-level fields
  for (const key of Object.keys(obj)) {
    if (!KNOWN_TOP_LEVEL_KEYS.has(key)) {
      return { ok: false, error: `unknown top-level field: ${key}` };
    }
  }

  // Check hushspec field is present
  if (!('hushspec' in obj) || typeof obj.hushspec !== 'string') {
    return { ok: false, error: 'missing or invalid "hushspec" version field' };
  }

  // Check for unknown rule keys
  if (obj.rules && typeof obj.rules === 'object' && !Array.isArray(obj.rules)) {
    for (const key of Object.keys(obj.rules as Record<string, unknown>)) {
      if (!KNOWN_RULE_KEYS.has(key)) {
        return { ok: false, error: `unknown rule: ${key}` };
      }
    }
  }

  // Check for unknown extension keys
  if (obj.extensions && typeof obj.extensions === 'object' && !Array.isArray(obj.extensions)) {
    for (const key of Object.keys(obj.extensions as Record<string, unknown>)) {
      if (!KNOWN_EXTENSION_KEYS.has(key)) {
        return { ok: false, error: `unknown extension: ${key}` };
      }
    }
  }

  return { ok: true, value: obj as unknown as HushSpec };
}

/**
 * Parse a YAML string into a HushSpec document, throwing on failure.
 *
 * @throws {Error} If the document is invalid or contains unknown fields.
 */
export function parseOrThrow(yaml: string): HushSpec {
  const result = parse(yaml);
  if (!result.ok) {
    throw new Error(result.error);
  }
  return result.value;
}
