import YAML from 'yaml';
import type { HushSpec } from './schema.js';
import { validateForParse } from './validate.js';

export type ParseResult =
  | { ok: true; value: HushSpec }
  | { ok: false; error: string };

export function parse(yaml: string): ParseResult {
  let doc: unknown;
  try {
    doc = YAML.parse(yaml);
  } catch (error) {
    return {
      ok: false,
      error: `YAML parse error: ${error instanceof Error ? error.message : String(error)}`,
    };
  }

  const result = validateForParse(doc);
  if (!result.valid) {
    return {
      ok: false,
      error: result.errors[0]?.message ?? 'invalid HushSpec document',
    };
  }

  return { ok: true, value: doc as HushSpec };
}

/** Throwing variant of `parse()`. */
export function parseOrThrow(yaml: string): HushSpec {
  const result = parse(yaml);
  if (!result.ok) {
    throw new Error(result.error);
  }
  return result.value;
}
