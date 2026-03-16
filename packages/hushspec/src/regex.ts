/**
 * Pattern that detects regex features outside the RE2 subset.
 *
 * HushSpec requires all regex patterns to be RE2-compatible to prevent ReDoS
 * attacks. JavaScript's RegExp uses a backtracking engine that is vulnerable
 * to catastrophic backtracking with certain pattern constructs. By restricting
 * patterns to the RE2 subset, we ensure safe O(mn) evaluation across all SDKs.
 *
 * Disallowed features:
 * - Backreferences: \1, \2, ..., \k<name>
 * - Lookahead: (?=...), (?!...)
 * - Lookbehind: (?<=...), (?<!...)
 * - Atomic groups: (?>...)
 * - Possessive quantifiers: *+, ++, ?+
 * - Conditional patterns: (?(...)...|...)
 * - Recursive patterns: (?R), (?1), (?2), ...
 * - Named backreferences: (?P=name)
 * - Subroutine calls: \g<name>
 */
const RE2_DISALLOWED = /\\[1-9]|\\k<|\(\?[=!]|\(\?<[=!]|\(\?>|\*\+|\+\+|\?\+|\(\?\(|\(\?R\)|\(\?\d+\)|\(\?P=|\\g</;
const LEADING_INLINE_FLAGS = /^\(\?([ims]+)\)/;
const PYTHON_NAMED_GROUP = /\(\?P<([A-Za-z_][A-Za-z0-9_]*)>/g;

export interface CompiledPolicyRegex {
  source: string;
  flags: string;
  regex: RegExp;
}

export function isSafeRegex(pattern: string): boolean {
  return !RE2_DISALLOWED.test(pattern);
}

export function compilePolicyRegex(pattern: string): CompiledPolicyRegex {
  const normalized = normalizePolicyRegex(pattern);
  return {
    ...normalized,
    regex: new RegExp(normalized.source, normalized.flags),
  };
}

export function compileSafePolicyRegex(pattern: string): CompiledPolicyRegex {
  if (!isSafeRegex(pattern)) {
    throw new Error('pattern uses features not in the RE2 subset');
  }
  return compilePolicyRegex(pattern);
}

function normalizePolicyRegex(pattern: string): { source: string; flags: string } {
  let source = pattern;
  let flags = '';

  while (true) {
    const match = source.match(LEADING_INLINE_FLAGS);
    if (match == null) {
      break;
    }

    for (const flag of match[1]) {
      if (!flags.includes(flag)) {
        flags += flag;
      }
    }

    source = source.slice(match[0].length);
  }

  source = source.replace(PYTHON_NAMED_GROUP, '(?<$1>');
  return { source, flags };
}
