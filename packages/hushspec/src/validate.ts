import type { HushSpec } from './schema.js';
import { isSupported } from './version.js';

/** A single validation error with a machine-readable code. */
export interface ValidationError {
  code: string;
  message: string;
}

/** Outcome of validating a HushSpec document. */
export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  warnings: string[];
}

/**
 * Validate a parsed HushSpec document for structural correctness.
 *
 * Checks version support, duplicate pattern names, and extension
 * constraints. Returns errors and warnings.
 */
export function validate(spec: HushSpec): ValidationResult {
  const errors: ValidationError[] = [];
  const warnings: string[] = [];

  // Version check
  if (!isSupported(spec.hushspec)) {
    errors.push({
      code: 'unsupported_version',
      message: `unsupported hushspec version: ${spec.hushspec}`,
    });
  }

  // Rules validation
  if (spec.rules) {
    // Secret pattern name uniqueness
    if (spec.rules.secret_patterns?.patterns) {
      const seen = new Set<string>();
      for (const p of spec.rules.secret_patterns.patterns) {
        if (seen.has(p.name)) {
          errors.push({
            code: 'duplicate_pattern_name',
            message: `duplicate secret pattern name: ${p.name}`,
          });
        }
        seen.add(p.name);
      }
    }

    // Check if any rules are configured
    const ruleKeys = Object.keys(spec.rules);
    if (ruleKeys.length === 0) {
      warnings.push('no rules configured');
    }
  } else {
    warnings.push('no rules section present');
  }

  // Extensions validation
  if (spec.extensions) {
    // Posture validation
    if (spec.extensions.posture) {
      const posture = spec.extensions.posture;
      const stateNames = new Set(Object.keys(posture.states ?? {}));

      if (!stateNames.has(posture.initial)) {
        errors.push({
          code: 'invalid_posture_initial',
          message: `posture.initial '${posture.initial}' does not reference a defined state`,
        });
      }

      for (const [i, t] of (posture.transitions ?? []).entries()) {
        if (t.from !== '*' && !stateNames.has(t.from)) {
          errors.push({
            code: 'invalid_transition_from',
            message: `posture.transitions[${i}].from '${t.from}' does not reference a defined state`,
          });
        }
        if (!stateNames.has(t.to)) {
          errors.push({
            code: 'invalid_transition_to',
            message: `posture.transitions[${i}].to '${t.to}' does not reference a defined state`,
          });
        }
        if (t.to === '*') {
          errors.push({
            code: 'invalid_transition_to',
            message: `posture.transitions[${i}].to cannot be '*'`,
          });
        }
        if (t.on === 'timeout' && !t.after) {
          errors.push({
            code: 'missing_timeout_after',
            message: `posture.transitions[${i}]: timeout trigger requires 'after' field`,
          });
        }
      }

      // Validate budgets are non-negative
      for (const [stateName, state] of Object.entries(posture.states ?? {})) {
        for (const [key, value] of Object.entries(state.budgets ?? {})) {
          if (value < 0) {
            errors.push({
              code: 'negative_budget',
              message: `posture.states.${stateName}.budgets.${key} must be non-negative, got ${value}`,
            });
          }
        }
      }
    }

    // Origins validation
    if (spec.extensions.origins?.profiles) {
      const seenIds = new Set<string>();
      for (const profile of spec.extensions.origins.profiles) {
        if (seenIds.has(profile.id)) {
          errors.push({
            code: 'duplicate_origin_profile_id',
            message: `duplicate origin profile id: '${profile.id}'`,
          });
        }
        seenIds.add(profile.id);
      }
    }

    // Detection validation
    if (spec.extensions.detection) {
      const det = spec.extensions.detection;
      if (det.prompt_injection) {
        const levels: Record<string, number> = { safe: 0, suspicious: 1, high: 2, critical: 3 };
        const warnLevel = levels[det.prompt_injection.warn_at_or_above ?? 'suspicious'] ?? 1;
        const blockLevel = levels[det.prompt_injection.block_at_or_above ?? 'high'] ?? 2;
        if (blockLevel < warnLevel) {
          warnings.push('detection.prompt_injection: block_at_or_above is less strict than warn_at_or_above');
        }
      }
      if (det.jailbreak) {
        const blockT = det.jailbreak.block_threshold ?? 70;
        const warnT = det.jailbreak.warn_threshold ?? 30;
        if (blockT < warnT) {
          warnings.push('detection.jailbreak: block_threshold is lower than warn_threshold');
        }
      }
      if (det.threat_intel) {
        const sim = det.threat_intel.similarity_threshold ?? 0.85;
        if (sim < 0 || sim > 1) {
          errors.push({
            code: 'invalid_similarity_threshold',
            message: 'detection.threat_intel.similarity_threshold must be between 0.0 and 1.0',
          });
        }
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}
