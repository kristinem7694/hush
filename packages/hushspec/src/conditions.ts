import type { HushSpec } from './schema.js';
import type { EvaluationAction, EvaluationResult } from './evaluate.js';
import { evaluate } from './evaluate.js';

const MAX_NESTING_DEPTH = 8;

export interface TimeWindowCondition {
  start: string;
  end: string;
  timezone?: string;
  days?: string[];
}

/** Multiple fields are ANDed; all present fields must evaluate to true. */
export interface Condition {
  time_window?: TimeWindowCondition;
  context?: Record<string, unknown>;
  all_of?: Condition[];
  any_of?: Condition[];
  not?: Condition;
}

export interface RuntimeContext {
  user?: Record<string, unknown>;
  environment?: string;
  deployment?: Record<string, unknown>;
  agent?: Record<string, unknown>;
  session?: Record<string, unknown>;
  request?: Record<string, unknown>;
  custom?: Record<string, unknown>;
  /** Override for testing (ISO 8601). */
  current_time?: string;
}

/** Missing context fields evaluate to false (fail-closed). */
export function evaluateCondition(
  condition: Condition,
  context: RuntimeContext,
): boolean {
  return evaluateConditionDepth(condition, context, 0);
}

function evaluateConditionDepth(
  condition: Condition,
  context: RuntimeContext,
  depth: number,
): boolean {
  if (depth > MAX_NESTING_DEPTH) {
    return false;
  }

  if (condition.time_window != null) {
    if (!checkTimeWindow(condition.time_window, context)) {
      return false;
    }
  }

  if (condition.context != null) {
    if (!checkContextMatch(condition.context, context)) {
      return false;
    }
  }

  if (condition.all_of != null) {
    if (
      !condition.all_of.every((c) =>
        evaluateConditionDepth(c, context, depth + 1),
      )
    ) {
      return false;
    }
  }

  if (condition.any_of != null) {
    if (
      !condition.any_of.some((c) =>
        evaluateConditionDepth(c, context, depth + 1),
      )
    ) {
      return false;
    }
  }

  if (condition.not != null) {
    if (evaluateConditionDepth(condition.not, context, depth + 1)) {
      return false;
    }
  }

  return true;
}

function checkTimeWindow(
  tw: TimeWindowCondition,
  context: RuntimeContext,
): boolean {
  const now = resolveCurrentTime(context, tw.timezone);
  if (now == null) {
    return false;
  }

  const [hour, minute, dayOfWeek] = now;

  if (tw.days != null && tw.days.length > 0) {
    const dayAbbrev = dayAbbreviation(dayOfWeek);
    if (
      !tw.days.some(
        (d) => d.toLowerCase() === dayAbbrev,
      )
    ) {
      return false;
    }
  }

  const startParsed = parseHHMM(tw.start);
  const endParsed = parseHHMM(tw.end);
  if (startParsed == null || endParsed == null) {
    return false;
  }

  const [startH, startM] = startParsed;
  const [endH, endM] = endParsed;

  const currentMinutes = hour * 60 + minute;
  const startMinutes = startH * 60 + startM;
  const endMinutes = endH * 60 + endM;

  if (startMinutes === endMinutes) {
    return true;
  }

  if (startMinutes < endMinutes) {
    return currentMinutes >= startMinutes && currentMinutes < endMinutes;
  } else {
    return currentMinutes >= startMinutes || currentMinutes < endMinutes;
  }
}

function parseHHMM(s: string): [number, number] | undefined {
  const parts = s.split(':');
  if (parts.length !== 2) return undefined;
  const hour = parseInt(parts[0], 10);
  const minute = parseInt(parts[1], 10);
  if (isNaN(hour) || isNaN(minute) || hour > 23 || minute > 59 || hour < 0 || minute < 0) {
    return undefined;
  }
  return [hour, minute];
}

function dayAbbreviation(day: number): string {
  const days = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'];
  return days[day] ?? 'mon';
}

/** Returns [hour, minute, dayOfWeek] where dayOfWeek is 0=Mon..6=Sun. */
function resolveCurrentTime(
  context: RuntimeContext,
  timezone?: string,
): [number, number, number] | undefined {
  let date: Date;

  if (context.current_time != null) {
    date = new Date(context.current_time);
    if (isNaN(date.getTime())) {
      return undefined;
    }
  } else {
    date = new Date();
  }

  const tz = timezone ?? 'UTC';
  const offsetHours = parseTimezoneOffset(tz);
  const adjustedMs = date.getTime() + offsetHours * 3600 * 1000;
  const adjusted = new Date(adjustedMs);

  const hour = adjusted.getUTCHours();
  const minute = adjusted.getUTCMinutes();
  // Convert JS 0=Sun..6=Sat to 0=Mon..6=Sun
  const jsDay = adjusted.getUTCDay();
  const dayOfWeek = jsDay === 0 ? 6 : jsDay - 1;

  return [hour, minute, dayOfWeek];
}

function parseTimezoneOffset(tz: string): number {
  const offsets: Record<string, number> = {
    'UTC': 0,
    'utc': 0,
    'Etc/UTC': 0,
    'Etc/GMT': 0,
    'GMT': 0,
    'America/New_York': -5,
    'US/Eastern': -5,
    'EST': -5,
    'America/Chicago': -6,
    'US/Central': -6,
    'CST': -6,
    'America/Denver': -7,
    'US/Mountain': -7,
    'MST': -7,
    'America/Los_Angeles': -8,
    'US/Pacific': -8,
    'PST': -8,
    'Europe/London': 0,
    'GB': 0,
    'Europe/Paris': 1,
    'Europe/Berlin': 1,
    'CET': 1,
    'Europe/Helsinki': 2,
    'EET': 2,
    'Asia/Tokyo': 9,
    'Japan': 9,
    'JST': 9,
    'Asia/Shanghai': 8,
    'Asia/Hong_Kong': 8,
    'PRC': 8,
    'Asia/Kolkata': 5,
    'Asia/Calcutta': 5,
    'IST': 5,
  };

  if (tz in offsets) {
    return offsets[tz];
  }

  if (tz.startsWith('+')) {
    return parseOffsetValue(tz.slice(1));
  }
  if (tz.startsWith('-')) {
    return -parseOffsetValue(tz.slice(1));
  }

  return 0;
}

function parseOffsetValue(s: string): number {
  const colonIdx = s.indexOf(':');
  if (colonIdx >= 0) {
    return parseInt(s.slice(0, colonIdx), 10) || 0;
  }
  return parseInt(s, 10) || 0;
}

function checkContextMatch(
  expected: Record<string, unknown>,
  context: RuntimeContext,
): boolean {
  for (const [key, expectedValue] of Object.entries(expected)) {
    const actual = resolveContextValue(key, context);
    if (!matchValue(actual, expectedValue)) {
      return false;
    }
  }
  return true;
}

function resolveContextValue(
  path: string,
  context: RuntimeContext,
): unknown {
  const dotIdx = path.indexOf('.');
  const topLevel = dotIdx >= 0 ? path.slice(0, dotIdx) : path;
  const rest = dotIdx >= 0 ? path.slice(dotIdx + 1) : undefined;

  switch (topLevel) {
    case 'environment':
      return context.environment;
    case 'user':
      return rest != null ? context.user?.[rest] : context.user;
    case 'deployment':
      return rest != null ? context.deployment?.[rest] : context.deployment;
    case 'agent':
      return rest != null ? context.agent?.[rest] : context.agent;
    case 'session':
      return rest != null ? context.session?.[rest] : context.session;
    case 'request':
      return rest != null ? context.request?.[rest] : context.request;
    case 'custom':
      return rest != null ? context.custom?.[rest] : context.custom;
    default:
      return undefined;
  }
}

function matchValue(actual: unknown, expected: unknown): boolean {
  if (actual == null) {
    return false;
  }

  if (typeof expected === 'string') {
    if (typeof actual === 'string') {
      return actual === expected;
    }
    if (Array.isArray(actual)) {
      return actual.some((v) => v === expected);
    }
    return false;
  }

  if (typeof expected === 'boolean') {
    return actual === expected;
  }

  if (typeof expected === 'number') {
    return actual === expected;
  }

  if (Array.isArray(expected)) {
    if (typeof actual === 'string') {
      return expected.some((v) => v === actual);
    }
    return false;
  }

  return false;
}

export function evaluateWithContext(
  spec: HushSpec,
  action: EvaluationAction,
  context: RuntimeContext,
  conditions: Record<string, Condition>,
): EvaluationResult {
  const effectiveSpec = applyConditions(spec, context, conditions);
  return evaluate(effectiveSpec, action);
}

function applyConditions(
  spec: HushSpec,
  context: RuntimeContext,
  conditions: Record<string, Condition>,
): HushSpec {
  if (!spec.rules) {
    return spec;
  }

  const effectiveRules = { ...spec.rules };
  let changed = false;

  for (const [blockName, condition] of Object.entries(conditions)) {
    if (!evaluateCondition(condition, context)) {
      const key = blockName as keyof typeof effectiveRules;
      if (key in effectiveRules && effectiveRules[key] != null) {
        (effectiveRules as Record<string, unknown>)[key] = undefined;
        changed = true;
      }
    }
  }

  if (!changed) {
    return spec;
  }

  return { ...spec, rules: effectiveRules };
}
