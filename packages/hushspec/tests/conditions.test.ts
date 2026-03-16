import { describe, it, expect } from 'vitest';
import {
  evaluateCondition,
  evaluateWithContext,
  type Condition,
  type RuntimeContext,
} from '../src/conditions.js';
import type { HushSpec } from '../src/schema.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function ctxWithEnv(env: string): RuntimeContext {
  return { environment: env };
}

function ctxWithTime(time: string): RuntimeContext {
  return { current_time: time };
}

function ctxWithUserRole(role: string): RuntimeContext {
  return { user: { role } };
}

function makeEgressSpec(): HushSpec {
  return {
    hushspec: '0.1.0',
    name: 'conditional-test',
    rules: {
      egress: {
        enabled: true,
        allow: ['api.openai.com'],
        default: 'block',
      },
    },
  };
}

function makeToolAccessSpec(): HushSpec {
  return {
    hushspec: '0.1.0',
    name: 'conditional-tool-test',
    rules: {
      tool_access: {
        enabled: true,
        allow: ['deploy'],
        block: ['danger_tool'],
        default: 'block',
      },
    },
  };
}

// ---------------------------------------------------------------------------
// Context conditions
// ---------------------------------------------------------------------------

describe('evaluateCondition', () => {
  describe('context conditions', () => {
    it('matches environment', () => {
      const cond: Condition = {
        context: { environment: 'production' },
      };
      expect(evaluateCondition(cond, ctxWithEnv('production'))).toBe(true);
    });

    it('rejects mismatch', () => {
      const cond: Condition = {
        context: { environment: 'production' },
      };
      expect(evaluateCondition(cond, ctxWithEnv('staging'))).toBe(false);
    });

    it('missing context field fails closed', () => {
      const cond: Condition = {
        context: { 'user.role': 'admin' },
      };
      expect(evaluateCondition(cond, {})).toBe(false);
    });

    it('matches user role', () => {
      const cond: Condition = {
        context: { 'user.role': 'admin' },
      };
      expect(evaluateCondition(cond, ctxWithUserRole('admin'))).toBe(true);
      expect(evaluateCondition(cond, ctxWithUserRole('viewer'))).toBe(false);
    });

    it('array of expected values (OR within a key)', () => {
      const cond: Condition = {
        context: { environment: ['production', 'staging'] },
      };
      expect(evaluateCondition(cond, ctxWithEnv('production'))).toBe(true);
      expect(evaluateCondition(cond, ctxWithEnv('staging'))).toBe(true);
      expect(evaluateCondition(cond, ctxWithEnv('development'))).toBe(false);
    });

    it('scalar expected vs array actual (membership check)', () => {
      const ctx: RuntimeContext = {
        user: { groups: ['engineering', 'ml-team'] },
      };
      const cond: Condition = {
        context: { 'user.groups': 'ml-team' },
      };
      expect(evaluateCondition(cond, ctx)).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // Time window conditions
  // -----------------------------------------------------------------------

  describe('time window conditions', () => {
    it('matches during business hours', () => {
      const ctx = ctxWithTime('2026-01-14T10:30:00Z');
      const cond: Condition = {
        time_window: {
          start: '09:00',
          end: '17:00',
          timezone: 'UTC',
        },
      };
      expect(evaluateCondition(cond, ctx)).toBe(true);
    });

    it('rejects outside hours', () => {
      const ctx = ctxWithTime('2026-01-14T20:00:00Z');
      const cond: Condition = {
        time_window: {
          start: '09:00',
          end: '17:00',
          timezone: 'UTC',
        },
      };
      expect(evaluateCondition(cond, ctx)).toBe(false);
    });

    it('filters by day of week', () => {
      // 2026-01-14 is a Wednesday
      const ctx = ctxWithTime('2026-01-14T10:00:00Z');

      const weekdayCond: Condition = {
        time_window: {
          start: '09:00',
          end: '17:00',
          timezone: 'UTC',
          days: ['mon', 'tue', 'wed', 'thu', 'fri'],
        },
      };
      expect(evaluateCondition(weekdayCond, ctx)).toBe(true);

      const weekendCond: Condition = {
        time_window: {
          start: '09:00',
          end: '17:00',
          timezone: 'UTC',
          days: ['sat', 'sun'],
        },
      };
      expect(evaluateCondition(weekendCond, ctx)).toBe(false);
    });

    it('wraps midnight', () => {
      const condNight: Condition = {
        time_window: {
          start: '22:00',
          end: '06:00',
          timezone: 'UTC',
        },
      };
      expect(evaluateCondition(condNight, ctxWithTime('2026-01-14T23:00:00Z'))).toBe(true);
      expect(evaluateCondition(condNight, ctxWithTime('2026-01-14T03:00:00Z'))).toBe(true);
      expect(evaluateCondition(condNight, ctxWithTime('2026-01-14T10:00:00Z'))).toBe(false);
    });

    it('same start and end means all day', () => {
      const cond: Condition = {
        time_window: {
          start: '12:00',
          end: '12:00',
          timezone: 'UTC',
        },
      };
      expect(evaluateCondition(cond, ctxWithTime('2026-01-14T03:00:00Z'))).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // Compound conditions
  // -----------------------------------------------------------------------

  describe('compound conditions', () => {
    it('all_of requires all conditions', () => {
      const cond: Condition = {
        all_of: [
          { context: { environment: 'production' } },
          { context: { 'user.role': 'admin' } },
        ],
      };

      const fullCtx: RuntimeContext = {
        environment: 'production',
        user: { role: 'admin' },
      };
      expect(evaluateCondition(cond, fullCtx)).toBe(true);

      // Only env matches
      expect(evaluateCondition(cond, ctxWithEnv('production'))).toBe(false);
    });

    it('any_of requires any condition', () => {
      const cond: Condition = {
        any_of: [
          { context: { environment: 'production' } },
          { context: { environment: 'staging' } },
        ],
      };

      expect(evaluateCondition(cond, ctxWithEnv('production'))).toBe(true);
      expect(evaluateCondition(cond, ctxWithEnv('staging'))).toBe(true);
      expect(evaluateCondition(cond, ctxWithEnv('development'))).toBe(false);
    });

    it('not negates condition', () => {
      const cond: Condition = {
        not: { context: { environment: 'production' } },
      };

      expect(evaluateCondition(cond, ctxWithEnv('production'))).toBe(false);
      expect(evaluateCondition(cond, ctxWithEnv('staging'))).toBe(true);
    });

    it('nested compound conditions', () => {
      // Business hours AND production AND (admin OR sre)
      const cond: Condition = {
        all_of: [
          {
            time_window: {
              start: '09:00',
              end: '17:00',
              timezone: 'UTC',
            },
          },
          { context: { environment: 'production' } },
          {
            any_of: [
              { context: { 'user.role': 'admin' } },
              { context: { 'user.role': 'sre' } },
            ],
          },
        ],
      };

      const ctx: RuntimeContext = {
        environment: 'production',
        current_time: '2026-01-14T10:00:00Z',
        user: { role: 'admin' },
      };
      expect(evaluateCondition(cond, ctx)).toBe(true);

      const ctxViewer: RuntimeContext = {
        ...ctx,
        user: { role: 'viewer' },
      };
      expect(evaluateCondition(cond, ctxViewer)).toBe(false);
    });
  });

  describe('edge cases', () => {
    it('empty condition is always true', () => {
      expect(evaluateCondition({}, {})).toBe(true);
    });

    it('max nesting depth exceeded fails closed', () => {
      // Build deeply nested condition
      let cond: Condition = { context: { environment: 'production' } };
      for (let i = 0; i < 12; i++) {
        cond = { all_of: [cond] };
      }
      expect(evaluateCondition(cond, ctxWithEnv('production'))).toBe(false);
    });
  });
});

// ---------------------------------------------------------------------------
// evaluateWithContext
// ---------------------------------------------------------------------------

describe('evaluateWithContext', () => {
  it('passes when condition is met', () => {
    const spec = makeEgressSpec();
    const action = { type: 'egress', target: 'api.openai.com' };
    const ctx: RuntimeContext = { environment: 'production' };
    const conditions: Record<string, Condition> = {
      egress: { context: { environment: 'production' } },
    };

    const result = evaluateWithContext(spec, action, ctx, conditions);
    expect(result.decision).toBe('allow');
  });

  it('skips rule when condition fails', () => {
    const spec = makeEgressSpec();
    const action = { type: 'egress', target: 'evil.example.com' };
    const ctx: RuntimeContext = { environment: 'staging' };
    const conditions: Record<string, Condition> = {
      egress: { context: { environment: 'production' } },
    };

    const result = evaluateWithContext(spec, action, ctx, conditions);
    expect(result.decision).toBe('allow');
  });

  it('enforces rule when condition is met', () => {
    const spec = makeEgressSpec();
    const action = { type: 'egress', target: 'evil.example.com' };
    const ctx: RuntimeContext = { environment: 'production' };
    const conditions: Record<string, Condition> = {
      egress: { context: { environment: 'production' } },
    };

    const result = evaluateWithContext(spec, action, ctx, conditions);
    expect(result.decision).toBe('deny');
  });

  it('no conditions behaves like evaluate', () => {
    const spec = makeEgressSpec();
    const action = { type: 'egress', target: 'evil.example.com' };
    const ctx: RuntimeContext = {};
    const conditions: Record<string, Condition> = {};

    const result = evaluateWithContext(spec, action, ctx, conditions);
    expect(result.decision).toBe('deny');
  });

  it('tool access with time window condition', () => {
    const spec = makeToolAccessSpec();
    const action = { type: 'tool_call', target: 'deploy' };
    const conditions: Record<string, Condition> = {
      tool_access: {
        time_window: {
          start: '09:00',
          end: '17:00',
          timezone: 'UTC',
        },
      },
    };

    const ctxInside: RuntimeContext = { current_time: '2026-01-14T10:00:00Z' };
    const resultInside = evaluateWithContext(spec, action, ctxInside, conditions);
    expect(resultInside.decision).toBe('allow');

    const ctxOutside: RuntimeContext = { current_time: '2026-01-14T20:00:00Z' };
    const resultOutside = evaluateWithContext(spec, action, ctxOutside, conditions);
    expect(resultOutside.decision).toBe('allow');
  });

  it('missing context fails closed', () => {
    const spec = makeEgressSpec();
    const action = { type: 'egress', target: 'api.openai.com' };
    const ctx: RuntimeContext = {};
    const conditions: Record<string, Condition> = {
      egress: { context: { environment: 'production' } },
    };

    const result = evaluateWithContext(spec, action, ctx, conditions);
    expect(result.decision).toBe('allow');
  });

  it('compound condition', () => {
    const spec = makeEgressSpec();
    const action = { type: 'egress', target: 'evil.example.com' };
    const conditions: Record<string, Condition> = {
      egress: {
        all_of: [
          { context: { environment: 'production' } },
          { context: { 'user.role': 'admin' } },
        ],
      },
    };

    const fullCtx: RuntimeContext = {
      environment: 'production',
      user: { role: 'admin' },
    };
    const result = evaluateWithContext(spec, action, fullCtx, conditions);
    expect(result.decision).toBe('deny');

    const partialCtx: RuntimeContext = { environment: 'production' };
    const result2 = evaluateWithContext(spec, action, partialCtx, conditions);
    expect(result2.decision).toBe('allow');
  });
});
