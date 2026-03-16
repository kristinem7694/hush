import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { readFileSync, unlinkSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { DecisionReceipt } from '../src/receipt.js';
import {
  FileReceiptSink,
  ConsoleReceiptSink,
  FilteredSink,
  MultiSink,
  CallbackSink,
  NullSink,
} from '../src/sinks.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeReceipt(decision: 'allow' | 'warn' | 'deny'): DecisionReceipt {
  return {
    receipt_id: 'test-receipt-001',
    timestamp: '2026-03-15T00:00:00.000Z',
    hushspec_version: '0.1.0',
    action: {
      type: 'tool_call',
      target: 'test_tool',
      content_redacted: false,
    },
    decision,
    matched_rule: 'rules.tool_access.allow',
    reason: 'tool is explicitly allowed',
    rule_trace: [
      {
        rule_block: 'tool_access',
        outcome: 'allow',
        matched_rule: 'rules.tool_access.allow',
        reason: 'tool is explicitly allowed',
        evaluated: true,
      },
    ],
    policy: {
      name: 'test-policy',
      version: '0.1.0',
      content_hash: 'abc123',
    },
    evaluation_duration_us: 42,
  };
}

// ---------------------------------------------------------------------------
// FileReceiptSink
// ---------------------------------------------------------------------------

describe('FileReceiptSink', () => {
  const testDir = join(tmpdir(), `hushspec_sink_test_ts_${process.pid}`);
  const testFile = join(testDir, 'receipts.jsonl');

  beforeEach(() => {
    mkdirSync(testDir, { recursive: true });
    if (existsSync(testFile)) unlinkSync(testFile);
  });

  afterEach(() => {
    if (existsSync(testFile)) unlinkSync(testFile);
  });

  it('writes JSON lines to file', () => {
    const sink = new FileReceiptSink(testFile);
    sink.send(makeReceipt('allow'));
    sink.send(makeReceipt('deny'));

    const content = readFileSync(testFile, 'utf-8');
    const lines = content.trim().split('\n');
    expect(lines).toHaveLength(2);

    const parsed1 = JSON.parse(lines[0]);
    expect(parsed1.receipt_id).toBe('test-receipt-001');
    expect(parsed1.decision).toBe('allow');

    const parsed2 = JSON.parse(lines[1]);
    expect(parsed2.decision).toBe('deny');
  });

  it('appends, does not overwrite', () => {
    const sink = new FileReceiptSink(testFile);
    sink.send(makeReceipt('allow'));
    sink.send(makeReceipt('allow'));
    sink.send(makeReceipt('allow'));

    const content = readFileSync(testFile, 'utf-8');
    const lines = content.trim().split('\n');
    expect(lines).toHaveLength(3);
  });
});

// ---------------------------------------------------------------------------
// ConsoleReceiptSink
// ---------------------------------------------------------------------------

describe('ConsoleReceiptSink', () => {
  it('does not crash', () => {
    const sink = new ConsoleReceiptSink();
    expect(() => sink.send(makeReceipt('allow'))).not.toThrow();
    expect(() => sink.send(makeReceipt('deny'))).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// FilteredSink
// ---------------------------------------------------------------------------

describe('FilteredSink', () => {
  it('denyOnly only forwards deny receipts', () => {
    const collected: string[] = [];
    const inner = new CallbackSink((r) => collected.push(r.decision));
    const filtered = FilteredSink.denyOnly(inner);

    filtered.send(makeReceipt('allow'));
    filtered.send(makeReceipt('warn'));
    filtered.send(makeReceipt('deny'));
    filtered.send(makeReceipt('allow'));
    filtered.send(makeReceipt('deny'));

    expect(collected).toEqual(['deny', 'deny']);
  });

  it('filters by custom decisions', () => {
    const collected: string[] = [];
    const inner = new CallbackSink((r) => collected.push(r.decision));
    const filtered = new FilteredSink(inner, ['allow', 'warn']);

    filtered.send(makeReceipt('allow'));
    filtered.send(makeReceipt('deny'));
    filtered.send(makeReceipt('warn'));

    expect(collected).toEqual(['allow', 'warn']);
  });
});

// ---------------------------------------------------------------------------
// MultiSink
// ---------------------------------------------------------------------------

describe('MultiSink', () => {
  it('sends to all sinks', () => {
    let count1 = 0;
    let count2 = 0;
    const sink1 = new CallbackSink(() => { count1++; });
    const sink2 = new CallbackSink(() => { count2++; });

    const multi = new MultiSink([sink1, sink2]);
    multi.send(makeReceipt('allow'));
    multi.send(makeReceipt('deny'));

    expect(count1).toBe(2);
    expect(count2).toBe(2);
  });

  it('continues after error in one sink', () => {
    let count = 0;
    const failingSink = new CallbackSink(() => { throw new Error('test error'); });
    const countingSink = new CallbackSink(() => { count++; });

    const multi = new MultiSink([failingSink, countingSink]);
    expect(() => multi.send(makeReceipt('allow'))).not.toThrow();
    expect(count).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// CallbackSink
// ---------------------------------------------------------------------------

describe('CallbackSink', () => {
  it('invokes the callback with receipt', () => {
    const received: DecisionReceipt[] = [];
    const sink = new CallbackSink((r) => received.push(r));

    sink.send(makeReceipt('allow'));
    sink.send(makeReceipt('deny'));

    expect(received).toHaveLength(2);
    expect(received[0].decision).toBe('allow');
    expect(received[1].decision).toBe('deny');
  });
});

// ---------------------------------------------------------------------------
// NullSink
// ---------------------------------------------------------------------------

describe('NullSink', () => {
  it('does not crash', () => {
    const sink = new NullSink();
    expect(() => sink.send(makeReceipt('allow'))).not.toThrow();
    expect(() => sink.send(makeReceipt('deny'))).not.toThrow();
    expect(() => sink.send(makeReceipt('warn'))).not.toThrow();
  });
});
