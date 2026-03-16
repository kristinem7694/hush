import type { DecisionReceipt } from './receipt.js';
import { appendFileSync } from 'node:fs';

export interface ReceiptSink {
  send(receipt: DecisionReceipt): void;
}

export class FileReceiptSink implements ReceiptSink {
  constructor(private path: string) {}

  send(receipt: DecisionReceipt): void {
    appendFileSync(this.path, JSON.stringify(receipt) + '\n');
  }
}

export class ConsoleReceiptSink implements ReceiptSink {
  send(receipt: DecisionReceipt): void {
    console.error('[hushspec]', JSON.stringify(receipt));
  }
}

export class FilteredSink implements ReceiptSink {
  constructor(
    private inner: ReceiptSink,
    private decisions: string[],
  ) {}

  static denyOnly(sink: ReceiptSink): FilteredSink {
    return new FilteredSink(sink, ['deny']);
  }

  send(receipt: DecisionReceipt): void {
    if (this.decisions.includes(receipt.decision)) {
      this.inner.send(receipt);
    }
  }
}

export class MultiSink implements ReceiptSink {
  constructor(private sinks: ReceiptSink[]) {}

  send(receipt: DecisionReceipt): void {
    for (const sink of this.sinks) {
      try {
        sink.send(receipt);
      } catch {
        // Sinks must not crash the application.
      }
    }
  }
}

export class CallbackSink implements ReceiptSink {
  constructor(private callback: (receipt: DecisionReceipt) => void) {}

  send(receipt: DecisionReceipt): void {
    this.callback(receipt);
  }
}

export class NullSink implements ReceiptSink {
  send(): void {}
}
