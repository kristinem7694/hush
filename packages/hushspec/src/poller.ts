import { createHash } from 'node:crypto';
import { parse } from './parse.js';
import type { HushSpec } from './schema.js';

export interface PollerOptions {
  loader: () => Promise<string>;
  intervalMs?: number;
  onChange: (spec: HushSpec) => void;
  onError?: (error: Error) => void;
  /** If set, `current()` throws when the last load exceeds this age. */
  maxStaleMs?: number;
}

export class PolicyPoller {
  private options: PollerOptions;
  private timer: ReturnType<typeof setInterval> | null = null;
  private currentSpec: HushSpec | null = null;
  private lastSuccessfulLoad: number = 0;
  private contentHash: string | null = null;

  constructor(options: PollerOptions) {
    this.options = options;
  }

  async start(): Promise<HushSpec> {
    const spec = await this.doLoad(true);

    const intervalMs = this.options.intervalMs ?? 60_000;
    this.timer = setInterval(() => {
      void this.doLoad(false);
    }, intervalMs);

    if (this.timer && typeof this.timer === 'object' && 'unref' in this.timer) {
      (this.timer as { unref(): void }).unref();
    }

    return spec;
  }

  stop(): void {
    if (this.timer != null) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  current(): HushSpec | null {
    const maxStaleMs = this.options.maxStaleMs ?? Infinity;
    if (
      this.currentSpec != null &&
      maxStaleMs !== Infinity &&
      this.lastSuccessfulLoad > 0
    ) {
      const age = Date.now() - this.lastSuccessfulLoad;
      if (age > maxStaleMs) {
        throw new Error(
          `Policy is stale: last successful load was ${age}ms ago (max: ${maxStaleMs}ms)`,
        );
      }
    }
    return this.currentSpec;
  }

  async reload(): Promise<HushSpec> {
    return this.doLoad(true);
  }

  private async doLoad(throwOnError: boolean): Promise<HushSpec> {
    let content: string;
    try {
      content = await this.options.loader();
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      if (throwOnError && this.currentSpec == null) {
        throw error;
      }
      this.options.onError?.(error);
      return this.currentSpec!;
    }

    const hash = createHash('sha256').update(content).digest('hex');
    if (hash === this.contentHash) {
      this.lastSuccessfulLoad = Date.now();
      return this.currentSpec!;
    }

    const result = parse(content);
    if (!result.ok) {
      const error = new Error(`Failed to parse policy: ${result.error}`);
      if (throwOnError && this.currentSpec == null) {
        throw error;
      }
      this.options.onError?.(error);
      return this.currentSpec!;
    }

    this.currentSpec = result.value;
    this.contentHash = hash;
    this.lastSuccessfulLoad = Date.now();
    this.options.onChange(result.value);

    return result.value;
  }
}
