import { readFileSync } from 'node:fs';
import type { HushSpec } from './schema.js';
import { PolicyWatcher, type WatcherOptions } from './watcher.js';
import { PolicyPoller, type PollerOptions } from './poller.js';
import { parse } from './parse.js';

export interface PolicyProvider {
  load(): Promise<HushSpec>;
  watch(onChange: (spec: HushSpec) => void, onError?: (error: Error) => void): void;
  stop(): void;
  current(): HushSpec | null;
}

export class FileProvider implements PolicyProvider {
  private path: string;
  private debounceMs: number;
  private watcher: PolicyWatcher | null = null;
  private currentSpec: HushSpec | null = null;

  constructor(path: string, options?: { debounceMs?: number }) {
    this.path = path;
    this.debounceMs = options?.debounceMs ?? 300;
  }

  async load(): Promise<HushSpec> {
    const content = readFileSync(this.path, 'utf8');
    const result = parse(content);
    if (!result.ok) {
      throw new Error(`Failed to parse HushSpec at ${this.path}: ${result.error}`);
    }
    this.currentSpec = result.value;
    return result.value;
  }

  watch(onChange: (spec: HushSpec) => void, onError?: (error: Error) => void): void {
    this.stop();

    const watcherOptions: WatcherOptions = {
      debounceMs: this.debounceMs,
      onChange: (spec: HushSpec) => {
        this.currentSpec = spec;
        onChange(spec);
      },
      onError,
    };

    this.watcher = new PolicyWatcher(this.path, watcherOptions);
    const spec = this.watcher.start();
    this.currentSpec = spec;
  }

  stop(): void {
    if (this.watcher != null) {
      this.watcher.stop();
      this.watcher = null;
    }
  }

  current(): HushSpec | null {
    return this.currentSpec;
  }
}

export class HttpProvider implements PolicyProvider {
  private url: string;
  private intervalMs: number;
  private authHeader?: string;
  private maxStaleMs: number;
  private poller: PolicyPoller | null = null;
  private currentSpec: HushSpec | null = null;

  constructor(url: string, options?: {
    intervalMs?: number;
    authHeader?: string;
    maxStaleMs?: number;
  }) {
    this.url = url;
    this.intervalMs = options?.intervalMs ?? 60_000;
    this.authHeader = options?.authHeader;
    this.maxStaleMs = options?.maxStaleMs ?? Infinity;
  }

  async load(): Promise<HushSpec> {
    const content = await this.fetchContent();
    const result = parse(content);
    if (!result.ok) {
      throw new Error(`Failed to parse HushSpec from ${this.url}: ${result.error}`);
    }
    this.currentSpec = result.value;
    return result.value;
  }

  watch(onChange: (spec: HushSpec) => void, onError?: (error: Error) => void): void {
    this.stop();

    const pollerOptions: PollerOptions = {
      loader: () => this.fetchContent(),
      intervalMs: this.intervalMs,
      onChange: (spec: HushSpec) => {
        this.currentSpec = spec;
        onChange(spec);
      },
      onError,
      maxStaleMs: this.maxStaleMs,
    };

    this.poller = new PolicyPoller(pollerOptions);
    void this.poller.start().then((spec) => {
      this.currentSpec = spec;
    }).catch((err) => {
      if (onError) {
        onError(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }

  stop(): void {
    if (this.poller != null) {
      this.poller.stop();
      this.poller = null;
    }
  }

  current(): HushSpec | null {
    if (this.poller != null) {
      return this.poller.current();
    }
    return this.currentSpec;
  }

  private async fetchContent(): Promise<string> {
    const headers: Record<string, string> = {};
    if (this.authHeader) {
      headers['Authorization'] = this.authHeader;
    }

    const response = await fetch(this.url, { headers });
    if (!response.ok) {
      throw new Error(
        `HTTP request to '${this.url}' returned status ${response.status}`,
      );
    }
    return response.text();
  }
}
