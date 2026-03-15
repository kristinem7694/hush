import type { Rules } from './rules.js';
import type { Extensions } from './extensions.js';

/** Strategy used when merging a child spec into a base spec. */
export type MergeStrategy = 'replace' | 'merge' | 'deep_merge';

/** A parsed HushSpec document describing AI agent security rules. */
export interface HushSpec {
  hushspec: string;
  name?: string;
  description?: string;
  extends?: string;
  merge_strategy?: MergeStrategy;
  rules?: Rules;
  extensions?: Extensions;
}
