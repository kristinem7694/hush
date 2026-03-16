import type { ClassificationValue, LifecycleStateValue, MergeStrategyValue } from './generated/contract.js';
import type { Rules } from './rules.js';
import type { Extensions } from './extensions.js';

export type MergeStrategy = MergeStrategyValue;
export type Classification = ClassificationValue;
export type LifecycleState = LifecycleStateValue;

/** Informational only -- has no impact on evaluation. */
export interface GovernanceMetadata {
  author?: string;
  approved_by?: string;
  approval_date?: string;
  classification?: Classification;
  change_ticket?: string;
  lifecycle_state?: LifecycleState;
  policy_version?: number;
  effective_date?: string;
  expiry_date?: string;
}

export interface HushSpec {
  hushspec: string;
  name?: string;
  description?: string;
  extends?: string;
  merge_strategy?: MergeStrategy;
  rules?: Rules;
  extensions?: Extensions;
  metadata?: GovernanceMetadata;
}
