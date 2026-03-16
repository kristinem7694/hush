import type { EvaluationAction, EvaluationResult } from '../evaluate.js';
import type { HushGuard } from '../middleware.js';

export function mapOpenAIToolCall(
  functionName: string,
  functionArgs: string | Record<string, unknown>,
): EvaluationAction {
  const args =
    typeof functionArgs === 'string'
      ? (JSON.parse(functionArgs) as Record<string, unknown>)
      : functionArgs;

  return {
    type: 'tool_call',
    target: functionName,
    args_size:
      typeof functionArgs === 'string'
        ? functionArgs.length
        : JSON.stringify(args).length,
  };
}

export function createOpenAIGuard(
  guard: HushGuard,
): (functionName: string, functionArgs: string | Record<string, unknown>) => EvaluationResult {
  return (
    functionName: string,
    functionArgs: string | Record<string, unknown>,
  ): EvaluationResult => {
    const action = mapOpenAIToolCall(functionName, functionArgs);
    return guard.evaluate(action);
  };
}
