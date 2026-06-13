// Finding data structures shared across the detection pipeline.
// Ported from scam_message_analyzer/findings.py.

export const HIGH = "high";
export const MEDIUM = "medium";
export const LOW = "low";

const SEVERITY_WEIGHTS = { [HIGH]: 3, [MEDIUM]: 2, [LOW]: 1 };

/** A single suspicious signal: a detector code, a severity, and evidence used
 *  to fill in the plain-language explanation. */
export function finding(code, severity, evidence = {}) {
  return { code, severity, evidence, weight: SEVERITY_WEIGHTS[severity] || 0 };
}
