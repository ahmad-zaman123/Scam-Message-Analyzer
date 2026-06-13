// Turn a list of findings into one traffic-light verdict.
// Ported from scam_message_analyzer/scoring.py.

import { HIGH } from "./findings.js";

export const RED = "red";
export const YELLOW = "yellow";
export const GREEN = "green";

export const VERDICT_LABEL = {
  [RED]: "🔴 LIKELY A SCAM",
  [YELLOW]: "🟡 BE CAREFUL",
  [GREEN]: "🟢 PROBABLY OKAY",
};

const RED_WEIGHT_THRESHOLD = 4;

/** Return [verdict, totalWeight] for the given findings. */
export function score(findings) {
  const total = findings.reduce((sum, f) => sum + (f.weight || 0), 0);
  const hasHigh = findings.some((f) => f.severity === HIGH);

  if (findings.length === 0) return [GREEN, 0];
  if (hasHigh || total >= RED_WEIGHT_THRESHOLD) return [RED, total];
  return [YELLOW, total];
}
