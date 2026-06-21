export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  severity: Severity;
  tool: string;
  file?: string;
  rule: string;
  message: string;
  fix?: string;
  /** One-liner prompt to paste into `claude -p` or `opencode run` to auto-fix this finding */
  agentPrompt?: string;
}

export interface CheckResult {
  findings: Finding[];
  skipped?: string;
}
