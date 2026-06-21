export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  severity: Severity;
  tool: string;
  file?: string;
  rule: string;
  message: string;
  fix?: string;
}

export interface CheckResult {
  findings: Finding[];
  skipped?: string;
}
