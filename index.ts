import { ReportSchema, type Report } from "@bug-bounty-ai/shared";

export type ValidationVerdict = {
  accepted: boolean;
  reasons: string[];
  phase: Report["phase"];
};

export async function validateReport(input: unknown): Promise<ValidationVerdict> {
  const report = ReportSchema.parse(input);
  const reasons: string[] = [];

  if (report.execution.completed_at < report.execution.started_at) {
    reasons.push("execution timestamps are invalid");
  }

  if (report.findings.length === 0) {
    reasons.push("report contains no findings");
  }

  return {
    accepted: reasons.length === 0,
    reasons,
    phase: report.phase
  };
}
