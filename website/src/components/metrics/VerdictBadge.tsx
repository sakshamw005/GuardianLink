export type Verdict = "safe" | "warning" | "danger";

const VERDICT_COLORS: Record<Verdict, string> = {
  safe: "#22c55e",
  warning: "#f59e0b",
  danger: "#ef4444"
};

export function VerdictBadge({
  verdict
}: {
  verdict: Verdict;
}) {
  return (
    <div className="glass-card p-6 flex flex-col items-center justify-center">
      <h4 className="text-sm text-muted-foreground mb-3">
        Final Verdict
      </h4>

      <span
        className="px-4 py-1 rounded-full text-sm font-semibold tracking-wide"
        style={{
          backgroundColor: `${VERDICT_COLORS[verdict]}20`,
          color: VERDICT_COLORS[verdict]
        }}
      >
        {verdict.toUpperCase()}
      </span>

      <p className="text-xs text-muted-foreground mt-3 text-center">
        System-enforced security decision
      </p>
    </div>
  );
}
