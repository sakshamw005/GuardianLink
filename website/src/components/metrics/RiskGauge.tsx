import { PieChart, Pie, Cell } from "recharts";

export type Verdict = "safe" | "warning" | "danger";

const COLORS: Record<Verdict, string> = {
  safe: "#22c55e",
  warning: "#f59e0b",
  danger: "#ef4444"
};

export function RiskGauge({
  score,
  verdict
}: {
  score: number;
  verdict: Verdict;
}) {
  const data = [
    { value: score },
    { value: 100 - score }
  ];

  return (
    <div className="glass-card p-6 flex flex-col items-center justify-center">
      {/* Title */}
      <h4 className="text-sm text-muted-foreground mb-2">
        Overall Risk
      </h4>

      {/* Gauge */}
      <div className="flex items-center justify-center">
        <PieChart width={220} height={170}>
          <Pie
            data={data}
            startAngle={180}
            endAngle={0}
            innerRadius={60}
            outerRadius={82}
            cx="50%"
            cy="72%"   // ⬅️ slightly lower than before
            dataKey="value"
            stroke="none"
          >
            <Cell fill={COLORS[verdict]} />
            <Cell fill="#1f2937" />
          </Pie>
        </PieChart>
      </div>

      {/* Score */}
      <div className="-mt-6 text-center">
        <div className="text-3xl font-bold">
          {score}%
        </div>

        <div
          className="text-sm font-semibold"
          style={{ color: COLORS[verdict] }}
        >
          {verdict === "danger"
            ? "High Risk"
            : verdict === "warning"
            ? "Moderate Risk"
            : "Low Risk"}
        </div>

        <div className="text-xs text-muted-foreground mt-1">
          Score out of 100
        </div>
      </div>
    </div>
  );
}
