import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell
} from "recharts";

interface PhaseMetric {
  name: string;
  score: number;
  max: number;
}

export function PhaseRiskHistogram({
  phases
}: {
  phases: PhaseMetric[];
}) {
  const data = phases.map(p => {
    const percent = Math.round((p.score / p.max) * 100);
    const risk = 100 - percent;

    return {
      name: p.name,
      risk,
      color:
        risk > 60
          ? "#ef4444"
          : risk > 30
          ? "#f59e0b"
          : "#22c55e"
    };
  });

  return (
    <div className="glass-card p-6">
      <h4 className="text-sm text-muted-foreground mb-4">
        Phase Risk Histogram
      </h4>

      <ResponsiveContainer width="100%" height={260}>
        <BarChart data={data}>
          <XAxis
            dataKey="name"
            stroke="#9ca3af"
            tick={{ fontSize: 11 }}
          />
          <YAxis
            domain={[0, 100]}
            stroke="#9ca3af"
            tick={{ fontSize: 11 }}
          />
          <Tooltip
            formatter={(v: number) => `${v}% risk`}
            contentStyle={{
              backgroundColor: "#020617",
              border: "1px solid #1f2937",
              fontSize: "12px"
            }}
          />
          <Bar dataKey="risk" radius={[6,6,0,0]}>
            {data.map((entry, index) => (
              <Cell key={index} fill={entry.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
