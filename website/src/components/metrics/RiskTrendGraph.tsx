import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer
} from "recharts";

interface RiskPoint {
  label: string;
  value: number;
}

export function RiskTrendGraph({
  data
}: {
  data: RiskPoint[];
}) {
  return (
    <div className="glass-card p-6">
      <h4 className="text-sm text-muted-foreground mb-4">
        Risk Signal Trend
      </h4>

      <ResponsiveContainer width="100%" height={260}>
        <LineChart data={data}>
          <CartesianGrid
            strokeDasharray="3 3"
            stroke="#1f2937"
          />
          <XAxis
            dataKey="label"
            stroke="#9ca3af"
            tick={{ fontSize: 12 }}
          />
          <YAxis
            stroke="#9ca3af"
            domain={[0, 100]}
            tick={{ fontSize: 12 }}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: "#020617",
              border: "1px solid #1f2937",
              fontSize: "12px"
            }}
          />
          <Line
            type="monotone"
            dataKey="value"
            stroke="#22d3ee"
            strokeWidth={3}
            dot={{ r: 4 }}
            activeDot={{ r: 6 }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
