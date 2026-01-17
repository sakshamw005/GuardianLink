export function HeuristicImpact({
  score,
  max
}: {
  score: number;
  max: number;
}) {
  const percent = Math.round((score / max) * 100);

  return (
    <div className="glass-card p-6">
      <h4 className="text-sm text-muted-foreground mb-2">
        Heuristic Impact
      </h4>

      <div className="text-2xl font-bold mb-3">
        {score} / {max}
      </div>

      <div className="w-full h-3 bg-muted rounded overflow-hidden">
        <div
          className="h-full bg-cyan-400 transition-all"
          style={{ width: `${percent}%` }}
        />
      </div>

      <div className="text-xs text-muted-foreground mt-2">
        {percent}% of heuristic rules triggered
      </div>
    </div>
  );
}
