interface DetectionSignalsProps {
  vtMalicious: number;
  vtSuspicious: number;
  heuristicHits: number;
}

export function DetectionSignals({
  vtMalicious,
  vtSuspicious,
  heuristicHits
}: DetectionSignalsProps) {
  const signals = [
    {
      label: "VT Malicious",
      value: vtMalicious,
      color: "#ef4444",
      desc: "Confirmed malware detections"
    },
    {
      label: "VT Suspicious",
      value: vtSuspicious,
      color: "#f59e0b",
      desc: "Suspicious vendor verdicts"
    },
    {
      label: "Heuristic Hits",
      value: heuristicHits,
      color: "#a855f7",
      desc: "Behavioral rule matches"
    }
  ];

  return (
    <div className="glass-card p-6">
      <h4 className="text-sm text-muted-foreground mb-4">
        Detection Signals
      </h4>

      <div className="grid grid-cols-3 gap-6">
        {signals.map(s => (
          <div key={s.label} className="text-center">
            <div
              className="text-3xl font-bold"
              style={{ color: s.color }}
            >
              {s.value}
            </div>
            <div className="text-xs font-semibold">
              {s.label}
            </div>
            <div className="text-[11px] text-muted-foreground mt-1">
              {s.desc}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
