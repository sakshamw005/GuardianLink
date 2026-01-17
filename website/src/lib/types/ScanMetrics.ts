export type Verdict = "safe" | "warning" | "danger";

export interface PhaseMetric {
  name: string;
  score: number;
  max: number;
}

export interface RiskTrendPoint {
  label: string;
  value: number;
}

export interface DetectionSignals {
  vtMalicious: number;
  vtSuspicious: number;
  heuristicHits: number;
}

export interface HeuristicMetric {
  score: number;
  max: number;
}

export interface ScanMetrics {
  riskScore: number;
  verdict: Verdict;

  phases: PhaseMetric[];
  heuristics: HeuristicMetric;
  signals: DetectionSignals;
  riskTrend: RiskTrendPoint[];
}
