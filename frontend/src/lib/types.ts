export type DatasetName = "cicids2018" | "iscx_vpn" | "caida" | "sample";
export type Protocol = "TCP" | "UDP" | "ICMP";
export type Verdict = "Benign" | "Suspicious" | "Attack";

export interface FlowFeatures {
  source_ip: string;
  destination_ip: string;
  protocol: Protocol;
  src_port: number;
  dst_port: number;
  duration_ms: number;
  fwd_packets: number;
  bwd_packets: number;
  total_bytes: number;
  packet_size_mean: number;
  packet_size_std: number;
  syn_count: number;
  fin_count: number;
  rst_count: number;
  unique_dst_ports: number;
  payload_entropy: number;
  is_vpn: boolean;
  hour_of_day: number;
}

export interface Attribution {
  feature: string;
  value: string;
  contribution: number;
  direction: "risk" | "benign";
  description: string;
}

export interface DetectionResponse {
  id: string;
  dataset: DatasetName;
  verdict: Verdict;
  attack_family: string;
  confidence: number;
  risk_score: number;
  probability: number;
  threshold: number;
  latency_ms: number;
  model: string;
  explanation_method: string;
  attributions: Attribution[];
  analyst_summary: string;
  recommendations: string[];
  llm_enabled: boolean;
  timestamp: string;
  flow?: FlowFeatures;
  source?: "manual" | "live";
}

export interface LiveStatus {
  running: boolean;
  method: string | null;
  interface: string | null;
  started_at: string | null;
  packets_seen: number;
  active_flows: number;
  flows_scored: number;
  flows_dropped: number;
  error: string | null;
}

export interface LiveFeedResponse {
  status: LiveStatus;
  items: DetectionResponse[];
}

export interface BatchDetectionResponse {
  dataset: DatasetName;
  total_rows: number;
  flagged: number;
  detections: DetectionResponse[];
}

export interface HealthResponse {
  status: "ok" | "training";
  model: string | null;
  threshold: number | null;
  datasets: DatasetName[];
  llm_calls_remaining: number;
}

export interface ModelMetrics {
  radiant_boost: {
    accuracy: number;
    f1_macro: number;
    precision: number;
    recall: number;
    roc_auc: number;
    threshold: number;
    train_seconds: number;
    single_flow_latency_ms: number;
    gb_best_params: Record<string, number>;
    xgb_best_params: Record<string, number>;
    gb_cv_roc_auc: number;
    xgb_cv_roc_auc: number;
  };
  random_forest_baseline: {
    accuracy: number;
    precision: number;
    recall: number;
    roc_auc: number;
    cv_roc_auc: number;
  };
  fast_path_ensemble: {
    accuracy: number;
    recall: number;
    precision: number;
  };
  class_balance: { benign: number; malicious: number };
  using_real_data: boolean;
  generalization: {
    iscx_vpn: {
      task: string;
      roc_auc: number;
      accuracy: number;
      recall: number;
      using_real_data: boolean;
    };
    caida: {
      task: string;
      flagged_fraction: number;
      outlier_fraction_dbscan: number;
      using_real_data: boolean;
    };
  };
  trained_at: string;
  feature_count: number;
}

export interface ImportanceItem {
  feature: string;
  mean_abs_shap: number;
}

export interface ClusterPoint {
  x: number;
  y: number;
  cluster: number;
  outlier: boolean;
}

export interface ClusterSnapshot {
  points: ClusterPoint[];
  outlier_fraction: number;
  n_clusters: number;
  dbscan_eps: number;
  kmeans_inertia: number;
  explained_variance: number[];
}

export interface DatasetInfo {
  name: DatasetName;
  description: string;
  using_real_data: boolean;
}

export interface DatasetPreview {
  columns: string[];
  rows: Record<string, string | number | boolean>[];
}

export interface ThreatLogStats {
  total: number;
  by_verdict: Record<Verdict, number>;
  by_protocol: Record<string, number>;
  top_sources: [string, number][];
}

export interface ThreatLogResponse {
  items: DetectionResponse[];
  stats: ThreatLogStats;
}
