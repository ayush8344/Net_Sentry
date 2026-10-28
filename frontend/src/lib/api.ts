import type {
  BatchDetectionResponse,
  ClusterSnapshot,
  DatasetInfo,
  DatasetName,
  DatasetPreview,
  DetectionResponse,
  FlowFeatures,
  HealthResponse,
  ImportanceItem,
  LiveFeedResponse,
  LiveStatus,
  ModelMetrics,
  ThreatLogResponse,
} from "./types";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
    cache: "no-store",
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail ?? detail;
    } catch {
      // ignore
    }
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => request<HealthResponse>("/api/health"),

  modelMetrics: () => request<ModelMetrics>("/api/model/metrics"),

  modelImportance: () => request<ImportanceItem[]>("/api/model/importance"),

  clusters: (dataset: DatasetName) =>
    request<ClusterSnapshot>(`/api/clusters?dataset=${dataset}`),

  datasets: () => request<DatasetInfo[]>("/api/datasets"),

  datasetPreview: (dataset: DatasetName, n = 10) =>
    request<DatasetPreview>(`/api/datasets/${dataset}/preview?n=${n}`),

  detect: (dataset: DatasetName, flow: FlowFeatures) =>
    request<DetectionResponse>("/api/detect", {
      method: "POST",
      body: JSON.stringify({ dataset, flow }),
    }),

  detectBatch: async (dataset: DatasetName, file: File): Promise<BatchDetectionResponse> => {
    const form = new FormData();
    form.append("file", file);
    const res = await fetch(`/api/detect/batch?dataset=${dataset}`, {
      method: "POST",
      body: form,
      cache: "no-store",
    });
    if (!res.ok) {
      let detail = res.statusText;
      try {
        const body = await res.json();
        detail = body.detail ?? detail;
      } catch {
        // ignore
      }
      throw new Error(`${res.status}: ${detail}`);
    }
    return res.json();
  },

  threatLog: (params: { limit?: number; verdict?: string; dataset?: string } = {}) => {
    const search = new URLSearchParams();
    if (params.limit) search.set("limit", String(params.limit));
    if (params.verdict) search.set("verdict", params.verdict);
    if (params.dataset) search.set("dataset", params.dataset);
    return request<ThreatLogResponse>(`/api/threat-log?${search.toString()}`);
  },

  exportThreatLogUrl: () => "/api/threat-log/export",

  retrain: () => request<{ status: string }>("/api/train", { method: "POST" }),

  liveFeed: (limit = 100) => request<LiveFeedResponse>(`/api/live/feed?limit=${limit}`),

  liveStart: () => request<LiveStatus>("/api/live/start", { method: "POST" }),

  liveStop: () => request<LiveStatus>("/api/live/stop", { method: "POST" }),
};
