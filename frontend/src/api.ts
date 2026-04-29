import axios from "axios";

const BASE = (import.meta.env.VITE_API_URL ?? "").replace(/\/$/, "");

export const api = axios.create({ baseURL: BASE });

// Inject auth token on every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("auth_token");
  if (token) {
    config.headers = config.headers ?? {};
    config.headers["Authorization"] = `Bearer ${token}`;
  }
  return config;
});

// On 401, clear token and redirect to login
api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err?.response?.status === 401) {
      localStorage.removeItem("auth_token");
      window.location.href = "/login";
    }
    return Promise.reject(err);
  },
);

export interface Assessment {
  id: string;
  tenant_id: string;
  name: string;
  organization: string;
  pci_dss_version: string;
  description: string | null;
  is_finalized: boolean;
  created_at: string;
}

export interface Asset {
  id: string;
  assessment_id: string;
  name: string;
  ip_address: string | null;
  hostname: string | null;
  asset_type: string;
  scope_status: string;
  is_cde: boolean;
  stores_pan: boolean;
  processes_pan: boolean;
  transmits_pan: boolean;
  segmentation_notes: string | null;
  justification: string | null;
  tags: string[];
  created_at: string;
}

export interface Report {
  id: string;
  assessment_id: string;
  generated_at: string;
  summary: Record<string, number> | null;
  report_json: Record<string, unknown> | null;
}

export const assessmentsApi = {
  list: () => api.get<Assessment[]>("/api/assessments/").then((r) => r.data),
  create: (data: Partial<Assessment>) =>
    api.post<Assessment>("/api/assessments/", data).then((r) => r.data),
  get: (id: string) =>
    api.get<Assessment>(`/api/assessments/${id}`).then((r) => r.data),
  delete: (id: string) => api.delete(`/api/assessments/${id}`),
};

export const assetsApi = {
  list: (assessmentId: string) =>
    api.get<Asset[]>(`/api/assessments/${assessmentId}/assets/`).then((r) => r.data),
  create: (assessmentId: string, data: Partial<Asset>) =>
    api.post<Asset>(`/api/assessments/${assessmentId}/assets/`, data).then((r) => r.data),
  update: (assessmentId: string, assetId: string, data: Partial<Asset>) =>
    api
      .patch<Asset>(`/api/assessments/${assessmentId}/assets/${assetId}`, data)
      .then((r) => r.data),
  delete: (assessmentId: string, assetId: string) =>
    api.delete(`/api/assessments/${assessmentId}/assets/${assetId}`),
  csvTemplateUrl: (assessmentId: string) =>
    `${BASE}/api/assessments/${assessmentId}/assets/csv-template`,
  importCsv: (assessmentId: string, file: File) => {
    const form = new FormData();
    form.append("file", file);
    return api
      .post<Asset[]>(`/api/assessments/${assessmentId}/assets/csv-import`, form, {
        headers: { "Content-Type": "multipart/form-data" },
      })
      .then((r) => r.data);
  },
};

export const reportsApi = {
  generate: (assessmentId: string) =>
    api.post<Report>(`/api/assessments/${assessmentId}/reports/`).then((r) => r.data),
  list: (assessmentId: string) =>
    api.get<Report[]>(`/api/assessments/${assessmentId}/reports/`).then((r) => r.data),
  pdfUrl: (assessmentId: string, reportId: string) =>
    `${BASE}/api/assessments/${assessmentId}/reports/${reportId}/pdf`,
};

// ---------------------------------------------------------------------------
// Auth API
// ---------------------------------------------------------------------------

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  created_at: string;
}

export const authApi = {
  me: () => api.get("/api/auth/me").then((r) => r.data),
  listTenants: () => api.get<Tenant[]>("/api/auth/tenants").then((r) => r.data),
  createTenant: (data: { name: string; slug: string }) =>
    api.post<Tenant>("/api/auth/tenants", data).then((r) => r.data),
  issueToken: (tenant_id: string, expires_hours = 24) =>
    api
      .post<{ token: string; tenant_id: string; tenant_name: string; expires_hours: number }>(
        "/api/auth/tokens",
        { tenant_id, expires_hours },
      )
      .then((r) => r.data),
};

// ---------------------------------------------------------------------------
// Firewall Analysis
// ---------------------------------------------------------------------------

export interface FirewallUpload {
  id: string;
  assessment_id: string;
  filename: string;
  vendor: string;
  parse_errors: string[];
  rule_count: number;
  interfaces: Record<string, string>;
  created_at: string;
}

export interface FirewallRule {
  id: string;
  upload_id: string;
  policy_id: string | null;
  name: string | null;
  src_intf: string | null;
  dst_intf: string | null;
  src_addrs: string[];
  dst_addrs: string[];
  services: string[];
  action: string;
  nat: boolean;
  log_traffic: boolean;
  comment: string | null;
}

export interface ScopeNode {
  ip: string;
  scope_status: "cde" | "connected" | "security_providing" | "out_of_scope" | "unknown";
  rule_ids: string[];
  label: string;
  name?: string;
}

export interface GapFinding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  requirement: string;
  title: string;
  description: string;
  affected_rules: string[];
  remediation: string;
}

export interface ScopeQuestion {
  id: string;
  category: "cde_id" | "ambiguity" | "segmentation" | "missing_rule";
  text: string;
  rule_id: string | null;
  context: Record<string, unknown>;
}

export interface FirewallAnalysis {
  id: string;
  upload_id: string;
  assessment_id: string;
  cde_seeds: string[];
  scope_nodes: ScopeNode[];
  questions: ScopeQuestion[];
  answers: Record<string, string>;
  gap_findings: GapFinding[];
  created_at: string;
}

export const firewallApi = {
  upload: (assessmentId: string, file: File) => {
    const form = new FormData();
    form.append("file", file);
    return api
      .post<FirewallUpload>(`/api/assessments/${assessmentId}/firewall/upload`, form, {
        headers: { "Content-Type": "multipart/form-data" },
      })
      .then((r) => r.data);
  },
  listUploads: (assessmentId: string) =>
    api.get<FirewallUpload[]>(`/api/assessments/${assessmentId}/firewall/uploads`).then((r) => r.data),
  listRules: (assessmentId: string, uploadId: string) =>
    api
      .get<FirewallRule[]>(`/api/assessments/${assessmentId}/firewall/uploads/${uploadId}/rules`)
      .then((r) => r.data),
  analyze: (
    assessmentId: string,
    uploadId: string,
    cdeSeeds: string[],
    subnetClassifications?: Record<string, string>,
  ) =>
    api
      .post<FirewallAnalysis>(`/api/assessments/${assessmentId}/firewall/analyze`, {
        upload_id: uploadId,
        cde_seeds: cdeSeeds,
        subnet_classifications: subnetClassifications ?? {},
      })
      .then((r) => r.data),
  getAnalysis: (assessmentId: string) =>
    api.get<FirewallAnalysis>(`/api/assessments/${assessmentId}/firewall/analysis`).then((r) => r.data),
  submitAnswers: (assessmentId: string, answers: Record<string, string>) =>
    api
      .patch<FirewallAnalysis>(`/api/assessments/${assessmentId}/firewall/analysis/answers`, { answers })
      .then((r) => r.data),
  exportCsvUrl: (assessmentId: string) =>
    `${BASE}/api/assessments/${assessmentId}/firewall/export/csv`,
};
