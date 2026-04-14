import axios from "axios";

const BASE = import.meta.env.VITE_API_URL ?? "";

export const api = axios.create({ baseURL: BASE });

export interface Assessment {
  id: string;
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
