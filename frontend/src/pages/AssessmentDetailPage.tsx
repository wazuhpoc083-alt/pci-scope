import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { PlusCircle, Download, RefreshCw } from "lucide-react";
import { assessmentsApi, assetsApi, reportsApi, type Assessment, type Asset, type Report } from "../api";
import AssetRow from "../components/AssetRow";
import AddAssetForm from "../components/AddAssetForm";

const SCOPE_COLORS: Record<string, string> = {
  in_scope: "bg-red-100 text-red-700",
  connected: "bg-yellow-100 text-yellow-700",
  out_of_scope: "bg-green-100 text-green-700",
  pending: "bg-gray-100 text-gray-600",
};

export default function AssessmentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [assessment, setAssessment] = useState<Assessment | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [showAddForm, setShowAddForm] = useState(false);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [activeTab, setActiveTab] = useState<"assets" | "reports">("assets");

  const loadAll = async () => {
    if (!id) return;
    const [a, ast, rpts] = await Promise.all([
      assessmentsApi.get(id),
      assetsApi.list(id),
      reportsApi.list(id),
    ]);
    setAssessment(a);
    setAssets(ast);
    setReports(rpts);
  };

  useEffect(() => { loadAll(); }, [id]);

  const handleGenerateReport = async () => {
    if (!id) return;
    setGeneratingReport(true);
    await reportsApi.generate(id);
    await loadAll();
    setActiveTab("reports");
    setGeneratingReport(false);
  };

  if (!assessment) return <p className="text-gray-500">Loading…</p>;

  const counts = {
    in_scope: assets.filter((a) => a.scope_status === "in_scope").length,
    connected: assets.filter((a) => a.scope_status === "connected").length,
    out_of_scope: assets.filter((a) => a.scope_status === "out_of_scope").length,
    pending: assets.filter((a) => a.scope_status === "pending").length,
  };

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold">{assessment.name}</h1>
        <p className="text-gray-500">{assessment.organization} · PCI DSS v{assessment.pci_dss_version}</p>
      </div>

      {/* Scope summary badges */}
      <div className="grid grid-cols-4 gap-3 mb-6">
        {(["in_scope", "connected", "out_of_scope", "pending"] as const).map((status) => (
          <div key={status} className={`rounded-xl p-4 text-center ${SCOPE_COLORS[status]}`}>
            <p className="text-2xl font-bold">{counts[status]}</p>
            <p className="text-xs font-medium capitalize mt-1">{status.replace(/_/g, " ")}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-4 border-b">
        {(["assets", "reports"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 text-sm font-medium capitalize border-b-2 transition ${
              activeTab === tab
                ? "border-brand-700 text-brand-700"
                : "border-transparent text-gray-500 hover:text-gray-700"
            }`}
          >
            {tab}
          </button>
        ))}
        <div className="flex-1 flex justify-end items-center gap-2 pb-1">
          {activeTab === "assets" && (
            <button
              onClick={() => setShowAddForm(!showAddForm)}
              className="flex items-center gap-1 text-sm text-brand-700 hover:text-brand-800 font-medium"
            >
              <PlusCircle className="w-4 h-4" /> Add Asset
            </button>
          )}
          <button
            onClick={handleGenerateReport}
            disabled={generatingReport || assets.length === 0}
            className="flex items-center gap-1 text-sm bg-brand-700 text-white px-3 py-1.5 rounded-lg hover:bg-brand-800 disabled:opacity-50 transition"
          >
            {generatingReport ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
            Generate Report
          </button>
        </div>
      </div>

      {activeTab === "assets" && (
        <>
          {showAddForm && id && (
            <AddAssetForm
              assessmentId={id}
              onSaved={() => { setShowAddForm(false); loadAll(); }}
              onCancel={() => setShowAddForm(false)}
            />
          )}
          {assets.length === 0 ? (
            <p className="text-center text-gray-400 py-16">No assets yet. Add your first asset above.</p>
          ) : (
            <div className="space-y-2">
              {assets.map((asset) => (
                <AssetRow
                  key={asset.id}
                  asset={asset}
                  onUpdated={loadAll}
                  onDeleted={loadAll}
                />
              ))}
            </div>
          )}
        </>
      )}

      {activeTab === "reports" && (
        <div className="space-y-3">
          {reports.length === 0 ? (
            <p className="text-center text-gray-400 py-16">No reports yet. Generate one above.</p>
          ) : (
            reports.map((r) => (
              <div key={r.id} className="bg-white border rounded-xl p-5 shadow-sm flex items-center justify-between">
                <div>
                  <p className="font-medium">Report — {new Date(r.generated_at).toLocaleString()}</p>
                  {r.summary && (
                    <p className="text-sm text-gray-500 mt-0.5">
                      {r.summary.in_scope} in-scope · {r.summary.connected} connected · {r.summary.out_of_scope} out-of-scope · {r.summary.total} total
                    </p>
                  )}
                </div>
                <a
                  href={reportsApi.pdfUrl(assessment.id, r.id)}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-1 text-brand-700 hover:text-brand-800 font-medium text-sm"
                >
                  <Download className="w-4 h-4" /> PDF
                </a>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}
