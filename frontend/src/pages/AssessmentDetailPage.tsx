import { useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { PlusCircle, Download, RefreshCw, Upload, FileDown } from "lucide-react";
import { assessmentsApi, assetsApi, reportsApi, type Assessment, type Asset, type Report } from "../api";
import AssetRow from "../components/AssetRow";
import AddAssetForm from "../components/AddAssetForm";
import FirewallAnalysis from "../components/firewall/FirewallAnalysis";

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
  const [activeTab, setActiveTab] = useState<"assets" | "firewall" | "reports">("assets");
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const csvInputRef = useRef<HTMLInputElement>(null);

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

  const handleCsvImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !id) return;
    setImporting(true);
    setImportError(null);
    try {
      await assetsApi.importCsv(id, file);
      await loadAll();
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
      if (detail && typeof detail === "object" && "errors" in detail) {
        setImportError((detail as { errors: string[] }).errors.join("\n"));
      } else if (typeof detail === "string") {
        setImportError(detail);
      } else {
        setImportError("Import failed. Please check your CSV and try again.");
      }
    } finally {
      setImporting(false);
      if (csvInputRef.current) csvInputRef.current.value = "";
    }
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
        {(["assets", "firewall", "reports"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 text-sm font-medium capitalize border-b-2 transition ${
              activeTab === tab
                ? "border-brand-700 text-brand-700"
                : "border-transparent text-gray-500 hover:text-gray-700"
            }`}
          >
            {tab === "firewall" ? "Firewall Analysis" : tab}
          </button>
        ))}
        <div className="flex-1 flex justify-end items-center gap-2 pb-1">
          {activeTab === "assets" && (
            <>
              <a
                href={id ? assetsApi.csvTemplateUrl(id) : "#"}
                download="assets_template.csv"
                className="flex items-center gap-1 text-sm text-gray-600 hover:text-gray-800 font-medium"
              >
                <FileDown className="w-4 h-4" /> Template
              </a>
              <label className="flex items-center gap-1 text-sm text-gray-600 hover:text-gray-800 font-medium cursor-pointer">
                {importing ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />}
                Import CSV
                <input
                  ref={csvInputRef}
                  type="file"
                  accept=".csv"
                  className="hidden"
                  onChange={handleCsvImport}
                  disabled={importing}
                />
              </label>
              <button
                onClick={() => setShowAddForm(!showAddForm)}
                className="flex items-center gap-1 text-sm text-brand-700 hover:text-brand-800 font-medium"
              >
                <PlusCircle className="w-4 h-4" /> Add Asset
              </button>
            </>
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
          {importError && (
            <div className="mb-4 bg-red-50 border border-red-200 rounded-xl p-4">
              <p className="text-sm font-semibold text-red-700 mb-1">Import failed</p>
              <pre className="text-xs text-red-600 whitespace-pre-wrap">{importError}</pre>
              <button
                onClick={() => setImportError(null)}
                className="mt-2 text-xs text-red-500 underline"
              >
                Dismiss
              </button>
            </div>
          )}
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

      {activeTab === "firewall" && id && (
        <FirewallAnalysis assessmentId={id} />
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
