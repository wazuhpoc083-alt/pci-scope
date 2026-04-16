import { useState } from "react";
import { Loader2, Info, Plus, Trash2 } from "lucide-react";
import type { FirewallUpload } from "../../api";

type SubnetStatus = "cde" | "connected" | "outofscope" | "pending";

interface SubnetRow {
  subnet: string;
  label: string;       // interface name or empty
  status: SubnetStatus;
  fromInterface: boolean;
}

const STATUS_OPTIONS: { value: SubnetStatus; label: string; color: string }[] = [
  { value: "cde", label: "CDE", color: "text-red-700 bg-red-50 border-red-300" },
  { value: "connected", label: "Connected", color: "text-orange-700 bg-orange-50 border-orange-300" },
  { value: "outofscope", label: "Out of Scope", color: "text-green-700 bg-green-50 border-green-300" },
  { value: "pending", label: "Pending", color: "text-gray-600 bg-gray-50 border-gray-300" },
];

interface Props {
  upload: FirewallUpload;
  onAnalyze: (cdeSeeds: string[], subnetClassifications: Record<string, string>) => void;
  loading: boolean;
}

function buildInitialRows(upload: FirewallUpload): SubnetRow[] {
  const interfaces = upload.interfaces ?? {};
  const rows: SubnetRow[] = Object.entries(interfaces)
    .filter(([, subnet]) => subnet && subnet !== "")
    .map(([intf, subnet]) => ({
      subnet,
      label: intf,
      status: "pending" as SubnetStatus,
      fromInterface: true,
    }));
  return rows;
}

function isValidCidr(value: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(value.trim());
}

export default function MarkSubnetsStep({ upload, onAnalyze, loading }: Props) {
  const [rows, setRows] = useState<SubnetRow[]>(() => buildInitialRows(upload));
  const [manualSubnet, setManualSubnet] = useState("");
  const [manualError, setManualError] = useState<string | null>(null);

  const updateStatus = (idx: number, status: SubnetStatus) => {
    setRows((prev) => prev.map((r, i) => (i === idx ? { ...r, status } : r)));
  };

  const addManual = () => {
    const trimmed = manualSubnet.trim();
    if (!trimmed) return;
    if (!isValidCidr(trimmed)) {
      setManualError("Invalid IP or CIDR (e.g. 10.1.2.0/24 or 192.168.1.10)");
      return;
    }
    const normalised = trimmed.includes("/") ? trimmed : `${trimmed}/32`;
    if (rows.some((r) => r.subnet === normalised)) {
      setManualError("This subnet is already in the list");
      return;
    }
    setRows((prev) => [...prev, { subnet: normalised, label: "", status: "pending", fromInterface: false }]);
    setManualSubnet("");
    setManualError(null);
  };

  const removeRow = (idx: number) => {
    setRows((prev) => prev.filter((_, i) => i !== idx));
  };

  const handleSubmit = () => {
    const cdeSeeds = rows
      .filter((r) => r.status === "cde")
      .map((r) => r.subnet);

    if (cdeSeeds.length === 0) {
      setManualError("Mark at least one subnet as CDE before running the analysis.");
      return;
    }

    const subnetClassifications: Record<string, string> = {};
    for (const r of rows) {
      subnetClassifications[r.subnet] = r.status;
    }

    onAnalyze(cdeSeeds, subnetClassifications);
  };

  const cdeCount = rows.filter((r) => r.status === "cde").length;

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold">Step 3 — Mark Subnets</h2>
        <p className="text-sm text-gray-500 mt-1">
          {rows.length > 0
            ? `${rows.length} interface subnet${rows.length !== 1 ? "s" : ""} discovered from the config.`
            : "No interfaces found in config."}{" "}
          Mark each subnet's role in your PCI DSS cardholder data environment.
        </p>
      </div>

      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 flex gap-2 text-sm text-blue-800">
        <Info className="w-4 h-4 mt-0.5 flex-shrink-0" />
        <div>
          <p className="font-medium">How to classify subnets</p>
          <ul className="text-xs mt-1 space-y-0.5 list-disc list-inside">
            <li><span className="font-semibold text-red-700">CDE</span> — stores, processes, or transmits cardholder data (PANs)</li>
            <li><span className="font-semibold text-orange-700">Connected</span> — has permitted traffic to/from CDE systems</li>
            <li><span className="font-semibold text-green-700">Out of Scope</span> — properly segmented, no CDE path</li>
            <li><span className="font-semibold text-gray-600">Pending</span> — not yet determined; scope engine will classify automatically</li>
          </ul>
        </div>
      </div>

      {rows.length > 0 ? (
        <div className="rounded-xl border overflow-hidden">
          <table className="min-w-full text-sm divide-y divide-gray-100">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-2 text-left font-medium text-gray-500">Interface</th>
                <th className="px-4 py-2 text-left font-medium text-gray-500">Subnet / CIDR</th>
                <th className="px-4 py-2 text-left font-medium text-gray-500">Classification</th>
                <th className="px-3 py-2 w-10" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 bg-white">
              {rows.map((row, idx) => (
                <tr key={idx} className="hover:bg-gray-50">
                  <td className="px-4 py-2 font-mono text-gray-600 text-xs">
                    {row.label || <span className="text-gray-400 italic">manual</span>}
                  </td>
                  <td className="px-4 py-2 font-mono font-medium text-gray-800 text-xs">{row.subnet}</td>
                  <td className="px-4 py-2">
                    <div className="flex gap-1 flex-wrap">
                      {STATUS_OPTIONS.map((opt) => (
                        <button
                          key={opt.value}
                          onClick={() => updateStatus(idx, opt.value)}
                          className={`px-2.5 py-1 rounded-full text-xs font-medium border transition ${
                            row.status === opt.value
                              ? opt.color
                              : "text-gray-400 bg-white border-gray-200 hover:border-gray-300"
                          }`}
                        >
                          {opt.label}
                        </button>
                      ))}
                    </div>
                  </td>
                  <td className="px-3 py-2 text-center">
                    {!row.fromInterface && (
                      <button
                        onClick={() => removeRow(idx)}
                        className="text-gray-300 hover:text-red-500 transition"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="rounded-xl border border-dashed border-gray-300 p-6 text-center text-sm text-gray-400">
          No interfaces detected in the uploaded config. Add subnets manually below.
        </div>
      )}

      {/* Manual subnet entry */}
      <div className="space-y-1">
        <p className="text-xs font-medium text-gray-500">Add subnet manually</p>
        <div className="flex gap-2 items-start">
          <div className="flex-1">
            <input
              type="text"
              value={manualSubnet}
              onChange={(e) => { setManualSubnet(e.target.value); setManualError(null); }}
              onKeyDown={(e) => { if (e.key === "Enter") addManual(); }}
              placeholder="e.g. 10.1.2.0/24 or 192.168.5.10"
              className={`w-full px-3 py-2 text-sm border rounded-lg focus:outline-none focus:ring-2 ${
                manualError ? "border-red-400 focus:ring-red-300" : "focus:ring-brand-400"
              }`}
            />
            {manualError && <p className="text-xs text-red-600 mt-0.5">{manualError}</p>}
          </div>
          <button
            onClick={addManual}
            className="flex items-center gap-1 px-3 py-2 text-sm border rounded-lg text-brand-700 border-brand-300 hover:bg-brand-50 transition font-medium"
          >
            <Plus className="w-4 h-4" /> Add
          </button>
        </div>
      </div>

      <div className="flex justify-between items-center">
        <p className="text-xs text-gray-400">
          {cdeCount > 0
            ? `${cdeCount} CDE subnet${cdeCount !== 1 ? "s" : ""} selected — scope engine will propagate outward`
            : "No CDE subnets selected yet"}
        </p>
        <button
          onClick={handleSubmit}
          disabled={loading || cdeCount === 0}
          className="flex items-center gap-2 bg-brand-700 text-white px-5 py-2 rounded-lg hover:bg-brand-800 disabled:opacity-50 transition font-medium"
        >
          {loading && <Loader2 className="w-4 h-4 animate-spin" />}
          Run Scope Analysis
        </button>
      </div>
    </div>
  );
}
