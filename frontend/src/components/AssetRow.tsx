import { useState } from "react";
import { Trash2, ChevronDown, ChevronUp } from "lucide-react";
import { assetsApi, type Asset } from "../api";

const SCOPE_BADGE: Record<string, string> = {
  in_scope: "bg-red-100 text-red-700",
  connected: "bg-yellow-100 text-yellow-700",
  out_of_scope: "bg-green-100 text-green-700",
  pending: "bg-gray-100 text-gray-600",
};

const SCOPE_STATUSES = ["in_scope", "connected", "out_of_scope", "pending"];

interface Props {
  asset: Asset;
  onUpdated: () => void;
  onDeleted: () => void;
}

export default function AssetRow({ asset, onUpdated, onDeleted }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [updating, setUpdating] = useState(false);

  const handleScopeChange = async (scope_status: string) => {
    setUpdating(true);
    await assetsApi.update(asset.assessment_id, asset.id, { scope_status } as Partial<Asset>);
    onUpdated();
    setUpdating(false);
  };

  const handleDelete = async () => {
    if (!confirm(`Delete asset "${asset.name}"?`)) return;
    await assetsApi.delete(asset.assessment_id, asset.id);
    onDeleted();
  };

  return (
    <div className="bg-white border rounded-xl shadow-sm overflow-hidden">
      <div className="flex items-center px-5 py-4 gap-4">
        <div className="flex-1 min-w-0">
          <p className="font-medium truncate">{asset.name}</p>
          <p className="text-xs text-gray-400">
            {[asset.ip_address, asset.hostname].filter(Boolean).join(" · ") || "No address"} ·{" "}
            {asset.asset_type.replace(/_/g, " ")}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {asset.is_cde && (
            <span className="text-xs bg-red-50 text-red-600 border border-red-200 rounded px-2 py-0.5 font-mono">CDE</span>
          )}
          <select
            value={asset.scope_status}
            disabled={updating}
            onChange={(e) => handleScopeChange(e.target.value)}
            className={`text-xs font-medium rounded-full px-3 py-1 border-0 cursor-pointer ${SCOPE_BADGE[asset.scope_status]}`}
          >
            {SCOPE_STATUSES.map((s) => (
              <option key={s} value={s}>{s.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}</option>
            ))}
          </select>
          <button onClick={() => setExpanded(!expanded)} className="text-gray-400 hover:text-gray-600">
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
          <button onClick={handleDelete} className="text-gray-400 hover:text-red-500">
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>
      {expanded && (
        <div className="border-t px-5 py-3 bg-gray-50 text-sm space-y-1">
          <div className="flex gap-4 text-xs text-gray-500">
            {asset.stores_pan && <span>Stores PAN</span>}
            {asset.processes_pan && <span>Processes PAN</span>}
            {asset.transmits_pan && <span>Transmits PAN</span>}
          </div>
          {asset.justification && (
            <p><span className="font-medium">Justification:</span> {asset.justification}</p>
          )}
          {asset.segmentation_notes && (
            <p><span className="font-medium">Segmentation:</span> {asset.segmentation_notes}</p>
          )}
        </div>
      )}
    </div>
  );
}
