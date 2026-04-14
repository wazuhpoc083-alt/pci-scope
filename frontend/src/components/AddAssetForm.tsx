import { useState } from "react";
import { assetsApi } from "../api";

interface Props {
  assessmentId: string;
  onSaved: () => void;
  onCancel: () => void;
}

const ASSET_TYPES = ["server", "database", "network_device", "workstation", "cloud_service", "other"];
const SCOPE_STATUSES = ["in_scope", "connected", "out_of_scope", "pending"];

export default function AddAssetForm({ assessmentId, onSaved, onCancel }: Props) {
  const [form, setForm] = useState({
    name: "",
    ip_address: "",
    hostname: "",
    asset_type: "server",
    scope_status: "pending",
    is_cde: false,
    stores_pan: false,
    processes_pan: false,
    transmits_pan: false,
    justification: "",
    segmentation_notes: "",
  });
  const [saving, setSaving] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    await assetsApi.create(assessmentId, {
      ...form,
      ip_address: form.ip_address || undefined,
      hostname: form.hostname || undefined,
      justification: form.justification || undefined,
      segmentation_notes: form.segmentation_notes || undefined,
    });
    onSaved();
  };

  return (
    <form onSubmit={handleSubmit} className="bg-white border rounded-xl p-6 mb-4 shadow-sm space-y-4">
      <h3 className="font-semibold">Add Asset</h3>
      <div className="grid grid-cols-3 gap-4">
        <div>
          <label className="block text-xs font-medium mb-1">Name *</label>
          <input required className="w-full border rounded-lg px-3 py-2 text-sm" value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Payment DB" />
        </div>
        <div>
          <label className="block text-xs font-medium mb-1">IP Address</label>
          <input className="w-full border rounded-lg px-3 py-2 text-sm" value={form.ip_address}
            onChange={(e) => setForm({ ...form, ip_address: e.target.value })} placeholder="10.0.1.5" />
        </div>
        <div>
          <label className="block text-xs font-medium mb-1">Hostname</label>
          <input className="w-full border rounded-lg px-3 py-2 text-sm" value={form.hostname}
            onChange={(e) => setForm({ ...form, hostname: e.target.value })} placeholder="pay-db-01.internal" />
        </div>
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs font-medium mb-1">Asset Type</label>
          <select className="w-full border rounded-lg px-3 py-2 text-sm" value={form.asset_type}
            onChange={(e) => setForm({ ...form, asset_type: e.target.value })}>
            {ASSET_TYPES.map((t) => <option key={t} value={t}>{t.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium mb-1">Scope Status</label>
          <select className="w-full border rounded-lg px-3 py-2 text-sm" value={form.scope_status}
            onChange={(e) => setForm({ ...form, scope_status: e.target.value })}>
            {SCOPE_STATUSES.map((s) => <option key={s} value={s}>{s.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}</option>)}
          </select>
        </div>
      </div>
      <div className="flex gap-6 text-sm">
        {(["is_cde", "stores_pan", "processes_pan", "transmits_pan"] as const).map((field) => (
          <label key={field} className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={form[field]} onChange={(e) => setForm({ ...form, [field]: e.target.checked })} />
            {field.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}
          </label>
        ))}
      </div>
      <div>
        <label className="block text-xs font-medium mb-1">Justification / Scoping rationale</label>
        <textarea className="w-full border rounded-lg px-3 py-2 text-sm" rows={2} value={form.justification}
          onChange={(e) => setForm({ ...form, justification: e.target.value })} />
      </div>
      <div>
        <label className="block text-xs font-medium mb-1">Segmentation Notes (out-of-scope assets)</label>
        <textarea className="w-full border rounded-lg px-3 py-2 text-sm" rows={2} value={form.segmentation_notes}
          onChange={(e) => setForm({ ...form, segmentation_notes: e.target.value })} />
      </div>
      <div className="flex gap-3">
        <button type="submit" disabled={saving}
          className="bg-brand-700 text-white px-5 py-2 rounded-lg hover:bg-brand-800 text-sm transition disabled:opacity-50">
          {saving ? "Saving…" : "Add Asset"}
        </button>
        <button type="button" onClick={onCancel} className="px-5 py-2 rounded-lg border text-sm hover:bg-gray-50 transition">
          Cancel
        </button>
      </div>
    </form>
  );
}
