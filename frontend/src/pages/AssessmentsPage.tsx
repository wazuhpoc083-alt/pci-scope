import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { PlusCircle, Trash2, ArrowRight } from "lucide-react";
import { assessmentsApi, authApi, type Assessment, type Tenant } from "../api";
import { useAuth } from "../AuthContext";

export default function AssessmentsPage() {
  const { claims } = useAuth();
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ name: "", organization: "", description: "", tenant_id: "" });
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [createError, setCreateError] = useState<string | null>(null);

  const load = () =>
    assessmentsApi.list().then((data) => {
      setAssessments(data);
      setLoading(false);
    }).catch(() => setLoading(false));

  useEffect(() => { load(); }, []);

  useEffect(() => {
    if (claims?.is_admin) {
      authApi.listTenants().then(setTenants).catch(console.error);
    }
  }, [claims?.is_admin]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateError(null);
    try {
      await assessmentsApi.create(form);
      setForm({ name: "", organization: "", description: "", tenant_id: "" });
      setShowForm(false);
      load();
    } catch (err: any) {
      setCreateError(err?.response?.data?.detail ?? "Failed to create assessment");
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Delete this assessment and all its assets?")) return;
    await assessmentsApi.delete(id);
    load();
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">Assessments</h1>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-2 bg-brand-700 text-white px-4 py-2 rounded-lg hover:bg-brand-800 transition"
        >
          <PlusCircle className="w-4 h-4" /> New Assessment
        </button>
      </div>

      {showForm && (
        <form onSubmit={handleCreate} className="bg-white border rounded-xl p-6 mb-6 shadow-sm space-y-4">
          <h2 className="font-semibold text-lg">New Assessment</h2>
          {claims?.is_admin && (
            <div>
              <label className="block text-sm font-medium mb-1">Tenant</label>
              {tenants.length === 0 ? (
                <p className="text-sm text-amber-600">No tenants yet. <Link to="/admin" className="underline">Create one first.</Link></p>
              ) : (
                <select
                  required
                  className="w-full border rounded-lg px-3 py-2 text-sm"
                  value={form.tenant_id}
                  onChange={(e) => setForm({ ...form, tenant_id: e.target.value })}
                >
                  <option value="">Select a tenant…</option>
                  {tenants.map((t) => (
                    <option key={t.id} value={t.id}>{t.name}</option>
                  ))}
                </select>
              )}
            </div>
          )}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-1">Assessment Name</label>
              <input
                required
                className="w-full border rounded-lg px-3 py-2 text-sm"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="Q2 2026 PCI DSS Scoping"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Organization</label>
              <input
                required
                className="w-full border rounded-lg px-3 py-2 text-sm"
                value={form.organization}
                onChange={(e) => setForm({ ...form, organization: e.target.value })}
                placeholder="Acme Bank Ltd"
              />
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Description (optional)</label>
            <textarea
              className="w-full border rounded-lg px-3 py-2 text-sm"
              rows={2}
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
          </div>
          {createError && (
            <p className="text-sm text-red-600">{createError}</p>
          )}
          <div className="flex gap-3">
            <button type="submit" className="bg-brand-700 text-white px-5 py-2 rounded-lg hover:bg-brand-800 text-sm transition">
              Create
            </button>
            <button type="button" onClick={() => setShowForm(false)} className="px-5 py-2 rounded-lg border text-sm hover:bg-gray-50 transition">
              Cancel
            </button>
          </div>
        </form>
      )}

      {loading ? (
        <p className="text-gray-500">Loading…</p>
      ) : assessments.length === 0 ? (
        <div className="text-center py-20 text-gray-400">
          <p className="text-lg">No assessments yet.</p>
          <p className="text-sm mt-1">Create one to start defining your PCI DSS scope.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {assessments.map((a) => (
            <div key={a.id} className="bg-white border rounded-xl p-5 shadow-sm flex items-center justify-between hover:shadow-md transition">
              <div>
                <p className="font-semibold">{a.name}</p>
                <p className="text-sm text-gray-500">{a.organization} · PCI DSS v{a.pci_dss_version}</p>
                {a.description && <p className="text-sm text-gray-400 mt-1">{a.description}</p>}
              </div>
              <div className="flex items-center gap-3">
                <button
                  onClick={() => handleDelete(a.id)}
                  className="text-gray-400 hover:text-red-500 transition"
                  title="Delete"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
                <Link
                  to={`/assessments/${a.id}`}
                  className="flex items-center gap-1 text-brand-700 hover:text-brand-800 font-medium text-sm"
                >
                  Open <ArrowRight className="w-4 h-4" />
                </Link>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
