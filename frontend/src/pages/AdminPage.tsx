import { useEffect, useState } from "react";
import { useAuth } from "../AuthContext";
import { authApi, Tenant } from "../api";
import { Navigate } from "react-router-dom";

export default function AdminPage() {
  const { claims } = useAuth();
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [tokens, setTokens] = useState<Record<string, string>>({});
  const [issuing, setIssuing] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  if (!claims?.is_admin) {
    return <Navigate to="/assessments" replace />;
  }

  const load = () => authApi.listTenants().then(setTenants).catch(console.error);

  useEffect(() => { load(); }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateError(null);
    setCreating(true);
    try {
      await authApi.createTenant({ name, slug });
      setName("");
      setSlug("");
      await load();
    } catch (err: any) {
      setCreateError(err?.response?.data?.detail ?? "Failed to create tenant");
    } finally {
      setCreating(false);
    }
  };

  const handleIssueToken = async (tenantId: string) => {
    setIssuing(tenantId);
    try {
      const res = await authApi.issueToken(tenantId, 24);
      setTokens((prev) => ({ ...prev, [tenantId]: res.token }));
    } finally {
      setIssuing(null);
    }
  };

  const copyToken = (tenantId: string) => {
    navigator.clipboard.writeText(tokens[tenantId]);
    setCopied(tenantId);
    setTimeout(() => setCopied(null), 2000);
  };

  const autoSlug = (val: string) =>
    val.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

  return (
    <div className="max-w-2xl mx-auto py-8 space-y-8">
      <h1 className="text-2xl font-bold text-gray-900">Admin — Tenant Management</h1>

      {/* Create tenant */}
      <section className="bg-white rounded-xl border border-gray-200 p-6">
        <h2 className="text-lg font-semibold text-gray-800 mb-4">Create Tenant</h2>
        <form onSubmit={handleCreate} className="space-y-3">
          <div className="flex gap-3">
            <div className="flex-1">
              <label className="block text-xs font-medium text-gray-600 mb-1">Name</label>
              <input
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Acme Corp"
                value={name}
                onChange={(e) => {
                  setName(e.target.value);
                  setSlug(autoSlug(e.target.value));
                }}
                required
              />
            </div>
            <div className="flex-1">
              <label className="block text-xs font-medium text-gray-600 mb-1">Slug</label>
              <input
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="acme-corp"
                value={slug}
                onChange={(e) => setSlug(e.target.value)}
                required
              />
            </div>
          </div>
          {createError && (
            <p className="text-sm text-red-600">{createError}</p>
          )}
          <button
            type="submit"
            disabled={creating}
            className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
          >
            {creating ? "Creating…" : "Create Tenant"}
          </button>
        </form>
      </section>

      {/* Tenant list */}
      <section className="bg-white rounded-xl border border-gray-200 p-6">
        <h2 className="text-lg font-semibold text-gray-800 mb-4">
          Tenants ({tenants.length})
        </h2>
        {tenants.length === 0 ? (
          <p className="text-sm text-gray-400">No tenants yet.</p>
        ) : (
          <ul className="space-y-4">
            {tenants.map((t) => (
              <li key={t.id} className="border border-gray-100 rounded-lg p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <span className="font-medium text-gray-800">{t.name}</span>
                    <span className="ml-2 text-xs text-gray-400 font-mono">{t.slug}</span>
                  </div>
                  <button
                    onClick={() => handleIssueToken(t.id)}
                    disabled={issuing === t.id}
                    className="text-sm bg-gray-100 hover:bg-gray-200 disabled:opacity-50 text-gray-700 px-3 py-1 rounded-lg transition-colors"
                  >
                    {issuing === t.id ? "Generating…" : "Generate 24h Token"}
                  </button>
                </div>

                {tokens[t.id] && (
                  <div className="bg-gray-50 border border-gray-200 rounded-lg p-3 space-y-2">
                    <p className="text-xs text-gray-500">
                      Share this token with the tenant. It expires in 24 hours.
                    </p>
                    <div className="flex gap-2 items-start">
                      <code className="flex-1 text-xs break-all font-mono text-gray-700">
                        {tokens[t.id]}
                      </code>
                      <button
                        onClick={() => copyToken(t.id)}
                        className="text-xs bg-blue-600 hover:bg-blue-700 text-white px-2 py-1 rounded transition-colors shrink-0"
                      >
                        {copied === t.id ? "Copied!" : "Copy"}
                      </button>
                    </div>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
