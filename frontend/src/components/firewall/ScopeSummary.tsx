import { useState } from "react";
import { assetsApi } from "../../api";
import type { ScopeNode, Asset } from "../../api";

interface Props {
  nodes: ScopeNode[];
  seeds: string[];
  assessmentId: string;
}

const STATUS_CONFIG: Record<
  string,
  { label: string; bg: string; text: string; dot: string; description: string }
> = {
  cde: {
    label: "CDE",
    bg: "bg-red-50",
    text: "text-red-700",
    dot: "bg-red-500",
    description: "Stores, processes, or transmits cardholder data",
  },
  connected: {
    label: "Connected",
    bg: "bg-orange-50",
    text: "text-orange-700",
    dot: "bg-orange-500",
    description: "Has permitted traffic path to/from CDE",
  },
  security_providing: {
    label: "Security",
    bg: "bg-blue-50",
    text: "text-blue-700",
    dot: "bg-blue-500",
    description: "Provides security services (auth, DNS, NTP, logging) to CDE",
  },
  out_of_scope: {
    label: "Out of Scope",
    bg: "bg-green-50",
    text: "text-green-700",
    dot: "bg-green-500",
    description: "No permitted path to CDE — properly segmented",
  },
  unknown: {
    label: "Unknown",
    bg: "bg-gray-50",
    text: "text-gray-600",
    dot: "bg-gray-400",
    description: "Discovered in rules but not yet classified",
  },
};

const SCOPE_STATUS_MAP: Record<string, string> = {
  cde: "in_scope",
  connected: "connected",
  security_providing: "in_scope",
  out_of_scope: "out_of_scope",
  unknown: "pending",
};

function scopeNodeToAsset(node: ScopeNode): Partial<Asset> {
  const isFqdn = node.ip.startsWith("fqdn:");
  const fqdnHost = isFqdn ? node.ip.slice(5) : null;
  const ipAddr = isFqdn ? null : node.ip;
  const name = node.name || node.label || (isFqdn ? fqdnHost! : node.ip);

  return {
    name,
    ip_address: ipAddr ?? undefined,
    hostname: fqdnHost ?? undefined,
    asset_type: "server",
    scope_status: SCOPE_STATUS_MAP[node.scope_status] ?? "pending",
    is_cde: node.scope_status === "cde",
    tags: ["firewall-analysis"],
  };
}

export default function ScopeSummary({ nodes, seeds, assessmentId }: Props) {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [adding, setAdding] = useState(false);
  const [addResult, setAddResult] = useState<{ count: number } | null>(null);
  const [addError, setAddError] = useState<string | null>(null);

  const groups = Object.entries(STATUS_CONFIG).map(([status, cfg]) => ({
    status,
    ...cfg,
    items: nodes.filter((n) => n.scope_status === status),
  }));

  function toggleOne(ip: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(ip)) next.delete(ip);
      else next.add(ip);
      return next;
    });
  }

  function toggleGroup(items: ScopeNode[]) {
    const allIn = items.every((n) => selected.has(n.ip));
    setSelected((prev) => {
      const next = new Set(prev);
      if (allIn) items.forEach((n) => next.delete(n.ip));
      else items.forEach((n) => next.add(n.ip));
      return next;
    });
  }

  function toggleAll() {
    if (selected.size === nodes.length) setSelected(new Set());
    else setSelected(new Set(nodes.map((n) => n.ip)));
  }

  async function handleAddToAssets() {
    setAdding(true);
    setAddError(null);
    try {
      const selectedNodes = nodes.filter((n) => selected.has(n.ip));
      const payloads = selectedNodes.map(scopeNodeToAsset);
      const created = await assetsApi.bulkCreate(assessmentId, payloads);
      setSelected(new Set());
      setAddResult({ count: created.length });
    } catch (err: unknown) {
      const msg =
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
        "Failed to add assets. Please try again.";
      setAddError(msg);
    } finally {
      setAdding(false);
    }
  }

  const allSelected = nodes.length > 0 && selected.size === nodes.length;
  const someSelected = selected.size > 0 && selected.size < nodes.length;

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold">Scope Classification</h2>
          <p className="text-sm text-gray-500 mt-1">
            Based on {seeds.length} CDE seed{seeds.length !== 1 ? "s" : ""} and graph reachability.
            {" "}{nodes.length} network nodes discovered.
          </p>
        </div>
        {nodes.length > 0 && (
          <button
            onClick={toggleAll}
            className="shrink-0 text-xs text-gray-500 hover:text-gray-700 underline underline-offset-2 mt-1"
          >
            {allSelected ? "Deselect all" : "Select all"}
          </button>
        )}
      </div>

      {/* Summary badges */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
        {groups.map(({ status, label, bg, text, items }) => (
          <div key={status} className={`rounded-xl p-3 text-center ${bg}`}>
            <p className={`text-xl font-bold ${text}`}>{items.length}</p>
            <p className={`text-xs font-medium mt-0.5 ${text}`}>{label}</p>
          </div>
        ))}
      </div>

      {/* Success / error banners */}
      {addResult && (
        <div className="flex items-center justify-between rounded-lg bg-green-50 border border-green-200 px-4 py-2.5 text-sm text-green-700">
          <span>
            ✓ {addResult.count} asset{addResult.count !== 1 ? "s" : ""} added — switch to the
            <strong> Assets</strong> tab to review.
          </span>
          <button
            onClick={() => setAddResult(null)}
            className="ml-4 text-green-500 hover:text-green-700 font-medium"
          >
            ×
          </button>
        </div>
      )}
      {addError && (
        <div className="flex items-center justify-between rounded-lg bg-red-50 border border-red-200 px-4 py-2.5 text-sm text-red-700">
          <span>{addError}</span>
          <button
            onClick={() => setAddError(null)}
            className="ml-4 text-red-400 hover:text-red-600 font-medium"
          >
            ×
          </button>
        </div>
      )}

      {/* Node lists */}
      <div className="space-y-3">
        {groups
          .filter((g) => g.items.length > 0)
          .map(({ status, label, bg, text, dot, description, items }) => {
            const groupAllSelected = items.every((n) => selected.has(n.ip));
            const groupSomeSelected = items.some((n) => selected.has(n.ip)) && !groupAllSelected;
            return (
              <details key={status} open={status === "cde" || status === "connected"}>
                <summary
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg cursor-pointer select-none ${bg} ${text} font-medium text-sm`}
                >
                  {/* Group select-all checkbox */}
                  <input
                    type="checkbox"
                    checked={groupAllSelected}
                    ref={(el) => { if (el) el.indeterminate = groupSomeSelected; }}
                    onChange={(e) => { e.stopPropagation(); toggleGroup(items); }}
                    onClick={(e) => e.stopPropagation()}
                    className="w-3.5 h-3.5 rounded accent-current cursor-pointer flex-shrink-0"
                    title={`Select all ${label} nodes`}
                  />
                  <span className={`w-2 h-2 rounded-full ${dot} flex-shrink-0`} />
                  {label} — {items.length} system{items.length !== 1 ? "s" : ""}
                  <span className="ml-auto text-xs font-normal opacity-70">{description}</span>
                </summary>
                <div className="mt-1 pl-4">
                  <div className="rounded-lg border overflow-hidden">
                    <table className="min-w-full text-xs divide-y divide-gray-100">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-2 py-1.5 w-8">
                            <input
                              type="checkbox"
                              checked={groupAllSelected}
                              ref={(el) => { if (el) el.indeterminate = groupSomeSelected; }}
                              onChange={() => toggleGroup(items)}
                              className="w-3.5 h-3.5 rounded accent-gray-600 cursor-pointer"
                            />
                          </th>
                          <th className="px-3 py-1.5 text-left font-medium text-gray-500">IP / CIDR</th>
                          <th className="px-3 py-1.5 text-left font-medium text-gray-500">Interface</th>
                          <th className="px-3 py-1.5 text-left font-medium text-gray-500">Via Rules</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-100 bg-white">
                        {items.map((node, i) => {
                          const isFqdn = node.ip.startsWith("fqdn:");
                          const displayIp = isFqdn ? node.ip.slice(5) : node.ip;
                          const showName = !isFqdn && node.name && node.name !== node.ip;
                          const isChecked = selected.has(node.ip);
                          return (
                            <tr
                              key={i}
                              className={`hover:bg-gray-50 cursor-pointer ${isChecked ? "bg-blue-50/40" : ""}`}
                              onClick={() => toggleOne(node.ip)}
                            >
                              <td className="px-2 py-1.5" onClick={(e) => e.stopPropagation()}>
                                <input
                                  type="checkbox"
                                  checked={isChecked}
                                  onChange={() => toggleOne(node.ip)}
                                  className="w-3.5 h-3.5 rounded accent-blue-600 cursor-pointer"
                                />
                              </td>
                              <td className="px-3 py-1.5 font-mono font-medium">
                                {displayIp}
                                {showName && (
                                  <span className="ml-1 text-gray-400 font-normal text-xs">({node.name})</span>
                                )}
                              </td>
                              <td className="px-3 py-1.5 text-gray-500">{node.label || "—"}</td>
                              <td className="px-3 py-1.5 text-gray-400">
                                {node.rule_ids.length > 0
                                  ? node.rule_ids.slice(0, 3).join(", ") +
                                    (node.rule_ids.length > 3 ? ` +${node.rule_ids.length - 3}` : "")
                                  : "—"}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              </details>
            );
          })}
      </div>

      {/* Sticky action bar — visible when nodes are selected */}
      {selected.size > 0 && (
        <div className="sticky bottom-4 z-10 flex items-center justify-between rounded-xl border border-blue-200 bg-white/95 backdrop-blur shadow-lg px-4 py-3">
          <div className="flex items-center gap-3 text-sm text-gray-700">
            <input
              type="checkbox"
              checked={allSelected}
              ref={(el) => { if (el) el.indeterminate = someSelected; }}
              onChange={toggleAll}
              className="w-4 h-4 rounded accent-blue-600 cursor-pointer"
            />
            <span>
              <strong>{selected.size}</strong> node{selected.size !== 1 ? "s" : ""} selected
            </span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setSelected(new Set())}
              className="text-xs text-gray-400 hover:text-gray-600 px-2 py-1"
            >
              Clear
            </button>
            <button
              onClick={handleAddToAssets}
              disabled={adding}
              className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 disabled:opacity-60 text-white text-sm font-medium px-4 py-1.5 transition"
            >
              {adding ? (
                <>
                  <svg className="animate-spin h-3.5 w-3.5" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                  </svg>
                  Adding…
                </>
              ) : (
                <>Add {selected.size} as Assets →</>
              )}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
