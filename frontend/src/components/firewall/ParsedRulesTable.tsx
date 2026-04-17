import { useState } from "react";
import { CheckCircle, AlertTriangle, Search } from "lucide-react";
import type { FirewallUpload, FirewallRule } from "../../api";

interface Props {
  upload: FirewallUpload;
  rules: FirewallRule[];
  onContinue: () => void;
}

const ACTION_COLORS: Record<string, string> = {
  permit: "bg-green-100 text-green-700",
  deny: "bg-red-100 text-red-700",
};

export default function ParsedRulesTable({ upload, rules, onContinue }: Props) {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 25;

  const filtered = rules.filter((r) => {
    const q = search.toLowerCase();
    return (
      !q ||
      (r.policy_id || "").includes(q) ||
      (r.name || "").toLowerCase().includes(q) ||
      r.src_addrs.some((a) => a.toLowerCase().includes(q)) ||
      r.dst_addrs.some((a) => a.toLowerCase().includes(q)) ||
      r.services.some((s) => s.toLowerCase().includes(q))
    );
  });

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const page_rules = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold">Step 2 — Review Parsed Rules</h2>
        <p className="text-sm text-gray-500 mt-1">
          {rules.length} rules parsed from <span className="font-medium">{upload.filename}</span>
          {" "}(vendor: <span className="font-mono text-xs">{upload.vendor}</span>).
          Review before proceeding.
        </p>
      </div>

      {upload.parse_errors.length > 0 && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3 flex gap-2 text-sm text-yellow-800">
          <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <div>
            <p className="font-medium">{upload.parse_errors.length} parse warning(s)</p>
            <ul className="list-disc list-inside text-xs mt-1 space-y-0.5">
              {upload.parse_errors.slice(0, 5).map((e, i) => <li key={i}>{e}</li>)}
              {upload.parse_errors.length > 5 && <li>…and {upload.parse_errors.length - 5} more</li>}
            </ul>
          </div>
        </div>
      )}

      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search by rule ID, name, IP, or service…"
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(0); }}
            className="w-full pl-9 pr-3 py-2 text-sm border rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-400"
          />
        </div>
        <span className="text-xs text-gray-400">{filtered.length} rules</span>
      </div>

      <div className="overflow-x-auto rounded-xl border">
        <table className="min-w-full text-xs divide-y divide-gray-100">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-3 py-2 text-left font-medium text-gray-500 w-12">#</th>
              <th className="px-3 py-2 text-left font-medium text-gray-500">Name</th>
              <th className="px-3 py-2 text-left font-medium text-gray-500">Src Intf</th>
              <th className="px-3 py-2 text-left font-medium text-gray-500">Src Intf Subnet</th>
              <th className="px-3 py-2 text-left font-medium text-gray-500">Src Addr IP</th>
              <th className="px-3 py-2 text-left font-medium text-gray-500">Dst Intf</th>
              <th className="px-3 py-2 text-left font-medium text-gray-500">Dst Addr IP</th>
              <th className="px-3 py-2 text-left font-medium text-gray-500">Services</th>
              <th className="px-3 py-2 text-left font-medium text-gray-500">Action</th>
              <th className="px-3 py-2 text-left font-medium text-gray-500">Comment</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100 bg-white">
            {page_rules.map((r) => {
              const srcIntfSubnet = r.src_intf ? (upload.interfaces?.[r.src_intf] ?? "—") : "—";
              return (
              <tr key={r.id} className="hover:bg-gray-50">
                <td className="px-3 py-1.5 font-mono text-gray-400">{r.policy_id}</td>
                <td className="px-3 py-1.5 text-gray-700 max-w-[120px] truncate" title={r.name ?? ""}>
                  {r.name || "—"}
                </td>
                <td className="px-3 py-1.5 font-mono text-gray-500">{r.src_intf || "—"}</td>
                <td className="px-3 py-1.5 font-mono text-blue-600">{srcIntfSubnet}</td>
                <td className="px-3 py-1.5">
                  <AddrList addrs={r.src_addrs} />
                </td>
                <td className="px-3 py-1.5 font-mono text-gray-500">{r.dst_intf || "—"}</td>
                <td className="px-3 py-1.5">
                  <AddrList addrs={r.dst_addrs} />
                </td>
                <td className="px-3 py-1.5">
                  <ServiceList services={r.services} />
                </td>
                <td className="px-3 py-1.5">
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${ACTION_COLORS[r.action] ?? "bg-gray-100 text-gray-600"}`}>
                    {r.action}
                  </span>
                </td>
                <td className="px-3 py-1.5 text-gray-400 max-w-[120px] truncate" title={r.comment ?? ""}>
                  {r.comment || "—"}
                </td>
              </tr>
              );
            })}
            {page_rules.length === 0 && (
              <tr>
                <td colSpan={9} className="px-3 py-8 text-center text-gray-400">No rules match your search.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className="flex justify-between items-center text-sm">
          <button
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            disabled={page === 0}
            className="px-3 py-1 rounded border disabled:opacity-40 hover:bg-gray-50"
          >
            Previous
          </button>
          <span className="text-gray-500">Page {page + 1} of {totalPages}</span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
            disabled={page >= totalPages - 1}
            className="px-3 py-1 rounded border disabled:opacity-40 hover:bg-gray-50"
          >
            Next
          </button>
        </div>
      )}

      <div className="flex justify-end">
        <button
          onClick={onContinue}
          className="flex items-center gap-2 bg-brand-700 text-white px-5 py-2 rounded-lg hover:bg-brand-800 transition font-medium"
        >
          <CheckCircle className="w-4 h-4" />
          Rules look good — Continue
        </button>
      </div>
    </div>
  );
}

function formatAddr(a: string): string {
  if (a === "0.0.0.0/0") return "any";
  if (a.startsWith("fqdn:")) {
    const rest = a.slice(5); // strip "fqdn:"
    if (rest.includes("|")) {
      const [host, ip] = rest.split("|", 2);
      return `${host} / ${ip}`;
    }
    return rest;
  }
  return a;
}

function AddrList({ addrs }: { addrs: string[] }) {
  if (addrs.length === 0) return <span className="text-gray-400">—</span>;
  const show = addrs.slice(0, 2);
  const more = addrs.length - 2;
  return (
    <div className="flex flex-wrap gap-0.5">
      {show.map((a, i) => (
        <span key={i} className="bg-blue-50 text-blue-700 px-1.5 py-0.5 rounded font-mono">
          {formatAddr(a)}
        </span>
      ))}
      {more > 0 && <span className="text-gray-400 text-xs">+{more}</span>}
    </div>
  );
}

function ServiceList({ services }: { services: string[] }) {
  if (services.length === 0) return <span className="text-gray-400">—</span>;
  const show = services.slice(0, 2);
  const more = services.length - 2;
  return (
    <div className="flex flex-wrap gap-0.5">
      {show.map((s, i) => (
        <span key={i} className={`px-1.5 py-0.5 rounded text-xs font-mono ${
          s.toUpperCase() === "ALL" ? "bg-red-50 text-red-600" : "bg-gray-100 text-gray-600"
        }`}>
          {s}
        </span>
      ))}
      {more > 0 && <span className="text-gray-400 text-xs">+{more}</span>}
    </div>
  );
}
