import type { ScopeNode } from "../../api";

interface Props {
  nodes: ScopeNode[];
  seeds: string[];
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

export default function ScopeSummary({ nodes, seeds }: Props) {
  const counts = nodes.reduce<Record<string, number>>((acc, n) => {
    acc[n.scope_status] = (acc[n.scope_status] ?? 0) + 1;
    return acc;
  }, {});

  const groups = Object.entries(STATUS_CONFIG).map(([status, cfg]) => ({
    status,
    ...cfg,
    items: nodes.filter((n) => n.scope_status === status),
  }));

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold">Scope Classification</h2>
        <p className="text-sm text-gray-500 mt-1">
          Based on {seeds.length} CDE seed{seeds.length !== 1 ? "s" : ""} and graph reachability.
          {" "}{nodes.length} network nodes discovered.
        </p>
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

      {/* Node lists */}
      <div className="space-y-3">
        {groups
          .filter((g) => g.items.length > 0)
          .map(({ status, label, bg, text, dot, description, items }) => (
            <details key={status} open={status === "cde" || status === "connected"}>
              <summary className={`flex items-center gap-2 px-4 py-2 rounded-lg cursor-pointer select-none ${bg} ${text} font-medium text-sm`}>
                <span className={`w-2 h-2 rounded-full ${dot} flex-shrink-0`} />
                {label} — {items.length} system{items.length !== 1 ? "s" : ""}
                <span className="ml-auto text-xs font-normal opacity-70">{description}</span>
              </summary>
              <div className="mt-1 pl-4">
                <div className="rounded-lg border overflow-hidden">
                  <table className="min-w-full text-xs divide-y divide-gray-100">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-3 py-1.5 text-left font-medium text-gray-500">IP / CIDR</th>
                        <th className="px-3 py-1.5 text-left font-medium text-gray-500">Interface</th>
                        <th className="px-3 py-1.5 text-left font-medium text-gray-500">Via Rules</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100 bg-white">
                      {items.map((node, i) => (
                        <tr key={i} className="hover:bg-gray-50">
                          <td className="px-3 py-1.5 font-mono font-medium">{node.ip}</td>
                          <td className="px-3 py-1.5 text-gray-500">{node.label || "—"}</td>
                          <td className="px-3 py-1.5 text-gray-400">
                            {node.rule_ids.length > 0
                              ? node.rule_ids.slice(0, 3).join(", ") +
                                (node.rule_ids.length > 3 ? ` +${node.rule_ids.length - 3}` : "")
                              : "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </details>
          ))}
      </div>
    </div>
  );
}
