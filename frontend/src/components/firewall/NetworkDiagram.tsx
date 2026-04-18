import { useEffect, useRef, useState } from "react";
import mermaid from "mermaid";
import type { FirewallUpload, FirewallRule, ScopeNode } from "../../api";

interface Props {
  upload: FirewallUpload;
  rules: FirewallRule[];
  analysis: {
    scope_nodes: ScopeNode[];
    cde_seeds: string[];
  };
}

// Scope status → Mermaid style fill/stroke colours
const ZONE_STYLE: Record<string, string> = {
  cde: "fill:#fee2e2,stroke:#dc2626,color:#7f1d1d",
  connected: "fill:#fed7aa,stroke:#ea580c,color:#7c2d12",
  security_providing: "fill:#dbeafe,stroke:#2563eb,color:#1e3a8a",
  out_of_scope: "fill:#dcfce7,stroke:#16a34a,color:#14532d",
  unknown: "fill:#f3f4f6,stroke:#9ca3af,color:#374151",
};

// Determine the worst-case scope status for a zone based on nodes labelled with that interface
function zoneStatus(
  intfName: string,
  nodes: ScopeNode[]
): keyof typeof ZONE_STYLE {
  const priority = ["cde", "connected", "security_providing", "out_of_scope", "unknown"] as const;
  const matching = nodes.filter(
    (n) => n.label && n.label.toLowerCase() === intfName.toLowerCase()
  );
  if (matching.length === 0) return "unknown";
  for (const p of priority) {
    if (matching.some((n) => n.scope_status === p)) return p;
  }
  return "unknown";
}

// Sanitise an interface name to a valid Mermaid node id
function nodeId(name: string) {
  return name.replace(/[^a-zA-Z0-9_]/g, "_");
}

function buildMermaid(
  interfaces: Record<string, string>,
  rules: FirewallRule[],
  nodes: ScopeNode[]
): string {
  const zones = Object.entries(interfaces);

  if (zones.length === 0) {
    // Fallback: derive zones from rule interfaces
    const intfs = new Set<string>();
    rules.forEach((r) => {
      if (r.src_intf && r.src_intf !== "any") intfs.add(r.src_intf);
      if (r.dst_intf && r.dst_intf !== "any") intfs.add(r.dst_intf);
    });
    intfs.forEach((i) => zones.push([i, ""]));
  }

  // Aggregate edges: key = "srcIntf→dstIntf", value = {permit: string[], deny: string[]}
  type EdgeInfo = { permit: string[]; deny: string[] };
  const edges = new Map<string, EdgeInfo>();

  rules.forEach((r) => {
    const src = r.src_intf;
    const dst = r.dst_intf;
    if (!src || !dst || src === "any" || dst === "any") return;
    const key = `${src}→${dst}`;
    if (!edges.has(key)) edges.set(key, { permit: [], deny: [] });
    const info = edges.get(key)!;
    const svcLabel = r.services.slice(0, 2).join(", ") + (r.services.length > 2 ? "…" : "");
    if (r.action === "deny") {
      info.deny.push(svcLabel || "ALL");
    } else {
      info.permit.push(svcLabel || "ANY");
    }
  });

  const lines: string[] = ["flowchart LR"];

  // Node definitions
  zones.forEach(([name, cidr]) => {
    const id = nodeId(name);
    const label = cidr ? `${name}\\n${cidr}` : name;
    lines.push(`  ${id}["${label}"]`);
  });

  lines.push("");

  // Edge definitions
  edges.forEach((info, key) => {
    const [src, dst] = key.split("→");
    const sid = nodeId(src);
    const did = nodeId(dst);

    if (info.permit.length > 0) {
      const label = info.permit.slice(0, 2).join(", ") + (info.permit.length > 2 ? "…" : "");
      lines.push(`  ${sid} -->|"✓ ${label}"| ${did}`);
    }
    if (info.deny.length > 0) {
      const label = info.deny.slice(0, 2).join(", ") + (info.deny.length > 2 ? "…" : "");
      lines.push(`  ${sid} -. "✗ ${label}" .-> ${did}`);
    }
  });

  lines.push("");

  // Style nodes by scope status
  zones.forEach(([name]) => {
    const id = nodeId(name);
    const status = zoneStatus(name, nodes);
    const style = ZONE_STYLE[status] ?? ZONE_STYLE.unknown;
    lines.push(`  style ${id} ${style}`);
  });

  return lines.join("\n");
}

let diagramCounter = 0;

export default function NetworkDiagram({ upload, rules, analysis }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [svgHtml, setSvgHtml] = useState<string>("");

  useEffect(() => {
    mermaid.initialize({
      startOnLoad: false,
      theme: "base",
      flowchart: { curve: "basis", padding: 20 },
    });

    const definition = buildMermaid(upload.interfaces ?? {}, rules, analysis.scope_nodes);
    const id = `mermaid-net-${++diagramCounter}`;

    mermaid
      .render(id, definition)
      .then(({ svg }) => {
        setSvgHtml(svg);
        setError(null);
      })
      .catch((e) => {
        setError(String(e));
      });
  }, [upload, rules, analysis]);

  const zones = Object.entries(upload.interfaces ?? {});

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold">Network Diagram</h2>
        <p className="text-sm text-gray-500 mt-1">
          Zone-level view derived from firewall interfaces and policy rules. Colours reflect PCI DSS scope classification.
        </p>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-3 text-xs">
        {[
          { status: "cde", label: "CDE", bg: "bg-red-100", text: "text-red-700" },
          { status: "connected", label: "Connected to CDE", bg: "bg-orange-100", text: "text-orange-700" },
          { status: "security_providing", label: "Security Zone", bg: "bg-blue-100", text: "text-blue-700" },
          { status: "out_of_scope", label: "Out of Scope", bg: "bg-green-100", text: "text-green-700" },
          { status: "unknown", label: "Unclassified", bg: "bg-gray-100", text: "text-gray-600" },
        ].map(({ label, bg, text }) => (
          <span key={label} className={`inline-flex items-center gap-1 px-2 py-1 rounded-full font-medium ${bg} ${text}`}>
            {label}
          </span>
        ))}
        <span className="inline-flex items-center gap-1 px-2 py-1 text-gray-500">
          ✓ = permit &nbsp; ✗ = deny
        </span>
      </div>

      {error ? (
        <div className="rounded-lg bg-red-50 border border-red-200 p-4 text-sm text-red-700">
          <p className="font-medium">Diagram render error</p>
          <pre className="mt-1 text-xs whitespace-pre-wrap">{error}</pre>
        </div>
      ) : svgHtml ? (
        <div
          ref={containerRef}
          className="rounded-xl border bg-white p-4 overflow-x-auto"
          dangerouslySetInnerHTML={{ __html: svgHtml }}
        />
      ) : (
        <div className="rounded-xl border bg-gray-50 p-8 text-center text-sm text-gray-400 animate-pulse">
          Rendering diagram…
        </div>
      )}

      {/* Zone table */}
      {zones.length > 0 && (
        <details className="text-sm">
          <summary className="cursor-pointer text-gray-500 hover:text-gray-700 font-medium">
            Interface table ({zones.length} zones)
          </summary>
          <div className="mt-2 rounded-lg border overflow-hidden">
            <table className="min-w-full divide-y divide-gray-100 text-xs">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-3 py-2 text-left font-medium text-gray-500">Interface</th>
                  <th className="px-3 py-2 text-left font-medium text-gray-500">Subnet</th>
                  <th className="px-3 py-2 text-left font-medium text-gray-500">Scope</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 bg-white">
                {zones.map(([name, cidr]) => {
                  const status = zoneStatus(name, analysis.scope_nodes);
                  const cfg: Record<string, string> = {
                    cde: "text-red-700 bg-red-50",
                    connected: "text-orange-700 bg-orange-50",
                    security_providing: "text-blue-700 bg-blue-50",
                    out_of_scope: "text-green-700 bg-green-50",
                    unknown: "text-gray-600 bg-gray-50",
                  };
                  return (
                    <tr key={name}>
                      <td className="px-3 py-2 font-mono font-medium">{name}</td>
                      <td className="px-3 py-2 font-mono text-gray-500">{cidr || "—"}</td>
                      <td className="px-3 py-2">
                        <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${cfg[status] ?? cfg.unknown}`}>
                          {status.replace(/_/g, " ")}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </details>
      )}
    </div>
  );
}
