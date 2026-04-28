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

const ZONE_STYLE: Record<string, string> = {
  cde: "fill:#fee2e2,stroke:#dc2626,color:#7f1d1d",
  connected: "fill:#fed7aa,stroke:#ea580c,color:#7c2d12",
  security_providing: "fill:#dbeafe,stroke:#2563eb,color:#1e3a8a",
  out_of_scope: "fill:#dcfce7,stroke:#16a34a,color:#14532d",
  unknown: "fill:#f3f4f6,stroke:#9ca3af,color:#374151",
};

const PORT_LABELS: Record<string, string> = {
  "tcp/80": "HTTP",
  "tcp/443": "HTTPS",
  "tcp/8080": "HTTP",
  "tcp/8443": "HTTPS",
  "tcp/22": "SSH",
  "tcp/23": "Telnet⚠",
  "tcp/21": "FTP⚠",
  "tcp/20": "FTP⚠",
  "tcp/69": "TFTP⚠",
  "udp/69": "TFTP⚠",
  "tcp/3306": "MySQL",
  "tcp/5432": "PostgreSQL",
  "tcp/1433": "MSSQL",
  "tcp/1521": "Oracle",
  "tcp/389": "LDAP",
  "tcp/636": "LDAPS",
  "tcp/88": "Kerberos",
  "udp/88": "Kerberos",
  "udp/53": "DNS",
  "tcp/53": "DNS",
  "udp/123": "NTP",
  "udp/514": "Syslog",
  "tcp/514": "Syslog",
  "tcp/6514": "Syslog",
  "udp/161": "SNMP",
  "udp/162": "SNMP",
  "tcp/25": "SMTP",
  "tcp/587": "SMTP",
  "tcp/3389": "RDP",
};

function serviceCategory(services: string[]): string {
  if (
    services.length === 0 ||
    services.some((s) => {
      const u = s.toUpperCase();
      return u === "ALL" || u === "ANY";
    })
  ) {
    return "All Traffic";
  }
  const unique = [...new Set(services.map((s) => s.toLowerCase()))];
  const labels = new Set<string>();
  unique.forEach((svc) => {
    const known = PORT_LABELS[svc];
    if (known) {
      labels.add(known);
    } else {
      const portMatch = svc.match(/\/(\d+(?:-\d+)?)$/);
      if (portMatch) labels.add(`port ${portMatch[1]}`);
      else labels.add(svc.toUpperCase());
    }
  });
  const arr = Array.from(labels);
  if (arr.length <= 3) return arr.join(", ");
  return `${arr.slice(0, 2).join(", ")} +${arr.length - 2} more`;
}

function isExternalZone(name: string): boolean {
  return /^(external|internet|wan|untrust|outside|dmz.?ext|inet)/i.test(name);
}

function zoneStatus(intfName: string, nodes: ScopeNode[]): keyof typeof ZONE_STYLE {
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

function nodeId(name: string) {
  return name.replace(/[^a-zA-Z0-9_]/g, "_");
}

function buildMermaid(
  interfaces: Record<string, string>,
  rules: FirewallRule[],
  nodes: ScopeNode[]
): string {
  // Build full zone list
  let allZones = Object.entries(interfaces);
  if (allZones.length === 0) {
    const intfs = new Set<string>();
    rules.forEach((r) => {
      if (r.src_intf && r.src_intf !== "any") intfs.add(r.src_intf);
      if (r.dst_intf && r.dst_intf !== "any") intfs.add(r.dst_intf);
    });
    intfs.forEach((i) => allZones.push([i, ""]));
  }

  // Map zone name → scope status
  const zoneStatusMap = new Map<string, string>();
  allZones.forEach(([name]) => {
    zoneStatusMap.set(name, zoneStatus(name, nodes));
  });

  // Collect permit-only edges; skip OOS/unknown ↔ OOS/unknown (irrelevant for PCI DSS)
  type EdgeInfo = { services: string[] };
  const edges = new Map<string, EdgeInfo>();

  rules.forEach((r) => {
    if (r.action !== "permit") return;
    const src = r.src_intf;
    const dst = r.dst_intf;
    if (!src || !dst || src === "any" || dst === "any") return;

    const srcStatus = zoneStatusMap.get(src) ?? "unknown";
    const dstStatus = zoneStatusMap.get(dst) ?? "unknown";
    const irrelevant = (s: string) => s === "out_of_scope" || s === "unknown";
    if (irrelevant(srcStatus) && irrelevant(dstStatus)) return;

    const key = `${src}→${dst}`;
    if (!edges.has(key)) edges.set(key, { services: [] });
    edges.get(key)!.services.push(...r.services);
  });

  // Active zones: appear in an edge OR are cde/connected/security_providing
  const activeZoneNames = new Set<string>();
  edges.forEach((_, key) => {
    const [src, dst] = key.split("→");
    activeZoneNames.add(src);
    activeZoneNames.add(dst);
  });
  allZones.forEach(([name]) => {
    const status = zoneStatusMap.get(name) ?? "unknown";
    if (status === "cde" || status === "connected" || status === "security_providing") {
      activeZoneNames.add(name);
    }
  });

  const activeZones = allZones.filter(([name]) => activeZoneNames.has(name));

  // Group by PCI tier
  const tiers: Record<string, Array<[string, string]>> = {
    cde: [],
    connected: [],
    security_providing: [],
    other: [],
  };
  activeZones.forEach(([name, cidr]) => {
    const status = zoneStatusMap.get(name) ?? "unknown";
    if (status === "cde") tiers.cde.push([name, cidr]);
    else if (status === "connected") tiers.connected.push([name, cidr]);
    else if (status === "security_providing") tiers.security_providing.push([name, cidr]);
    else tiers.other.push([name, cidr]);
  });

  const TIER_LABELS: Record<string, string> = {
    cde: "CDE — Cardholder Data Environment",
    connected: "Connected to CDE",
    security_providing: "Security and Management",
  };

  const lines: string[] = ["flowchart LR"];

  // Subgraphs for CDE, Connected, Security tiers
  (["cde", "connected", "security_providing"] as const).forEach((tier) => {
    const zones = tiers[tier];
    if (zones.length === 0) return;
    lines.push(`  subgraph ${tier}_tier["${TIER_LABELS[tier]}"]`);
    zones.forEach(([name, cidr]) => {
      const id = nodeId(name);
      const label = cidr ? `${name}\\n${cidr}` : name;
      lines.push(`    ${id}["${label}"]`);
    });
    lines.push("  end");
  });

  // Flat nodes for out-of-scope / unknown zones
  tiers.other.forEach(([name, cidr]) => {
    const id = nodeId(name);
    const label = cidr ? `${name}\\n${cidr}` : name;
    lines.push(`  ${id}["${label}"]`);
  });

  lines.push("");

  // Emit edges; track critical external→CDE connections
  let edgeIndex = 0;
  const criticalEdgeIndices: number[] = [];

  edges.forEach((info, key) => {
    const [src, dst] = key.split("→");
    const sid = nodeId(src);
    const did = nodeId(dst);
    const label = serviceCategory(info.services);
    const dstStatus = zoneStatusMap.get(dst) ?? "unknown";
    const isCritical = isExternalZone(src) && dstStatus === "cde";

    lines.push(`  ${sid} -->|"${label}"| ${did}`);
    if (isCritical) criticalEdgeIndices.push(edgeIndex);
    edgeIndex++;
  });

  lines.push("");

  // Style active zone nodes by scope status
  activeZones.forEach(([name]) => {
    const id = nodeId(name);
    const status = zoneStatusMap.get(name) ?? "unknown";
    const style = ZONE_STYLE[status] ?? ZONE_STYLE.unknown;
    lines.push(`  style ${id} ${style}`);
  });

  // Red thick border on critical external→CDE edges
  criticalEdgeIndices.forEach((idx) => {
    lines.push(`  linkStyle ${idx} stroke:#dc2626,stroke-width:3px`);
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
          Simplified PCI DSS segmentation view — zones grouped by scope tier, permit traffic only.
          Red edges indicate direct external access to CDE.
        </p>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-3 text-xs">
        {[
          { label: "CDE", bg: "bg-red-100", text: "text-red-700" },
          { label: "Connected to CDE", bg: "bg-orange-100", text: "text-orange-700" },
          { label: "Security Zone", bg: "bg-blue-100", text: "text-blue-700" },
          { label: "Out of Scope", bg: "bg-green-100", text: "text-green-700" },
          { label: "Unclassified", bg: "bg-gray-100", text: "text-gray-600" },
        ].map(({ label, bg, text }) => (
          <span
            key={label}
            className={`inline-flex items-center gap-1 px-2 py-1 rounded-full font-medium ${bg} ${text}`}
          >
            {label}
          </span>
        ))}
        <span className="inline-flex items-center gap-1 px-2 py-1 text-gray-500">
          → permitted &nbsp;{" "}
          <span className="font-semibold text-red-600">→</span> external→CDE (critical)
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
                        <span
                          className={`px-2 py-0.5 rounded-full text-xs font-medium ${cfg[status] ?? cfg.unknown}`}
                        >
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
