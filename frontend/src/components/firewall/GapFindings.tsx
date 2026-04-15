import { Download, CheckCircle, ShieldAlert, AlertTriangle, Info, XCircle } from "lucide-react";
import type { GapFinding } from "../../api";

interface Props {
  findings: GapFinding[];
  exportUrl: string;
}

const SEVERITY_CONFIG: Record<string, { icon: React.FC<{ className?: string }>; bg: string; text: string; border: string; label: string }> = {
  critical: { icon: XCircle, bg: "bg-red-50", text: "text-red-700", border: "border-red-200", label: "Critical" },
  high: { icon: ShieldAlert, bg: "bg-orange-50", text: "text-orange-700", border: "border-orange-200", label: "High" },
  medium: { icon: AlertTriangle, bg: "bg-yellow-50", text: "text-yellow-700", border: "border-yellow-200", label: "Medium" },
  low: { icon: Info, bg: "bg-blue-50", text: "text-blue-700", border: "border-blue-200", label: "Low" },
  info: { icon: Info, bg: "bg-gray-50", text: "text-gray-600", border: "border-gray-200", label: "Info" },
};

export default function GapFindings({ findings, exportUrl }: Props) {
  const criticals = findings.filter((f) => f.severity === "critical").length;
  const highs = findings.filter((f) => f.severity === "high").length;

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold">Gap Analysis Results</h2>
          <p className="text-sm text-gray-500 mt-1">
            PCI DSS v4.0 Req 1.2–1.5 checks.{" "}
            {findings.length === 0 ? (
              "No gaps found."
            ) : (
              <>
                {criticals > 0 && <span className="text-red-600 font-medium">{criticals} critical</span>}
                {criticals > 0 && highs > 0 && ", "}
                {highs > 0 && <span className="text-orange-600 font-medium">{highs} high</span>}
                {(criticals > 0 || highs > 0) && " findings require immediate attention."}
              </>
            )}
          </p>
        </div>
        <a
          href={exportUrl}
          download="pci_scope_analysis.csv"
          className="flex items-center gap-1.5 text-sm font-medium text-brand-700 hover:text-brand-800 border border-brand-200 rounded-lg px-3 py-2 hover:bg-brand-50 transition flex-shrink-0"
        >
          <Download className="w-4 h-4" /> Export CSV
        </a>
      </div>

      {findings.length === 0 ? (
        <div className="flex flex-col items-center gap-2 py-12 text-green-600">
          <CheckCircle className="w-10 h-10" />
          <p className="text-sm font-medium">No gap findings — all checked rules passed.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {["critical", "high", "medium", "low", "info"].map((sev) => {
            const sevFindings = findings.filter((f) => f.severity === sev);
            if (sevFindings.length === 0) return null;
            const cfg = SEVERITY_CONFIG[sev];
            const Icon = cfg.icon;
            return sevFindings.map((finding) => (
              <details key={finding.id} className={`border rounded-xl overflow-hidden ${cfg.border}`}>
                <summary className={`flex items-center gap-3 px-4 py-3 cursor-pointer select-none ${cfg.bg}`}>
                  <Icon className={`w-4 h-4 flex-shrink-0 ${cfg.text}`} />
                  <div className="flex-1 min-w-0">
                    <span className={`text-xs font-bold uppercase ${cfg.text}`}>{cfg.label}</span>
                    <span className="mx-2 text-gray-300">·</span>
                    <span className="text-sm font-medium text-gray-800">{finding.title}</span>
                  </div>
                  <span className="text-xs text-gray-400 flex-shrink-0 ml-2">{finding.requirement}</span>
                </summary>
                <div className="px-4 py-4 bg-white space-y-3 text-sm">
                  <p className="text-gray-700">{finding.description}</p>
                  {finding.affected_rules.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-gray-500 mb-1">Affected Rules</p>
                      <div className="flex flex-wrap gap-1">
                        {finding.affected_rules.map((r, i) => (
                          <span key={i} className="bg-gray-100 text-gray-700 px-2 py-0.5 rounded font-mono text-xs">
                            #{r}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  <div className={`rounded-lg p-3 ${cfg.bg}`}>
                    <p className={`text-xs font-semibold mb-1 ${cfg.text}`}>Remediation</p>
                    <p className={`text-xs ${cfg.text}`}>{finding.remediation}</p>
                  </div>
                </div>
              </details>
            ));
          })}
        </div>
      )}
    </div>
  );
}
