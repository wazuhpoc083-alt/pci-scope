import { useEffect, useState } from "react";
import { firewallApi, type FirewallUpload, type FirewallRule, type FirewallAnalysis as AnalysisType } from "../../api";
import UploadStep from "./UploadStep";
import ParsedRulesTable from "./ParsedRulesTable";
import MarkSubnetsStep from "./MarkSubnetsStep";
import ScopeSummary from "./ScopeSummary";
import QuestionFlow from "./QuestionFlow";
import GapFindings from "./GapFindings";

type Step = "upload" | "rules" | "seeds" | "results";

interface Props {
  assessmentId: string;
}

const STEPS: { id: Step; label: string }[] = [
  { id: "upload", label: "Upload" },
  { id: "rules", label: "Review Rules" },
  { id: "seeds", label: "Mark Subnets" },
  { id: "results", label: "Results" },
];

export default function FirewallAnalysis({ assessmentId }: Props) {
  const [step, setStep] = useState<Step>("upload");
  const [upload, setUpload] = useState<FirewallUpload | null>(null);
  const [rules, setRules] = useState<FirewallRule[]>([]);
  const [analysis, setAnalysis] = useState<AnalysisType | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [submittingAnswers, setSubmittingAnswers] = useState(false);
  const [activeTab, setActiveTab] = useState<"scope" | "questions" | "gaps">("scope");

  // On mount, try to restore any existing upload / analysis
  useEffect(() => {
    firewallApi
      .listUploads(assessmentId)
      .then(async (uploads) => {
        if (uploads.length === 0) return;
        const latest = uploads[0];
        setUpload(latest);
        const fetchedRules = await firewallApi.listRules(assessmentId, latest.id);
        setRules(fetchedRules);

        try {
          const existingAnalysis = await firewallApi.getAnalysis(assessmentId);
          setAnalysis(existingAnalysis);
          setStep("results");
        } catch {
          setStep("rules");
        }
      })
      .catch(() => {
        // No uploads yet — stay on upload step
      });
  }, [assessmentId]);

  const handleUploaded = async (u: FirewallUpload) => {
    setUpload(u);
    const fetchedRules = await firewallApi.listRules(assessmentId, u.id);
    setRules(fetchedRules);
    setStep("rules");
  };

  const handleAnalyze = async (seeds: string[], subnetClassifications?: Record<string, string>) => {
    if (!upload) return;
    setAnalyzing(true);
    try {
      const result = await firewallApi.analyze(assessmentId, upload.id, seeds, subnetClassifications);
      setAnalysis(result);
      setStep("results");
      setActiveTab("scope");
    } finally {
      setAnalyzing(false);
    }
  };

  const handleAnswers = async (answers: Record<string, string>) => {
    setSubmittingAnswers(true);
    try {
      const updated = await firewallApi.submitAnswers(assessmentId, answers);
      setAnalysis(updated);
      setActiveTab("gaps");
    } finally {
      setSubmittingAnswers(false);
    }
  };

  const currentStepIdx = STEPS.findIndex((s) => s.id === step);

  return (
    <div className="space-y-6">
      {/* Stepper */}
      <nav className="flex items-center gap-0">
        {STEPS.map((s, idx) => {
          const done = idx < currentStepIdx;
          const active = s.id === step;
          return (
            <div key={s.id} className="flex items-center">
              <button
                onClick={() => {
                  if (done) setStep(s.id);
                }}
                disabled={!done && !active}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition ${
                  active
                    ? "bg-brand-700 text-white"
                    : done
                    ? "text-brand-700 hover:bg-brand-50 cursor-pointer"
                    : "text-gray-400 cursor-not-allowed"
                }`}
              >
                <span className={`w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold ${
                  active ? "bg-white text-brand-700" : done ? "bg-brand-100 text-brand-700" : "bg-gray-200 text-gray-400"
                }`}>
                  {done ? "✓" : idx + 1}
                </span>
                {s.label}
              </button>
              {idx < STEPS.length - 1 && (
                <span className="text-gray-300 mx-1">›</span>
              )}
            </div>
          );
        })}
        {upload && step !== "upload" && (
          <button
            onClick={() => {
              setUpload(null);
              setRules([]);
              setAnalysis(null);
              setStep("upload");
            }}
            className="ml-auto text-xs text-gray-400 hover:text-red-500 transition"
          >
            Upload different config
          </button>
        )}
      </nav>

      {/* Step content */}
      {step === "upload" && (
        <UploadStep assessmentId={assessmentId} onUploaded={handleUploaded} />
      )}

      {step === "rules" && upload && (
        <ParsedRulesTable
          upload={upload}
          rules={rules}
          onContinue={() => setStep("seeds")}
        />
      )}

      {step === "seeds" && upload && (
        <MarkSubnetsStep upload={upload} onAnalyze={handleAnalyze} loading={analyzing} />
      )}

      {step === "results" && analysis && upload && (
        <div className="space-y-4">
          {/* Re-analyze button */}
          <div className="flex justify-between items-center">
            <p className="text-xs text-gray-400">
              Analysis based on {analysis.cde_seeds.length} CDE seed
              {analysis.cde_seeds.length !== 1 ? "s" : ""}:
              {" "}<span className="font-mono">{analysis.cde_seeds.join(", ")}</span>
            </p>
            <button
              onClick={() => setStep("seeds")}
              className="text-xs text-brand-700 hover:text-brand-800 font-medium"
            >
              Change CDE seeds
            </button>
          </div>

          {/* Results tabs */}
          <div className="flex gap-1 border-b">
            {(["scope", "questions", "gaps"] as const).map((tab) => {
              const labels: Record<string, string> = {
                scope: `Scope Map (${analysis.scope_nodes.length})`,
                questions: `Questions (${analysis.questions.length})`,
                gaps: `Gap Findings (${analysis.gap_findings.length})`,
              };
              const hasAlert = tab === "gaps" && analysis.gap_findings.some((f) => f.severity === "critical");
              return (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`px-4 py-2 text-sm font-medium border-b-2 transition flex items-center gap-1 ${
                    activeTab === tab
                      ? "border-brand-700 text-brand-700"
                      : "border-transparent text-gray-500 hover:text-gray-700"
                  }`}
                >
                  {labels[tab]}
                  {hasAlert && <span className="w-2 h-2 rounded-full bg-red-500" />}
                </button>
              );
            })}
          </div>

          {activeTab === "scope" && (
            <ScopeSummary nodes={analysis.scope_nodes} seeds={analysis.cde_seeds} />
          )}
          {activeTab === "questions" && (
            <QuestionFlow
              questions={analysis.questions}
              answers={analysis.answers}
              onSubmit={handleAnswers}
              loading={submittingAnswers}
            />
          )}
          {activeTab === "gaps" && (
            <GapFindings
              findings={analysis.gap_findings}
              exportUrl={firewallApi.exportCsvUrl(assessmentId)}
            />
          )}
        </div>
      )}
    </div>
  );
}
