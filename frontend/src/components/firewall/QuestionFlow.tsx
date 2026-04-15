import { useState } from "react";
import { MessageSquare, ChevronRight, Loader2 } from "lucide-react";
import type { ScopeQuestion } from "../../api";

interface Props {
  questions: ScopeQuestion[];
  answers: Record<string, string>;
  onSubmit: (answers: Record<string, string>) => void;
  loading: boolean;
}

const CATEGORY_LABELS: Record<string, { label: string; color: string }> = {
  cde_id: { label: "CDE Identification", color: "bg-red-100 text-red-700" },
  ambiguity: { label: "Ambiguity", color: "bg-yellow-100 text-yellow-700" },
  segmentation: { label: "Segmentation", color: "bg-blue-100 text-blue-700" },
  missing_rule: { label: "Missing Rule", color: "bg-purple-100 text-purple-700" },
};

export default function QuestionFlow({ questions, answers, onSubmit, loading }: Props) {
  const [localAnswers, setLocalAnswers] = useState<Record<string, string>>(answers);

  if (questions.length === 0) {
    return (
      <div className="py-8 text-center text-gray-400">
        <MessageSquare className="w-8 h-8 mx-auto mb-2 opacity-40" />
        <p className="text-sm">No clarifying questions — the config is sufficiently clear.</p>
      </div>
    );
  }

  const answered = Object.keys(localAnswers).filter((k) => localAnswers[k]?.trim()).length;

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold">Step 4 — Clarifying Questions</h2>
        <p className="text-sm text-gray-500 mt-1">
          {questions.length} question{questions.length !== 1 ? "s" : ""} generated from your config.
          Answer what you can — unanswered questions will remain open in the report.
          ({answered}/{questions.length} answered)
        </p>
      </div>

      <div className="space-y-3">
        {questions.map((q, idx) => {
          const catCfg = CATEGORY_LABELS[q.category] ?? { label: q.category, color: "bg-gray-100 text-gray-600" };
          const answered = !!(localAnswers[q.id]?.trim());
          return (
            <div
              key={q.id}
              className={`border rounded-xl p-4 space-y-3 transition ${
                answered ? "border-green-200 bg-green-50/30" : "border-gray-200 bg-white"
              }`}
            >
              <div className="flex items-start gap-3">
                <span className="text-gray-400 text-xs font-mono mt-0.5 w-5 flex-shrink-0">{idx + 1}</span>
                <div className="flex-1 space-y-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${catCfg.color}`}>
                      {catCfg.label}
                    </span>
                    {q.rule_id && (
                      <span className="text-xs text-gray-400 font-mono">Rule #{q.rule_id}</span>
                    )}
                  </div>
                  <p className="text-sm text-gray-800">{q.text}</p>
                </div>
              </div>
              <textarea
                rows={2}
                value={localAnswers[q.id] ?? ""}
                onChange={(e) => setLocalAnswers((prev) => ({ ...prev, [q.id]: e.target.value }))}
                placeholder="Your answer (optional)…"
                className="w-full px-3 py-2 text-sm border rounded-lg resize-none focus:outline-none focus:ring-2 focus:ring-brand-400"
              />
            </div>
          );
        })}
      </div>

      <div className="flex justify-end">
        <button
          onClick={() => onSubmit(localAnswers)}
          disabled={loading}
          className="flex items-center gap-2 bg-brand-700 text-white px-5 py-2 rounded-lg hover:bg-brand-800 disabled:opacity-50 transition font-medium"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ChevronRight className="w-4 h-4" />}
          Save Answers &amp; View Gap Analysis
        </button>
      </div>
    </div>
  );
}
