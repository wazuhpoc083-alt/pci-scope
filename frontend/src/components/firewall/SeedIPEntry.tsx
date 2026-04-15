import { useState } from "react";
import { Plus, Trash2, Loader2, Info } from "lucide-react";

interface Props {
  onAnalyze: (seeds: string[]) => void;
  loading: boolean;
}

function isValidCidr(value: string): boolean {
  const trimmed = value.trim();
  // Accept IP or CIDR
  const cidr = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(trimmed);
  return cidr;
}

export default function SeedIPEntry({ onAnalyze, loading }: Props) {
  const [seeds, setSeeds] = useState<string[]>([""]);
  const [errors, setErrors] = useState<Record<number, string>>({});

  const update = (idx: number, val: string) => {
    setSeeds((prev) => prev.map((s, i) => (i === idx ? val : s)));
    setErrors((prev) => { const n = { ...prev }; delete n[idx]; return n; });
  };

  const add = () => setSeeds((prev) => [...prev, ""]);
  const remove = (idx: number) => setSeeds((prev) => prev.filter((_, i) => i !== idx));

  const handleSubmit = () => {
    const errs: Record<number, string> = {};
    const valid: string[] = [];
    seeds.forEach((s, i) => {
      const trimmed = s.trim();
      if (!trimmed) return;
      if (!isValidCidr(trimmed)) {
        errs[i] = "Invalid IP or CIDR (e.g. 10.1.2.0/24 or 192.168.1.10)";
      } else {
        // Normalise bare IPs to /32
        valid.push(trimmed.includes("/") ? trimmed : `${trimmed}/32`);
      }
    });
    if (Object.keys(errs).length > 0) {
      setErrors(errs);
      return;
    }
    if (valid.length === 0) {
      setErrors({ 0: "Enter at least one CDE IP or subnet" });
      return;
    }
    onAnalyze(valid);
  };

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold">Step 3 — Identify CDE Systems</h2>
        <p className="text-sm text-gray-500 mt-1">
          Enter the IP addresses or subnets of systems that store, process, or transmit
          cardholder data (CHD). The scope engine will propagate outward from these seeds.
        </p>
      </div>

      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 flex gap-2 text-sm text-blue-800">
        <Info className="w-4 h-4 mt-0.5 flex-shrink-0" />
        <div>
          <p className="font-medium">What counts as CDE?</p>
          <p className="text-xs mt-0.5">
            Any system that stores PANs, processes card transactions, or transmits cardholder data —
            including payment servers, databases with card data, and transaction processing hosts.
          </p>
        </div>
      </div>

      <div className="space-y-2">
        {seeds.map((seed, idx) => (
          <div key={idx} className="flex items-start gap-2">
            <div className="flex-1">
              <input
                type="text"
                value={seed}
                onChange={(e) => update(idx, e.target.value)}
                placeholder="e.g. 10.1.2.0/24 or 192.168.5.10"
                className={`w-full px-3 py-2 text-sm border rounded-lg focus:outline-none focus:ring-2 ${
                  errors[idx] ? "border-red-400 focus:ring-red-300" : "focus:ring-brand-400"
                }`}
              />
              {errors[idx] && (
                <p className="text-xs text-red-600 mt-0.5">{errors[idx]}</p>
              )}
            </div>
            {seeds.length > 1 && (
              <button
                onClick={() => remove(idx)}
                className="mt-2 text-gray-400 hover:text-red-500 transition"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            )}
          </div>
        ))}
      </div>

      <button
        onClick={add}
        className="flex items-center gap-1 text-sm text-brand-700 hover:text-brand-800 font-medium"
      >
        <Plus className="w-4 h-4" /> Add another CDE subnet
      </button>

      <div className="flex justify-end">
        <button
          onClick={handleSubmit}
          disabled={loading}
          className="flex items-center gap-2 bg-brand-700 text-white px-5 py-2 rounded-lg hover:bg-brand-800 disabled:opacity-50 transition font-medium"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
          Run Scope Analysis
        </button>
      </div>
    </div>
  );
}
