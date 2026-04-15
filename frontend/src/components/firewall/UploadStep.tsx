import { useRef, useState } from "react";
import { Upload, RefreshCw, ShieldAlert } from "lucide-react";
import { firewallApi, type FirewallUpload } from "../../api";

interface Props {
  assessmentId: string;
  onUploaded: (upload: FirewallUpload) => void;
}

export default function UploadStep({ assessmentId, onUploaded }: Props) {
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFile = async (file: File) => {
    setError(null);
    setUploading(true);
    try {
      const result = await firewallApi.upload(assessmentId, file);
      onUploaded(result);
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      setError(detail || "Upload failed. Please check the file and try again.");
    } finally {
      setUploading(false);
    }
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) handleFile(file);
  };

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold">Step 1 — Upload Firewall Config</h2>
        <p className="text-sm text-gray-500 mt-1">
          Upload a Fortinet FortiGate config (preferred) or iptables-save output.
          The file will be parsed server-side — raw text is stored for this analysis session only.
        </p>
      </div>

      <div
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => inputRef.current?.click()}
        className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition ${
          dragging ? "border-brand-500 bg-brand-50" : "border-gray-300 hover:border-brand-400 hover:bg-gray-50"
        }`}
      >
        {uploading ? (
          <div className="flex flex-col items-center gap-2 text-gray-500">
            <RefreshCw className="w-8 h-8 animate-spin" />
            <p className="text-sm font-medium">Parsing config…</p>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-2 text-gray-400">
            <Upload className="w-8 h-8" />
            <p className="text-sm font-medium text-gray-600">
              Drop your firewall config here, or click to browse
            </p>
            <p className="text-xs">Supports: .conf, .txt, .cfg (max 10 MB)</p>
          </div>
        )}
        <input
          ref={inputRef}
          type="file"
          accept=".conf,.txt,.cfg,.log"
          className="hidden"
          disabled={uploading}
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) handleFile(file);
            e.target.value = "";
          }}
        />
      </div>

      {error && (
        <div className="flex gap-2 items-start bg-red-50 border border-red-200 rounded-lg p-4 text-sm text-red-700">
          <ShieldAlert className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 text-sm text-amber-800">
        <p className="font-medium mb-1">Fortinet FortiGate format tips</p>
        <ul className="list-disc list-inside space-y-0.5 text-xs">
          <li>Run <code className="bg-amber-100 px-1 rounded">show full-configuration</code> in the CLI and save the output</li>
          <li>Or export from FortiManager: Policy &amp; Objects → Export → Full Configuration</li>
          <li>The parser extracts firewall policies, address objects, service objects, and interface IPs</li>
        </ul>
      </div>
    </div>
  );
}
