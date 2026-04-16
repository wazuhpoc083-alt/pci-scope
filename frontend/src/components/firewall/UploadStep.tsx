import { useRef, useState } from "react";
import { Upload, RefreshCw, ShieldAlert, FlaskConical } from "lucide-react";
import { firewallApi, type FirewallUpload } from "../../api";

// Minimal but representative FortiGate sample config for demo/testing
const SAMPLE_FORTINET_CONFIG = `config system interface
    edit "wan1"
        set ip 203.0.113.1 255.255.255.0
        set type physical
    next
    edit "internal"
        set ip 10.10.10.1 255.255.255.0
        set type physical
    next
    edit "dmz"
        set ip 172.16.0.1 255.255.255.0
        set type physical
    next
    edit "mgmt"
        set ip 192.168.1.1 255.255.255.0
        set type physical
    next
end
config firewall address
    edit "PCI_Servers"
        set type ipmask
        set subnet 10.10.10.0 255.255.255.0
    next
    edit "DMZ_Web"
        set type ipmask
        set subnet 172.16.0.0 255.255.255.0
    next
    edit "Internet"
        set type ipmask
        set subnet 0.0.0.0 0.0.0.0
    next
    edit "Mgmt_Net"
        set type ipmask
        set subnet 192.168.1.0 255.255.255.0
    next
end
config firewall service custom
    edit "HTTPS_ALT"
        set protocol TCP
        set tcp-portrange 8443
    next
end
config firewall policy
    edit 1
        set name "Internet-to-DMZ"
        set srcintf "wan1"
        set dstintf "dmz"
        set srcaddr "Internet"
        set dstaddr "DMZ_Web"
        set action accept
        set service "HTTP" "HTTPS"
        set logtraffic all
        set comments "Allow inbound web traffic to DMZ"
    next
    edit 2
        set name "DMZ-to-PCI"
        set srcintf "dmz"
        set dstintf "internal"
        set srcaddr "DMZ_Web"
        set dstaddr "PCI_Servers"
        set action accept
        set service "MYSQL"
        set logtraffic all
        set comments "DMZ web servers connecting to PCI DB"
    next
    edit 3
        set name "PCI-to-Internet"
        set srcintf "internal"
        set dstintf "wan1"
        set srcaddr "PCI_Servers"
        set dstaddr "Internet"
        set action deny
        set logtraffic all
        set comments "Block PCI servers from internet"
    next
    edit 4
        set name "Mgmt-to-PCI"
        set srcintf "mgmt"
        set dstintf "internal"
        set srcaddr "Mgmt_Net"
        set dstaddr "PCI_Servers"
        set action accept
        set service "SSH" "HTTPS"
        set logtraffic all
        set nat disable
        set comments "Admin access to PCI servers"
    next
    edit 5
        set name "Mgmt-to-DMZ"
        set srcintf "mgmt"
        set dstintf "dmz"
        set srcaddr "Mgmt_Net"
        set dstaddr "DMZ_Web"
        set action accept
        set service "SSH" "HTTPS_ALT"
        set logtraffic all
        set comments "Admin access to DMZ web servers"
    next
end
`;


interface Props {
  assessmentId: string;
  onUploaded: (upload: FirewallUpload) => void;
}

export default function UploadStep({ assessmentId, onUploaded }: Props) {
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const loadSampleConfig = async () => {
    const blob = new Blob([SAMPLE_FORTINET_CONFIG], { type: "text/plain" });
    const file = new File([blob], "sample-fortigate.conf", { type: "text/plain" });
    await handleFile(file);
  };

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

      <div className="flex items-center gap-3">
        <hr className="flex-1 border-gray-200" />
        <span className="text-xs text-gray-400">or</span>
        <hr className="flex-1 border-gray-200" />
      </div>

      <button
        onClick={loadSampleConfig}
        disabled={uploading}
        className="w-full flex items-center justify-center gap-2 px-4 py-2.5 border border-dashed border-brand-300 rounded-lg text-sm font-medium text-brand-700 hover:bg-brand-50 disabled:opacity-50 transition"
      >
        <FlaskConical className="w-4 h-4" />
        Load sample FortiGate config (for testing)
      </button>

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
