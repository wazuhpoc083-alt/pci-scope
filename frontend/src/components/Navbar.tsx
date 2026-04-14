import { Link } from "react-router-dom";
import { ShieldCheck } from "lucide-react";

export default function Navbar() {
  return (
    <nav className="bg-brand-800 text-white shadow-md">
      <div className="container mx-auto px-4 max-w-5xl flex items-center gap-3 h-14">
        <ShieldCheck className="w-6 h-6 text-blue-300" />
        <Link to="/assessments" className="font-semibold text-lg tracking-tight">
          PCI DSS Scoping Tool
        </Link>
        <span className="ml-2 text-xs bg-blue-700 rounded px-2 py-0.5 font-mono">v4.0</span>
      </div>
    </nav>
  );
}
