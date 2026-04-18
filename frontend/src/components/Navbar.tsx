import { Link, useNavigate } from "react-router-dom";
import { ShieldCheck, LogOut, Settings } from "lucide-react";
import { useAuth } from "../AuthContext";

export default function Navbar() {
  const { claims, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate("/login", { replace: true });
  };

  return (
    <nav className="bg-brand-800 text-white shadow-md">
      <div className="container mx-auto px-4 max-w-5xl flex items-center gap-3 h-14">
        <ShieldCheck className="w-6 h-6 text-blue-300" />
        <Link to="/assessments" className="font-semibold text-lg tracking-tight">
          PCI DSS Scoping Tool
        </Link>
        <span className="ml-2 text-xs bg-blue-700 rounded px-2 py-0.5 font-mono">v4.0</span>

        <div className="ml-auto flex items-center gap-3">
          {claims && (
            <span className="text-xs text-blue-200">
              {claims.is_admin ? "Admin" : claims.tenant_name ?? "Viewer"}
            </span>
          )}
          {claims?.is_admin && (
            <Link
              to="/admin"
              className="flex items-center gap-1 text-xs text-blue-200 hover:text-white transition-colors"
            >
              <Settings className="w-4 h-4" />
              Admin
            </Link>
          )}
          {claims && (
            <button
              onClick={handleLogout}
              className="flex items-center gap-1 text-xs text-blue-200 hover:text-white transition-colors"
            >
              <LogOut className="w-4 h-4" />
              Sign out
            </button>
          )}
        </div>
      </div>
    </nav>
  );
}
