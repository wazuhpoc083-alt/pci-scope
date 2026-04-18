import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { api } from "./api";

export interface AuthClaims {
  role: "admin" | "viewer";
  is_admin: boolean;
  tenant_id: string | null;
  tenant_name: string | null;
}

interface AuthState {
  token: string | null;
  claims: AuthClaims | null;
  loading: boolean;
  login: (token: string) => Promise<AuthClaims>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem("auth_token"));
  const [claims, setClaims] = useState<AuthClaims | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!token) {
      setClaims(null);
      setLoading(false);
      return;
    }
    api
      .get<AuthClaims>("/api/auth/me", {
        headers: { Authorization: `Bearer ${token}` },
      })
      .then((r) => {
        setClaims(r.data);
        setLoading(false);
      })
      .catch(() => {
        // Token invalid or expired — clear it
        localStorage.removeItem("auth_token");
        setToken(null);
        setClaims(null);
        setLoading(false);
      });
  }, [token]);

  const login = async (newToken: string): Promise<AuthClaims> => {
    const r = await api.get<AuthClaims>("/api/auth/me", {
      headers: { Authorization: `Bearer ${newToken}` },
    });
    localStorage.setItem("auth_token", newToken);
    setToken(newToken);
    setClaims(r.data);
    return r.data;
  };

  const logout = () => {
    localStorage.removeItem("auth_token");
    setToken(null);
    setClaims(null);
  };

  return (
    <AuthContext.Provider value={{ token, claims, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
