import { Routes, Route, Navigate, useLocation } from "react-router-dom";
import { AuthProvider } from "./AuthContext";
import PrivateRoute from "./components/PrivateRoute";
import AssessmentsPage from "./pages/AssessmentsPage";
import AssessmentDetailPage from "./pages/AssessmentDetailPage";
import AdminPage from "./pages/AdminPage";
import LoginPage from "./pages/LoginPage";
import Navbar from "./components/Navbar";

function Layout() {
  const location = useLocation();
  const isLogin = location.pathname === "/login";

  if (isLogin) {
    return (
      <Routes>
        <Route path="/login" element={<LoginPage />} />
      </Routes>
    );
  }

  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <main className="flex-1 container mx-auto px-4 py-8 max-w-5xl">
        <Routes>
          <Route
            path="/"
            element={
              <PrivateRoute>
                <Navigate to="/assessments" replace />
              </PrivateRoute>
            }
          />
          <Route
            path="/assessments"
            element={
              <PrivateRoute>
                <AssessmentsPage />
              </PrivateRoute>
            }
          />
          <Route
            path="/assessments/:id"
            element={
              <PrivateRoute>
                <AssessmentDetailPage />
              </PrivateRoute>
            }
          />
          <Route
            path="/admin"
            element={
              <PrivateRoute>
                <AdminPage />
              </PrivateRoute>
            }
          />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <Layout />
    </AuthProvider>
  );
}
