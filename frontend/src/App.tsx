import { Routes, Route, Navigate } from "react-router-dom";
import AssessmentsPage from "./pages/AssessmentsPage";
import AssessmentDetailPage from "./pages/AssessmentDetailPage";
import Navbar from "./components/Navbar";

export default function App() {
  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <main className="flex-1 container mx-auto px-4 py-8 max-w-5xl">
        <Routes>
          <Route path="/" element={<Navigate to="/assessments" replace />} />
          <Route path="/assessments" element={<AssessmentsPage />} />
          <Route path="/assessments/:id" element={<AssessmentDetailPage />} />
        </Routes>
      </main>
    </div>
  );
}
