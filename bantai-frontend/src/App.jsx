import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
} from "react-router-dom";

import Navbar from "./components/Navbar";
import Hero from "./components/Hero";
import TechStack from "./components/TechStack";
import Advantage from "./components/Advantage";
import CTA from "./components/CTA";
import Footer from "./components/Footer";
import BackToTop from "./components/BackToTop";

import Login from "./components/Login";
import SignUp from "./components/SignUp";
import ForgotPassword from "./components/ForgotPassword";
import ResetPassword from "./components/ResetPassword";

import DashboardLayout from "./components/DashboardLayout";

import Dashboard from "./components/Dashboard";
import ThreatHistory from "./components/ThreatHistory";
import Settings from "./components/Settings";

import RequireAuth from "./components/RequireAuth";
import ScanDetail from "./components/ScanDetail"; //newly

function LandingPage() {
  return (
    <main className="bg-black text-white">
      <Navbar />

      <Hero />

      <TechStack />

      <Advantage />

      <CTA />

      <Footer />

      <BackToTop />
    </main>
  );
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Landing Page */}
        <Route path="/" element={<LandingPage />} />

        {/* Authentication */}
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<SignUp />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/reset-password" element={<ResetPassword />} />

        {/* Legacy scan links lead to login; scanning is available in the extension. */}
        <Route path="/analyze" element={<Navigate to="/login" replace />} />

        {/* Authenticated account application */}
        <Route element={<RequireAuth />}> 
          <Route element={<DashboardLayout />}>
          <Route path="/app/dashboard" element={<Dashboard />} />
          <Route path="/app/analyze" element={<Navigate to="/app/dashboard" replace />} />
          <Route path="/app/threat-history" element={<ThreatHistory />} />
          <Route path="/app/threat-history/:scanId" element={<ScanDetail />} />
          <Route path="/app/settings" element={<Settings />} />
          </Route>
        </Route>

        {/* Unknown routes */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;