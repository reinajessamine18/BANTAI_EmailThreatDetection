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

import Login from "./components/Login";
import SignUp from "./components/SignUp";
import ForgotPassword from "./components/ForgotPassword";
import GuestAnalyzeEmail from "./components/GuestAnalyzeEmail";

import DashboardLayout from "./components/DashboardLayout";
import AnalyzeEmail from "./components/AnalyzeEmail";

import Dashboard from "./components/Dashboard";
import ThreatHistory from "./components/ThreatHistory";
import Settings from "./components/Settings";


function LandingPage() {
  return (
    <main className="bg-black text-white">

      <Navbar />

      <Hero />

      <TechStack />

      <Advantage />

      <CTA />

      <Footer />

    </main>
  );
}


function App() {
  return (
    <BrowserRouter>

      <Routes>

        {/* LANDING PAGE */}
        <Route
          path="/"
          element={<LandingPage />}
        />


        {/* AUTHENTICATION */}
        <Route
          path="/login"
          element={<Login />}
        />

        <Route
          path="/signup"
          element={<SignUp />}
        />

        <Route
          path="/forgot-password"
          element={<ForgotPassword />}
        />


        {/* GUEST EMAIL ANALYSIS */}
        <Route
          path="/analyze"
          element={<GuestAnalyzeEmail />}
        />


        {/* AUTHENTICATED APPLICATION */}
        <Route element={<DashboardLayout />}>

          <Route
            path="/app/dashboard"
            element={<Dashboard />}
          />

          <Route
            path="/app/analyze"
            element={<AnalyzeEmail />}
          />

          <Route
            path="/app/threat-history"
            element={<ThreatHistory />}
          />

          <Route
            path="/app/settings"
            element={<Settings />}
          />

        </Route>


        {/* UNKNOWN ROUTES */}
        <Route
          path="*"
          element={<Navigate to="/" replace />}
        />

      </Routes>

    </BrowserRouter>
  );
}

export default App;