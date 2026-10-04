import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";

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
import AnalyzeEmail from "./components/AnalyzeEmail";
import DashboardLayout from "./components/DashboardLayout";

function LandingPage() {
  return (
    <div className="min-h-screen bg-black text-white">
      <Navbar />
      <Hero />
      <TechStack />
      <Advantage />
      <CTA />
      <Footer />
    </div>
  );
}

function Dashboard() {
  return (
    <div className="min-h-screen bg-black px-8 py-10 text-white">
      <div className="mx-auto max-w-7xl">

        {/* HEADER */}
        <div>
          <h1 className="text-3xl font-bold tracking-tight">
            System Overview
          </h1>

          <p className="mt-2 text-sm text-zinc-400">
            Monitor email threat detection activity and system performance.
          </p>
        </div>

        {/* KPI CARDS */}
        <div className="mt-8 grid gap-5 md:grid-cols-2 xl:grid-cols-4">

          <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-6">
            <p className="text-xs font-bold uppercase tracking-wider text-zinc-500">
              Total Email Scanned
            </p>

            <p className="mt-4 text-3xl font-bold text-white">
              0
            </p>

            <p className="mt-2 text-xs text-zinc-600">
              No scans recorded yet
            </p>
          </div>

          <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-6">
            <p className="text-xs font-bold uppercase tracking-wider text-zinc-500">
              Phishing Blocked
            </p>

            <p className="mt-4 text-3xl font-bold text-white">
              0
            </p>

            <p className="mt-2 text-xs text-zinc-600">
              No threats recorded yet
            </p>
          </div>

          <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-6">
            <p className="text-xs font-bold uppercase tracking-wider text-zinc-500">
              Safe Emails
            </p>

            <p className="mt-4 text-3xl font-bold text-white">
              0
            </p>

            <p className="mt-2 text-xs text-zinc-600">
              No safe scans recorded yet
            </p>
          </div>

          <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-6">
            <p className="text-xs font-bold uppercase tracking-wider text-zinc-500">
              Avg. Inference Time
            </p>

            <p className="mt-4 text-3xl font-bold text-white">
              0 ms
            </p>

            <p className="mt-2 text-xs text-zinc-600">
              No inference data yet
            </p>
          </div>

        </div>

        {/* GRAPHS */}
        <div className="mt-6 grid gap-6 lg:grid-cols-3">

          {/* THREAT TRENDS */}
          <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-6 lg:col-span-2">

            <h2 className="text-lg font-semibold">
              Threat Trends
            </h2>

            <p className="mt-1 text-sm text-zinc-500">
              Scanning activity will appear here once emails are analyzed.
            </p>

            <div className="mt-6 flex h-72 items-center justify-center rounded-xl border border-dashed border-zinc-800 bg-black/40">
              <p className="text-sm text-zinc-600">
                No scanning data available
              </p>
            </div>

          </div>

          {/* RISK DISTRIBUTION */}
          <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-6">

            <h2 className="text-lg font-semibold">
              Risk Distribution
            </h2>

            <p className="mt-1 text-sm text-zinc-500">
              Email risk distribution will appear here.
            </p>

            <div className="mt-6 flex h-72 items-center justify-center rounded-xl border border-dashed border-zinc-800 bg-black/40">
              <p className="text-sm text-zinc-600">
                No data available
              </p>
            </div>

          </div>

        </div>

        {/* RECENT ACTIVITY */}
        <div className="mt-6 rounded-2xl border border-zinc-800 bg-zinc-950 p-6">

          <h2 className="text-lg font-semibold">
            Recent Scan Activity
          </h2>

          <p className="mt-1 text-sm text-zinc-500">
            Your latest email analysis activity will appear here.
          </p>

          <div className="mt-6 flex min-h-32 items-center justify-center rounded-xl border border-dashed border-zinc-800 bg-black/40">
            <p className="text-sm text-zinc-600">
              No recent scans
            </p>
          </div>

        </div>

      </div>
    </div>
  );
}

function ThreatHistory() {
  return (
    <div className="min-h-screen bg-black px-8 py-10 text-white">
      <div className="mx-auto max-w-7xl">

        <h1 className="text-3xl font-bold tracking-tight">
          Threat History
        </h1>

        <p className="mt-2 text-sm text-zinc-400">
          Review previous email threat analysis and audit logs.
        </p>

        <div className="mt-8 rounded-2xl border border-zinc-800 bg-zinc-950 p-6">

          <div className="flex min-h-80 items-center justify-center rounded-xl border border-dashed border-zinc-800 bg-black/40">
            <p className="text-sm text-zinc-600">
              No threat history available
            </p>
          </div>

        </div>

      </div>
    </div>
  );
}

function Settings() {
  return (
    <div className="min-h-screen bg-black px-8 py-10 text-white">
      <div className="mx-auto max-w-7xl">

        <h1 className="text-3xl font-bold tracking-tight">
          System Settings
        </h1>

        <p className="mt-2 text-sm text-zinc-400">
          Manage your BANTAI account and system preferences.
        </p>

        <div className="mt-8 rounded-2xl border border-zinc-800 bg-zinc-950 p-6">

          <h2 className="text-lg font-semibold">
            Settings
          </h2>

          <p className="mt-2 text-sm text-zinc-500">
            System settings will be available here.
          </p>

        </div>

      </div>
    </div>
  );
}

function App() {
  return (
    <BrowserRouter>
      <Routes>

        {/* PUBLIC */}
        <Route
          path="/"
          element={<LandingPage />}
        />

        <Route
          path="/forgot-password"
          element={<ForgotPassword />}
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

        {/* GUEST / FREE SCANNER */}
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

        {/* FALLBACK */}
        <Route
          path="*"
          element={<Navigate to="/" replace />}
        />

      </Routes>
    </BrowserRouter>
  );
}

export default App;