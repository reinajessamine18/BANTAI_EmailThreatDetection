import {
  Activity,
  Brain,
  CircleAlert,
  Clock3,
  List,
  ShieldCheck,
} from "lucide-react";
import { useState } from "react";

const metrics = [
  {
    label: "Total Emails Scanned",
    value: "0",
    detail: "No scans yet",
    color: "text-white",
    icon: Activity,
  },
  {
    label: "Phishing Blocked",
    value: "0",
    detail: "No detections yet",
    color: "text-red-400",
    icon: CircleAlert,
  },
  {
    label: "Safe Emails",
    value: "0",
    detail: "No safe scans yet",
    color: "text-emerald-400",
    icon: ShieldCheck,
  },
  {
    label: "Avg. Inference Time",
    value: "—",
    detail: "No measurement yet",
    color: "text-white",
    icon: Brain,
  },
];

function Dashboard() {
  const [dateFilter, setDateFilter] = useState("30");

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="text-3xl font-black tracking-tight text-white">
          System Overview
        </h1>
        <div className="flex items-center gap-3">
          <select
            aria-label="Dashboard date range"
            value={dateFilter}
            onChange={(event) => setDateFilter(event.target.value)}
            className="rounded-lg border border-zinc-800 bg-zinc-950 px-4 py-2.5 text-sm text-zinc-400 outline-none transition focus:border-lime-400"
          >
            <option value="7">Last 7 Days</option>
            <option value="30">Last 30 Days</option>
            <option value="year">This Year</option>
            <option value="all">All Time</option>
          </select>
        </div>
      </div>

      <div className="grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
        {metrics.map(({ label, value, detail, color, icon: Icon }) => (
          <article
            key={label}
            className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-5"
          >
            <div className="flex items-start justify-between gap-3">
              <p className="text-[11px] font-bold uppercase tracking-[0.12em] text-zinc-500">
                {label}
              </p>
              <Icon size={16} className="shrink-0 text-zinc-600" />
            </div>
            <div className="mt-4 flex items-baseline justify-between gap-2">
              <p className={`font-mono text-3xl font-bold ${color}`}>{value}</p>
              <p className="text-[10px] text-zinc-600">{detail}</p>
            </div>
          </article>
        ))}
      </div>

      <div className="grid gap-5 xl:grid-cols-[1.55fr_1fr]">
        <section className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-5">
          <div className="flex items-center justify-between gap-4">
            <h2 className="flex items-center gap-2 text-sm font-bold text-white">
              <Brain size={16} className="text-lime-400" />
              Threat Trends
            </h2>
            <span className="flex items-center gap-2 text-xs text-zinc-500">
              <span className="h-2 w-2 rounded-full bg-lime-400" />
              Scanning Activity
            </span>
          </div>

          <div className="relative mt-5 h-64 pl-9 pb-6">
            <div className="absolute inset-x-9 top-1 bottom-7 flex flex-col justify-between">
              {Array.from({ length: 5 }, (_, index) => (
                <div
                  key={index}
                  className="w-full border-t border-zinc-800/70"
                />
              ))}
            </div>
            <div className="absolute inset-x-9 top-1 bottom-7 flex justify-between">
              {Array.from({ length: 7 }, (_, index) => (
                <div
                  key={index}
                  className="h-full border-l border-zinc-800/40"
                />
              ))}
            </div>
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="rounded-full border border-zinc-800 bg-zinc-950 px-4 py-2 text-xs text-zinc-500">
                No scan data available
              </span>
            </div>
          </div>
        </section>

        <section className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-5">
          <h2 className="flex items-center gap-2 text-sm font-bold text-white">
            <ShieldCheck size={16} className="text-lime-400" />
            Risk Distribution
          </h2>

          <div className="flex flex-col items-center">
            <div className="relative mt-5 flex h-52 w-52 items-center justify-center">
              <div
                role="img"
                aria-label="Empty risk distribution chart"
                className="h-48 w-48 rounded-full border-[24px] border-zinc-800"
              />
              <span className="absolute text-sm font-medium text-zinc-500">
                No data
              </span>
            </div>

            <div className="mt-3 grid w-full grid-cols-3 gap-2 text-center">
              {[
                ["SAFE", "text-emerald-400"],
                ["PHISHING", "text-red-400"],
                ["SUSPECT", "text-amber-400"],
              ].map(([label, color]) => (
                <div key={label}>
                  <p className="text-[10px] font-medium text-zinc-600">
                    {label}
                  </p>
                  <p className={`mt-1 font-mono text-sm font-bold ${color}`}>
                    —
                  </p>
                </div>
              ))}
            </div>
          </div>
        </section>
      </div>

      <section className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950/80">
        <div className="flex items-center justify-between border-b border-zinc-800 px-5 py-4">
          <h2 className="flex items-center gap-2 text-sm font-bold text-white">
            <List size={16} className="text-lime-400" />
            Recent Scan Activity
          </h2>
          <span className="rounded-md border border-zinc-800 px-3 py-1.5 text-xs text-zinc-500">
            View All
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[680px] text-left">
            <thead>
              <tr className="border-b border-zinc-800 text-[10px] font-bold uppercase tracking-wider text-zinc-600">
                <th className="px-5 py-3">Timestamp</th>
                <th className="px-5 py-3">Subject</th>
                <th className="px-5 py-3">Sender</th>
                <th className="px-5 py-3">Threat Score</th>
                <th className="px-5 py-3">Status</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td
                  colSpan={5}
                  className="h-28 px-5 text-center text-sm text-zinc-600"
                >
                  <span className="inline-flex items-center gap-2">
                    <Clock3 size={15} />
                    No email scans have been recorded.
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

export default Dashboard;
