import {
  Activity,
  Brain,
  CircleAlert,
  Clock3,
  List,
  ShieldCheck,
} from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Doughnut, Line } from "react-chartjs-2";
import {
  ArcElement,
  CategoryScale,
  Chart as ChartJS,
  Legend,
  LineElement,
  LinearScale,
  PointElement,
  Tooltip,
} from "chart.js";
import { friendlyError, getDashboard } from "../api/client";

ChartJS.register(
  ArcElement,
  CategoryScale,
  Legend,
  LineElement,
  LinearScale,
  PointElement,
  Tooltip,
);

const metrics = [
  {
    label: "Total Emails Scanned",
    value: "0",
    detail: "No scans yet",
    color: "text-white",
    icon: Activity,
  },
  {
    label: "Phishing Detected",
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
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    getDashboard(dateFilter)
      .then((d) => {
        if (!cancelled) {
          setData(d);
          setError("");
        }
      })
      .catch((err) => {
        if (!cancelled) setError(friendlyError(err));
      });
    return () => {
      cancelled = true;
    };
  }, [dateFilter]);

  const m = data?.metrics;
  const values = {
    "Total Emails Scanned": m ? String(m.totalScanned) : "—",
    "Phishing Detected": m ? String(m.phishingBlocked) : "—",
    "Safe Emails": m ? String(m.safeEmails) : "—",
    "Avg. Inference Time":
      m?.avgInferenceMs != null ? `${m.avgInferenceMs} ms` : "—",
  };
  const distribution = data?.riskDistribution;
  const points = data?.trend?.points ?? [];
  const lineData = {
    labels: points.map((p) => p.bucket),
    datasets: [
      {
        label: "Phishing",
        data: points.map((p) => p.phishing),
        borderColor: "#f87171",
        tension: 0.3,
      },
      {
        label: "Suspicious",
        data: points.map((p) => p.suspicious),
        borderColor: "#fbbf24",
        tension: 0.3,
      },
      {
        label: "Safe",
        data: points.map((p) => p.safe),
        borderColor: "#34d399",
        tension: 0.3,
      },
    ],
  };
  const doughnutData = {
    labels: ["Safe", "Phishing", "Suspicious"],
    datasets: [
      {
        data: distribution
          ? [distribution.safe, distribution.phishing, distribution.suspicious]
          : [],
        backgroundColor: ["#34d399", "#f87171", "#fbbf24"],
      },
    ],
  };

  return (
    <div className="space-y-6">
      {error && (
        <p role="alert" className="rounded-lg border border-red-400/30 bg-red-400/10 px-4 py-3 text-sm text-red-400">
          {error}
        </p>
      )}

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
        {metrics.map(({ label, detail, color, icon: Icon }) => (
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
              <p className={`font-mono text-3xl font-bold ${color}`}>{values[label]}</p>
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

          <div className="relative mt-5 h-64">
            {points.length > 0 ? (
              <Line
                data={lineData}
                options={{
                  responsive: true,
                  maintainAspectRatio: false,
                  plugins: {
                    legend: {
                      labels: { color: "#a1a1aa", boxWidth: 12, font: { size: 10 } },
                    },
                  },
                  scales: {
                    x: { ticks: { color: "#71717a" }, grid: { color: "#27272a" } },
                    y: { beginAtZero: true, ticks: { color: "#71717a" }, grid: { color: "#27272a" } },
                  },
                }}
              />
            ) : (
              <div className="flex h-full items-center justify-center">
                <span className="rounded-full border border-zinc-800 bg-zinc-950 px-4 py-2 text-xs text-zinc-500">
                  No scan data available
                </span>
              </div>
            )}
          </div>
        </section>

        <section className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-5">
          <h2 className="flex items-center gap-2 text-sm font-bold text-white">
            <ShieldCheck size={16} className="text-lime-400" />
            Risk Distribution
          </h2>

          <div className="flex flex-col items-center">
            <div className="relative mt-5 h-52 w-52">
              <Doughnut
                data={doughnutData}
                options={{
                  responsive: true,
                  maintainAspectRatio: true,
                  plugins: {
                    legend: { display: false },
                  },
                }}
              />
            </div>

            <div className="mt-3 grid w-full grid-cols-3 gap-2 text-center">
              {[
                ["SAFE", "text-emerald-400", distribution?.safe],
                ["PHISHING", "text-red-400", distribution?.phishing],
                ["SUSPECT", "text-amber-400", distribution?.suspicious],
              ].map(([label, color, count]) => (
                <div key={label}>
                  <p className="text-[10px] font-medium text-zinc-600">
                    {label}
                  </p>
                  <p className={`mt-1 font-mono text-sm font-bold ${color}`}>
                    {count ?? "—"}
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
          <Link
            to="/app/threat-history"
            className="rounded-md border border-zinc-800 px-3 py-1.5 text-xs text-zinc-500 transition hover:border-lime-400/50 hover:text-lime-400"
          >
            View All
          </Link>
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
              {data?.recent?.length ? (
                data.recent.map((item) => (
                  <tr
                    key={item.id}
                    className="border-b border-zinc-900 transition hover:bg-zinc-900/40"
                  >
                    <td className="whitespace-nowrap px-5 py-4 text-xs text-zinc-500">
                      {item.date ? new Date(item.date).toLocaleString() : "—"}
                    </td>
                    <td className="max-w-xs truncate px-5 py-4 text-sm text-white">
                      {item.subject || "—"}
                    </td>
                    <td className="max-w-xs truncate px-5 py-4 text-sm text-zinc-400">
                      {item.email || "—"}
                    </td>
                    <td className="px-5 py-4 font-mono text-sm text-zinc-300">
                      {item.threatScore ?? "—"}
                    </td>
                    <td className="px-5 py-4">
                      <span className="rounded-full border border-zinc-700 px-3 py-1 text-xs font-semibold text-zinc-400">
                        {item.classification || "—"}
                      </span>
                    </td>
                  </tr>
                ))
              ) : (
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
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

export default Dashboard;

// import {
//   Activity,
//   Brain,
//   CircleAlert,
//   Clock3,
//   List,
//   ShieldCheck,
// } from "lucide-react";
// import { useEffect, useState } from "react";

// const metrics = [
//   {
//     label: "Total Emails Scanned",
//     value: "0",
//     detail: "No scans yet",
//     color: "text-white",
//     icon: Activity,
//   },
//   {
//     label: "Phishing Blocked",
//     value: "0",
//     detail: "No detections yet",
//     color: "text-red-400",
//     icon: CircleAlert,
//   },
//   {
//     label: "Safe Emails",
//     value: "0",
//     detail: "No safe scans yet",
//     color: "text-emerald-400",
//     icon: ShieldCheck,
//   },
//   {
//     label: "Avg. Inference Time",
//     value: "—",
//     detail: "No measurement yet",
//     color: "text-white",
//     icon: Brain,
//   },
// ];

// function Dashboard() {
//   const [dateFilter, setDateFilter] = useState("30");

//   return (
//     <div className="space-y-6">
//       <div className="flex flex-wrap items-center justify-between gap-4">
//         <h1 className="text-3xl font-black tracking-tight text-white">
//           System Overview
//         </h1>
//         <div className="flex items-center gap-3">
//           <select
//             aria-label="Dashboard date range"
//             value={dateFilter}
//             onChange={(event) => setDateFilter(event.target.value)}
//             className="rounded-lg border border-zinc-800 bg-zinc-950 px-4 py-2.5 text-sm text-zinc-400 outline-none transition focus:border-lime-400"
//           >
//             <option value="7">Last 7 Days</option>
//             <option value="30">Last 30 Days</option>
//             <option value="year">This Year</option>
//             <option value="all">All Time</option>
//           </select>
//         </div>
//       </div>

//       <div className="grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
//         {metrics.map(({ label, value, detail, color, icon: Icon }) => (
//           <article
//             key={label}
//             className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-5"
//           >
//             <div className="flex items-start justify-between gap-3">
//               <p className="text-[11px] font-bold uppercase tracking-[0.12em] text-zinc-500">
//                 {label}
//               </p>
//               <Icon size={16} className="shrink-0 text-zinc-600" />
//             </div>
//             <div className="mt-4 flex items-baseline justify-between gap-2">
//               <p className={`font-mono text-3xl font-bold ${color}`}>{value}</p>
//               <p className="text-[10px] text-zinc-600">{detail}</p>
//             </div>
//           </article>
//         ))}
//       </div>

//       <div className="grid gap-5 xl:grid-cols-[1.55fr_1fr]">
//         <section className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-5">
//           <div className="flex items-center justify-between gap-4">
//             <h2 className="flex items-center gap-2 text-sm font-bold text-white">
//               <Brain size={16} className="text-lime-400" />
//               Threat Trends
//             </h2>
//             <span className="flex items-center gap-2 text-xs text-zinc-500">
//               <span className="h-2 w-2 rounded-full bg-lime-400" />
//               Scanning Activity
//             </span>
//           </div>

//           <div className="relative mt-5 h-64 pl-9 pb-6">
//             <div className="absolute inset-x-9 top-1 bottom-7 flex flex-col justify-between">
//               {Array.from({ length: 5 }, (_, index) => (
//                 <div
//                   key={index}
//                   className="w-full border-t border-zinc-800/70"
//                 />
//               ))}
//             </div>
//             <div className="absolute inset-x-9 top-1 bottom-7 flex justify-between">
//               {Array.from({ length: 7 }, (_, index) => (
//                 <div
//                   key={index}
//                   className="h-full border-l border-zinc-800/40"
//                 />
//               ))}
//             </div>
//             <div className="absolute inset-0 flex items-center justify-center">
//               <span className="rounded-full border border-zinc-800 bg-zinc-950 px-4 py-2 text-xs text-zinc-500">
//                 No scan data available
//               </span>
//             </div>
//           </div>
//         </section>

//         <section className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-5">
//           <h2 className="flex items-center gap-2 text-sm font-bold text-white">
//             <ShieldCheck size={16} className="text-lime-400" />
//             Risk Distribution
//           </h2>

//           <div className="flex flex-col items-center">
//             <div className="relative mt-5 flex h-52 w-52 items-center justify-center">
//               <div
//                 role="img"
//                 aria-label="Empty risk distribution chart"
//                 className="h-48 w-48 rounded-full border-[24px] border-zinc-800"
//               />
//               <span className="absolute text-sm font-medium text-zinc-500">
//                 No data
//               </span>
//             </div>

//             <div className="mt-3 grid w-full grid-cols-3 gap-2 text-center">
//               {[
//                 ["SAFE", "text-emerald-400"],
//                 ["PHISHING", "text-red-400"],
//                 ["SUSPECT", "text-amber-400"],
//               ].map(([label, color]) => (
//                 <div key={label}>
//                   <p className="text-[10px] font-medium text-zinc-600">
//                     {label}
//                   </p>
//                   <p className={`mt-1 font-mono text-sm font-bold ${color}`}>
//                     —
//                   </p>
//                 </div>
//               ))}
//             </div>
//           </div>
//         </section>
//       </div>

//       <section className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950/80">
//         <div className="flex items-center justify-between border-b border-zinc-800 px-5 py-4">
//           <h2 className="flex items-center gap-2 text-sm font-bold text-white">
//             <List size={16} className="text-lime-400" />
//             Recent Scan Activity
//           </h2>
//           <span className="rounded-md border border-zinc-800 px-3 py-1.5 text-xs text-zinc-500">
//             View All
//           </span>
//         </div>

//         <div className="overflow-x-auto">
//           <table className="w-full min-w-[680px] text-left">
//             <thead>
//               <tr className="border-b border-zinc-800 text-[10px] font-bold uppercase tracking-wider text-zinc-600">
//                 <th className="px-5 py-3">Timestamp</th>
//                 <th className="px-5 py-3">Subject</th>
//                 <th className="px-5 py-3">Sender</th>
//                 <th className="px-5 py-3">Threat Score</th>
//                 <th className="px-5 py-3">Status</th>
//               </tr>
//             </thead>
//             <tbody>
//               <tr>
//                 <td
//                   colSpan={5}
//                   className="h-28 px-5 text-center text-sm text-zinc-600"
//                 >
//                   <span className="inline-flex items-center gap-2">
//                     <Clock3 size={15} />
//                     No email scans have been recorded.
//                   </span>
//                 </td>
//               </tr>
//             </tbody>
//           </table>
//         </div>
//       </section>
//     </div>
//   );
// }

// export default Dashboard;
