function Dashboard() {
  return (
    <div className="space-y-8">

      <div>
        <h1 className="text-3xl font-black tracking-tight text-white">
          Dashboard
        </h1>

        <p className="mt-2 text-sm text-zinc-500">
          Monitor your email threat detection activity.
        </p>
      </div>

      <div className="grid gap-5 sm:grid-cols-2 xl:grid-cols-4">

        {[
          ["Total Email Scanned", "0"],
          ["Phishing Blocked", "0"],
          ["Safe Emails", "0"],
          ["Avg Inference Time", "0 ms"],
        ].map(([label, value]) => (
          <div
            key={label}
            className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-6"
          >
            <p className="text-xs font-bold uppercase tracking-wider text-zinc-500">
              {label}
            </p>

            <p className="mt-4 text-3xl font-black text-white">
              {value}
            </p>
          </div>
        ))}

      </div>

      <div className="grid gap-6 lg:grid-cols-2">

        <div className="min-h-[320px] rounded-2xl border border-zinc-800 bg-zinc-950/70 p-6">

          <h2 className="text-lg font-bold text-white">
            Threat Trends
          </h2>

          <div className="flex h-[250px] items-center justify-center">

            <p className="text-sm text-zinc-600">
              No scan data available yet.
            </p>

          </div>

        </div>

        <div className="min-h-[320px] rounded-2xl border border-zinc-800 bg-zinc-950/70 p-6">

          <h2 className="text-lg font-bold text-white">
            Risk Distribution
          </h2>

          <div className="flex h-[250px] items-center justify-center">

            <p className="text-sm text-zinc-600">
              No scan data available yet.
            </p>

          </div>

        </div>

      </div>

      <div className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-6">

        <h2 className="text-lg font-bold text-white">
          Recent Scan Activity
        </h2>

        <div className="mt-6 flex min-h-[160px] items-center justify-center">

          <p className="text-sm text-zinc-600">
            No email scans have been recorded.
          </p>

        </div>

      </div>

    </div>
  );
}

export default Dashboard;