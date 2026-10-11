import { Download, Search } from "lucide-react";
import { useState } from "react";

function ThreatHistory() {
  const [search, setSearch] = useState("");
  const [dateFilter, setDateFilter] = useState("all");
  const [threatFilter, setThreatFilter] = useState("all");

  // This will eventually come from the database/API.
  const history = [];

  const filteredHistory = history.filter((item) => {
    const matchesSearch =
      item.subject?.toLowerCase().includes(search.toLowerCase()) ||
      item.email?.toLowerCase().includes(search.toLowerCase());

    const matchesThreat =
      threatFilter === "all" ||
      item.threatLevel?.toLowerCase() === threatFilter;

    return matchesSearch && matchesThreat;
  });

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-black tracking-tight text-white">
          Threat History &amp; Audit Logs
        </h1>

      </div>

      {/* Search and Filters */}
      <div className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-5">
        <div className="flex flex-col gap-3 xl:flex-row xl:items-center">
          {/* Search */}
          <div className="relative min-w-0 flex-1">
            <Search
              size={17}
              className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500"
            />
            <input
              type="text"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search by subject, sender, or scan ID..."
              className="w-full rounded-lg border border-zinc-800 bg-black py-3 pl-10 pr-4 text-sm text-white outline-none transition placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400"
            />
          </div>

          {/* Date Filter */}
          <select
            value={dateFilter}
            onChange={(event) => setDateFilter(event.target.value)}
            className="rounded-lg border border-zinc-800 bg-black px-4 py-3 text-sm text-zinc-400 outline-none transition focus:border-lime-400"
          >
            <option value="all">All Time</option>
            <option value="7">Last 7 Days</option>
            <option value="30">Last 30 Days</option>
            <option value="year">This Year</option>
          </select>

          {/* Threat Level Filter */}
          <select
            value={threatFilter}
            onChange={(event) => setThreatFilter(event.target.value)}
            className="rounded-lg border border-zinc-800 bg-black px-4 py-3 text-sm text-zinc-400 outline-none transition focus:border-lime-400"
          >
            <option value="all">All Threat Levels</option>
            <option value="safe">Safe</option>
            <option value="suspicious">Suspicious</option>
            <option value="phishing">Phishing</option>
          </select>

          <button
            type="button"
            className="inline-flex items-center justify-center gap-2 rounded-lg border border-lime-400 px-4 py-3 text-xs font-bold uppercase tracking-wider text-lime-400 transition hover:bg-lime-400/10"
          >
            <Download size={15} />
            Export CSV
          </button>
        </div>
      </div>

      {/* Audit Log */}
      <div className="rounded-2xl border border-zinc-800 bg-zinc-950/70">
        <div className="border-b border-zinc-800 px-6 py-5">
          <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h2 className="text-lg font-bold text-white">
                Audit Log
              </h2>

              <p className="mt-1 text-sm text-zinc-500">
                A record of email analysis activity associated with your
                account.
              </p>
            </div>

            <span className="text-xs font-medium text-zinc-600">
              {filteredHistory.length} record
              {filteredHistory.length !== 1 ? "s" : ""}
            </span>
          </div>
        </div>

        {filteredHistory.length === 0 ? (
          <div className="flex min-h-[320px] flex-col items-center justify-center px-6 text-center">
            <div className="mb-5 flex h-14 w-14 items-center justify-center rounded-full border border-zinc-800 bg-black">
              <span className="text-xl text-zinc-600">
                ◷
              </span>
            </div>

            <h3 className="text-base font-semibold text-white">
              No scan history yet
            </h3>

            <p className="mt-2 max-w-md text-sm leading-6 text-zinc-600">
              Your email analysis activity will appear here once you
              complete a scan.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[800px] text-left">
              <thead className="border-b border-zinc-800">
                <tr className="text-[11px] font-bold uppercase tracking-wider text-zinc-600">
                  <th className="px-6 py-4">Date & Time</th>
                  <th className="px-6 py-4">Email / Subject</th>
                  <th className="px-6 py-4">Threat Level</th>
                  <th className="px-6 py-4">Result</th>
                  <th className="px-6 py-4">Action</th>
                </tr>
              </thead>

              <tbody>
                {filteredHistory.map((item) => (
                  <tr
                    key={item.id}
                    className="border-b border-zinc-900 transition hover:bg-zinc-900/40"
                  >
                    <td className="px-6 py-4 text-sm text-zinc-400">
                      {item.date}
                    </td>

                    <td className="px-6 py-4">
                      <p className="text-sm font-medium text-white">
                        {item.subject}
                      </p>

                      <p className="mt-1 text-xs text-zinc-600">
                        {item.email}
                      </p>
                    </td>

                    <td className="px-6 py-4">
                      <span className="rounded-full border border-zinc-700 px-3 py-1 text-xs font-semibold text-zinc-400">
                        {item.threatLevel}
                      </span>
                    </td>

                    <td className="px-6 py-4 text-sm text-zinc-400">
                      {item.result}
                    </td>

                    <td className="px-6 py-4">
                      <button
                        type="button"
                        className="text-xs font-semibold text-lime-400 transition hover:text-lime-300"
                      >
                        View Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

export default ThreatHistory;