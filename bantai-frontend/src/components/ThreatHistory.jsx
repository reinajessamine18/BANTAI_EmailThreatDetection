function ThreatHistory() {
  return (
    <div>

      <h1 className="text-3xl font-black tracking-tight text-white">
        Threat History
      </h1>

      <p className="mt-2 text-sm text-zinc-500">
        Review previously analyzed email threats.
      </p>

      <div className="mt-8 rounded-2xl border border-zinc-800 bg-zinc-950/70 p-10 text-center">

        <p className="text-sm text-zinc-600">
          No threat history available yet.
        </p>

      </div>

    </div>
  );
}

export default ThreatHistory;