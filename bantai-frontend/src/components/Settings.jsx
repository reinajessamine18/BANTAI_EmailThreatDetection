function Settings() {
  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-black tracking-tight text-white">
          System Settings
        </h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-zinc-500">
          Manage your BANTAI account and email threat detection preferences.
        </p>
      </div>

      {/* Account Settings */}
      <section className="rounded-2xl border border-zinc-800 bg-zinc-950/70">
        <div className="border-b border-zinc-800 p-6">
          <h2 className="text-lg font-bold text-white">
            Account
          </h2>

          <p className="mt-1 text-sm text-zinc-500">
            Manage your BANTAI account information.
          </p>
        </div>

        <div className="space-y-6 p-6">
          <div>
            <label className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-500">
              Display Name
            </label>

            <input
              type="text"
              placeholder="BANTAI User"
              className="w-full rounded-lg border border-zinc-800 bg-black px-4 py-3 text-sm text-white outline-none transition placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400 sm:max-w-xl"
            />
          </div>

          <div>
            <label className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-500">
              Email Address
            </label>

            <input
              type="email"
              placeholder="user@example.com"
              className="w-full rounded-lg border border-zinc-800 bg-black px-4 py-3 text-sm text-white outline-none transition placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400 sm:max-w-xl"
            />
          </div>

          <button
            type="button"
            className="rounded-lg bg-lime-400 px-6 py-3 text-sm font-bold text-black transition hover:bg-lime-300"
          >
            Save Changes
          </button>
        </div>
      </section>

      {/* Detection Settings */}
      <section className="rounded-2xl border border-zinc-800 bg-zinc-950/70">
        <div className="border-b border-zinc-800 p-6">
          <h2 className="text-lg font-bold text-white">
            Detection Settings
          </h2>

          <p className="mt-1 text-sm text-zinc-500">
            Configure how BANTAI handles email threat analysis.
          </p>
        </div>

        <div className="divide-y divide-zinc-800">
          <div className="flex items-center justify-between gap-6 p-6">
            <div>
              <h3 className="text-sm font-semibold text-white">
                Threat History
              </h3>

              <p className="mt-1 text-sm leading-6 text-zinc-600">
                Save completed email scans to your threat history.
              </p>
            </div>

            <div className="relative h-6 w-11 shrink-0 rounded-full bg-lime-400">
              <div className="absolute right-1 top-1 h-4 w-4 rounded-full bg-black" />
            </div>
          </div>

          <div className="flex items-center justify-between gap-6 p-6">
            <div>
              <h3 className="text-sm font-semibold text-white">
                SHAP Explainability
              </h3>

              <p className="mt-1 text-sm leading-6 text-zinc-600">
                Display the features that influenced the threat prediction.
              </p>
            </div>

            <div className="relative h-6 w-11 shrink-0 rounded-full bg-lime-400">
              <div className="absolute right-1 top-1 h-4 w-4 rounded-full bg-black" />
            </div>
          </div>

          <div className="flex items-center justify-between gap-6 p-6">
            <div>
              <h3 className="text-sm font-semibold text-white">
                Automatic Analysis
              </h3>

              <p className="mt-1 text-sm leading-6 text-zinc-600">
                Automatically analyze supported email files after upload.
              </p>
            </div>

            <div className="relative h-6 w-11 shrink-0 rounded-full bg-zinc-800">
              <div className="absolute left-1 top-1 h-4 w-4 rounded-full bg-zinc-500" />
            </div>
          </div>
        </div>
      </section>

      {/* System Information */}
      <section className="rounded-2xl border border-zinc-800 bg-zinc-950/70">
        <div className="border-b border-zinc-800 p-6">
          <h2 className="text-lg font-bold text-white">
            System Information
          </h2>

          <p className="mt-1 text-sm text-zinc-500">
            Current BANTAI platform configuration.
          </p>
        </div>

        <div className="grid gap-6 p-6 sm:grid-cols-2 lg:grid-cols-3">
          <div>
            <p className="text-xs font-bold uppercase tracking-wider text-zinc-600">
              Platform
            </p>
            <p className="mt-2 text-sm font-semibold text-white">
              BANTAI
            </p>
          </div>

          <div>
            <p className="text-xs font-bold uppercase tracking-wider text-zinc-600">
              Detection Engine
            </p>
            <p className="mt-2 text-sm font-semibold text-white">
              XGBoost
            </p>
          </div>

          <div>
            <p className="text-xs font-bold uppercase tracking-wider text-zinc-600">
              Explainability
            </p>
            <p className="mt-2 text-sm font-semibold text-white">
              SHAP
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}

export default Settings;