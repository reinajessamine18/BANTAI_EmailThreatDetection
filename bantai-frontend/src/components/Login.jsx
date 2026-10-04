import { useState } from "react";
import { Link } from "react-router-dom";

import backgroundImage from "../assets/bgimg-login.png";
import shieldIcon from "../assets/shield-icon.png";
import lockIcon from "../assets/lock-icon.png";
import eyeIcon from "../assets/eye-icon.png";

function Login() {
  const [showPassword, setShowPassword] = useState(false);

  return (
    <main
      className="relative min-h-screen bg-black bg-cover bg-center bg-no-repeat text-white"
      style={{ backgroundImage: `url(${backgroundImage})` }}
    >
      {/* Background overlay */}
      <div className="absolute inset-0 bg-black/55" />

      {/* Page content */}
      <div className="relative z-10 flex min-h-screen flex-col">

        {/* Login area */}
        <div className="flex flex-1 items-center justify-center px-6 py-12">

          {/* Login container */}
          <div className="w-full max-w-md rounded-2xl border border-zinc-800/80 bg-black/80 p-8 shadow-2xl backdrop-blur-md sm:p-10">

            {/* BANTAI Logo */}
            <div className="mb-8 text-center">
              <div className="mb-5">
                <span className="text-3xl font-black tracking-tight text-white">
                  BANTAI<span className="text-lime-400">.</span>
                </span>
              </div>

              <h1 className="text-2xl font-bold tracking-tight text-white">
                Sign in
              </h1>

              <p className="mt-2 text-sm text-zinc-500">
                Access the BANTAI threat intelligence platform.
              </p>
            </div>

            {/* Login form */}
            <form className="space-y-5">

              {/* Username */}
              <div>
                <label
                  htmlFor="username"
                  className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-400"
                >
                  Username
                </label>

                <input
                  id="username"
                  name="username"
                  type="email"
                  placeholder="name@company.com"
                  autoComplete="username"
                  className="w-full rounded-lg border border-zinc-800 bg-zinc-950/80 px-4 py-3.5 text-sm text-white outline-none transition placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400"
                />
              </div>

              {/* Password */}
              <div>
                <div className="mb-2 flex items-center justify-between">

                  <label
                    htmlFor="password"
                    className="block text-xs font-bold uppercase tracking-wider text-zinc-400"
                  >
                    Password
                  </label>

                  <Link
                    to="/forgot-password"
                    className="text-xs font-semibold text-lime-400 transition hover:text-lime-300"
                  >
                    Forgot password?
                  </Link>

                </div>

                {/* Password input */}
                <div className="relative">

                  <input
                    id="password"
                    name="password"
                    type={showPassword ? "text" : "password"}
                    placeholder="••••••••••••"
                    autoComplete="current-password"
                    className="w-full rounded-lg border border-zinc-800 bg-zinc-950/80 px-4 py-3.5 pr-12 text-sm text-white outline-none transition placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400"
                  />

                  {/* Eye button */}
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    aria-label={
                      showPassword
                        ? "Hide password"
                        : "Show password"
                    }
                    className="absolute right-3 top-1/2 -translate-y-1/2 rounded-md p-1.5 transition hover:bg-white/10"
                  >
                    <img
                      src={eyeIcon}
                      alt=""
                      className="h-5 w-5 object-contain"
                    />
                  </button>

                </div>
              </div>

              {/* Sign In button */}
              <button
                type="submit"
                className="w-full rounded-lg bg-lime-400 px-6 py-3.5 text-sm font-bold uppercase tracking-wider text-black transition hover:bg-lime-300 active:scale-[0.99]"
              >
                Sign In
              </button>

              {/* Divider */}
              <div className="flex items-center gap-4 py-1">

                <div className="h-px flex-1 bg-zinc-800" />

                <span className="text-xs font-medium uppercase tracking-wider text-zinc-600">
                  or
                </span>

                <div className="h-px flex-1 bg-zinc-800" />

              </div>

              {/* SSO button */}
              <button
                type="button"
                className="flex w-full items-center justify-center gap-3 rounded-lg border border-zinc-700 bg-zinc-900/70 px-6 py-3.5 text-sm font-semibold text-white transition hover:border-zinc-500 hover:bg-zinc-800"
              >
                <img
                  src={shieldIcon}
                  alt=""
                  className="h-5 w-5 object-contain"
                />

                <span>Sign in with SSO (SAML)</span>
              </button>

            </form>

            {/* System status */}
            <div className="mt-8 flex items-center justify-center gap-2 text-xs">

              <span className="h-2 w-2 rounded-full bg-lime-400 shadow-[0_0_8px_rgba(163,230,53,0.8)]" />

              <span className="font-medium text-zinc-400">
                System Online
              </span>

              <span className="text-zinc-700">
                |
              </span>

              <span className="font-mono text-zinc-500">
                v4.0.2-stable
              </span>

            </div>

          </div>
        </div>

        {/* Security footer */}
        <footer className="px-6 pb-7 text-center">

          <div className="flex items-center justify-center gap-2">

            <img
              src={lockIcon}
              alt=""
              className="h-4 w-4 object-contain opacity-60"
            />

            <p className="text-[11px] leading-5 text-zinc-500">
              Protected by end-to-end encryption. Unauthorized access is
              strictly prohibited.
            </p>

          </div>

        </footer>

      </div>
    </main>
  );
}

export default Login;