import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import backgroundImage from "../assets/bgimg-login.png";
import lockIcon from "../assets/lock-icon.png";

function SignUp() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [error, setError] = useState("");

  const navigate = useNavigate();

  const handleSubmit = (event) => {
    event.preventDefault();

    setError("");

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    const user = {
      name: name.trim(),
      email: email.trim(),
      password: password,
    };

    localStorage.setItem(
      "bantaiUser",
      JSON.stringify(user)
    );

    localStorage.setItem(
      "bantaiAuthenticated",
      "true"
    );

    navigate("/app/dashboard");
  };

  return (
    <main
      className="relative min-h-screen bg-black bg-cover bg-center bg-no-repeat text-white"
      style={{
        backgroundImage: `url(${backgroundImage})`,
      }}
    >
      <div className="absolute inset-0 bg-black/55" />

      <div className="relative z-10 flex min-h-screen flex-col">

        <div className="flex flex-1 items-center justify-center px-6 py-12">
          <div className="w-full max-w-md rounded-2xl border border-zinc-800/80 bg-black/80 p-8 shadow-2xl backdrop-blur-md sm:p-10">

            {/* Header */}
            <div className="mb-8 text-center">
              <div className="mb-5">
                <span className="text-3xl font-black italic tracking-tight text-white">
                  BANTAI<span className="text-lime-400">.</span>
                </span>
              </div>

              <h1 className="text-2xl font-bold tracking-tight text-white">
                Create account
              </h1>

              <p className="mt-2 text-sm text-zinc-500">
                Create your BANTAI threat intelligence account.
              </p>
            </div>

            <form
              onSubmit={handleSubmit}
              className="space-y-5"
            >
              {/* Full Name */}
              <div>
                <label
                  htmlFor="name"
                  className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-400"
                >
                  Full Name
                </label>

                <input
                  id="name"
                  name="name"
                  type="text"
                  value={name}
                  onChange={(event) => {
                    setName(event.target.value);
                    setError("");
                  }}
                  placeholder="Your full name"
                  autoComplete="name"
                  required
                  className="w-full rounded-lg border border-zinc-800 bg-zinc-950/80 px-4 py-3.5 text-sm text-white outline-none transition placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400"
                />
              </div>

              {/* Email */}
              <div>
                <label
                  htmlFor="email"
                  className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-400"
                >
                  Email
                </label>

                <input
                  id="email"
                  name="email"
                  type="email"
                  value={email}
                  onChange={(event) => {
                    setEmail(event.target.value);
                    setError("");
                  }}
                  placeholder="name@company.com"
                  autoComplete="email"
                  required
                  className="w-full rounded-lg border border-zinc-800 bg-zinc-950/80 px-4 py-3.5 text-sm text-white outline-none transition placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400"
                />
              </div>

              {/* Password */}
              <div>
                <label
                  htmlFor="password"
                  className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-400"
                >
                  Password
                </label>

                <input
                  id="password"
                  name="password"
                  type="password"
                  value={password}
                  onChange={(event) => {
                    setPassword(event.target.value);
                    setError("");
                  }}
                  placeholder="Create a password"
                  autoComplete="new-password"
                  required
                  className="w-full rounded-lg border border-zinc-800 bg-zinc-950/80 px-4 py-3.5 text-sm text-white outline-none transition placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400"
                />
              </div>

              {/* Confirm Password */}
              <div>
                <label
                  htmlFor="confirm-password"
                  className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-400"
                >
                  Confirm Password
                </label>

                <input
                  id="confirm-password"
                  name="confirm-password"
                  type="password"
                  value={confirmPassword}
                  onChange={(event) => {
                    setConfirmPassword(event.target.value);
                    setError("");
                  }}
                  placeholder="Confirm your password"
                  autoComplete="new-password"
                  required
                  className="w-full rounded-lg border border-zinc-800 bg-zinc-950/80 px-4 py-3.5 text-sm text-white outline-none transition placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400"
                />
              </div>

              {/* Error */}
              {error && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3">
                  <p className="text-xs leading-5 text-red-400">
                    {error}
                  </p>
                </div>
              )}

              {/* Create Account */}
              <button
                type="submit"
                className="w-full rounded-lg bg-lime-400 px-6 py-3.5 text-sm font-bold uppercase tracking-wider text-black transition hover:bg-lime-300 active:scale-[0.99]"
              >
                Create Account
              </button>
            </form>

            {/* Login */}
            <div className="mt-6 text-center">
              <p className="text-xs text-zinc-500">
                Already have a BANTAI account?
              </p>

              <Link
                to="/login"
                className="mt-1 inline-block text-xs font-semibold text-lime-400 transition hover:text-lime-300"
              >
                Log in
              </Link>
            </div>
          </div>
        </div>

        {/* Footer */}
        <footer className="px-6 pb-7 text-center">
          <div className="flex items-center justify-center gap-2">
            <img
              src={lockIcon}
              alt=""
              className="h-4 w-4 object-contain opacity-60"
            />

            <p className="text-[11px] leading-5 text-zinc-500">
              Protected by end-to-end encryption. Unauthorized
              access is strictly prohibited.
            </p>
          </div>
        </footer>

      </div>
    </main>
  );
}

export default SignUp;