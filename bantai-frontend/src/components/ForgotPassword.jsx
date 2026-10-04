import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import backgroundImage from "../assets/bgimg-login.png";
import lockIcon from "../assets/lock-icon.png";

function ForgotPassword() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [verified, setVerified] = useState(false);
  const [error, setError] = useState("");

  const navigate = useNavigate();

  const handleVerifyUsername = (event) => {
    event.preventDefault();

    const storedUser = localStorage.getItem("bantaiUser");

    if (!storedUser) {
      setError("Username not found.");
      return;
    }

    try {
      const user = JSON.parse(storedUser);

      if (
        username.trim().toLowerCase() !==
        (user.email || "").trim().toLowerCase()
      ) {
        setError("Username not found.");
        return;
      }

      setError("");
      setVerified(true);
    } catch {
      setError("Unable to verify username.");
    }
  };

  const handleResetPassword = (event) => {
    event.preventDefault();

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setError("");

    // The real password update will be handled by the backend.
    navigate("/login");
  };

  return (
    <main
      className="relative min-h-screen bg-black bg-cover bg-center bg-no-repeat text-white"
      style={{ backgroundImage: `url(${backgroundImage})` }}
    >
      <div className="absolute inset-0 bg-black/55" />

      <div className="relative z-10 flex min-h-screen flex-col">

        <div className="flex flex-1 items-center justify-center px-6 py-12">
          <div className="w-full max-w-md rounded-2xl border border-zinc-800/80 bg-black/80 p-8 shadow-2xl backdrop-blur-md sm:p-10">

            <div className="mb-8 text-center">

              <div className="mb-5">
                <span className="text-3xl font-black tracking-tight text-white">
                  BANTAI<span className="text-lime-400">.</span>
                </span>
              </div>

              <h1 className="text-2xl font-bold tracking-tight text-white">
                {verified ? "Reset Password" : "Forgot Password"}
              </h1>

              <p className="mt-2 text-sm leading-6 text-zinc-500">
                {verified
                  ? "Create a new password for your BANTAI account."
                  : "Verify your username to continue."}
              </p>

            </div>

            {!verified ? (
              <form onSubmit={handleVerifyUsername} className="space-y-5">

                <div>
                  <label
                    htmlFor="username"
                    className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-400"
                  >
                    Username
                  </label>

                  <input
                    id="username"
                    type="email"
                    value={username}
                    onChange={(event) => {
                      setUsername(event.target.value);
                      setError("");
                    }}
                    placeholder="name@company.com"
                    autoComplete="username"
                    required
                    className="w-full rounded-lg border border-zinc-800 bg-zinc-950/80 px-4 py-3.5 text-sm text-white outline-none transition placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400"
                  />
                </div>

                {error && (
                  <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3">
                    <p className="text-xs text-red-400">
                      {error}
                    </p>
                  </div>
                )}

                <button
                  type="submit"
                  className="w-full rounded-lg bg-lime-400 px-6 py-3.5 text-sm font-bold uppercase tracking-wider text-black transition hover:bg-lime-300 active:scale-[0.99]"
                >
                  VERIFY USERNAME
                </button>

              </form>
            ) : (
              <form onSubmit={handleResetPassword} className="space-y-5">

                <div>
                  <label
                    htmlFor="new-password"
                    className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-400"
                  >
                    New Password
                  </label>

                  <input
                    id="new-password"
                    type="password"
                    value={password}
                    onChange={(event) => {
                      setPassword(event.target.value);
                      setError("");
                    }}
                    placeholder="Enter new password"
                    required
                    className="w-full rounded-lg border border-zinc-800 bg-zinc-950/80 px-4 py-3.5 text-sm text-white outline-none transition placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400"
                  />
                </div>

                <div>
                  <label
                    htmlFor="confirm-password"
                    className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-400"
                  >
                    Confirm Password
                  </label>

                  <input
                    id="confirm-password"
                    type="password"
                    value={confirmPassword}
                    onChange={(event) => {
                      setConfirmPassword(event.target.value);
                      setError("");
                    }}
                    placeholder="Confirm new password"
                    required
                    className="w-full rounded-lg border border-zinc-800 bg-zinc-950/80 px-4 py-3.5 text-sm text-white outline-none transition placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400"
                  />
                </div>

                {error && (
                  <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3">
                    <p className="text-xs text-red-400">
                      {error}
                    </p>
                  </div>
                )}

                <button
                  type="submit"
                  className="w-full rounded-lg bg-lime-400 px-6 py-3.5 text-sm font-bold uppercase tracking-wider text-black transition hover:bg-lime-300 active:scale-[0.99]"
                >
                  RESET PASSWORD
                </button>

              </form>
            )}

            <div className="mt-7 text-center">
              <Link
                to="/login"
                className="text-xs font-semibold text-lime-400 transition hover:text-lime-300"
              >
                Back to Log In
              </Link>
            </div>

          </div>
        </div>

        <footer className="px-6 pb-7 text-center">
          <div className="flex items-center justify-center gap-2">
            <img
              src={lockIcon}
              alt=""
              className="h-4 w-4 object-contain opacity-60"
            />

            <p className="text-[11px] leading-5 text-zinc-500">
              Protected by end-to-end encryption. Unauthorized access is strictly prohibited.
            </p>
          </div>
        </footer>

      </div>
    </main>
  );
}

export default ForgotPassword;