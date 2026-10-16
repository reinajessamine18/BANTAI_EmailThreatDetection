import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getToken, SESSION_EXPIRED_EVENT } from "../api/client";

function Navbar() {
  const [isSignedIn, setIsSignedIn] = useState(() => Boolean(getToken()));

  useEffect(() => {
    const syncSession = () => setIsSignedIn(Boolean(getToken()));
    window.addEventListener("storage", syncSession);
    window.addEventListener(SESSION_EXPIRED_EVENT, syncSession);
    return () => {
      window.removeEventListener("storage", syncSession);
      window.removeEventListener(SESSION_EXPIRED_EVENT, syncSession);
    };
  }, []);

  return (
    <nav className="sticky top-0 z-50 border-b border-zinc-800 bg-zinc-950">
      <div className="mx-auto flex h-20 max-w-7xl items-center justify-between px-6 lg:px-8">
        {/* BANTAI */}
        <Link
          to="/"
          onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
          className="flex items-center"
        >
          <span className="text-2xl font-black italic tracking-tight text-white">
            BANTAI<span className="text-lime-400">.</span>
          </span>
        </Link>

        {/* Navigation */}
        <div className="flex items-center gap-8">
          <div className="hidden items-center gap-7 md:flex">
            <a
              href="#technology"
              className="text-sm font-medium text-zinc-500 transition duration-200 hover:text-white"
            >
              Technology
            </a>

            <a
              href="#advantages"
              className="text-sm font-medium text-zinc-500 transition duration-200 hover:text-white"
            >
              Advantages
            </a>

            <a
              href="#about"
              className="text-sm font-medium text-zinc-500 transition duration-200 hover:text-white"
            >
              About
            </a>
          </div>

          {/* Authentication */}
          <div className="flex items-center gap-3">
            {isSignedIn ? (
              <Link
                to="/app/dashboard"
                className="rounded-lg border border-lime-400 bg-lime-400 px-4 py-2 text-sm font-bold text-black transition duration-200 hover:bg-transparent hover:text-lime-400 hover:shadow-[0_0_25px_rgba(190,255,0,0.3)] focus:bg-transparent focus:text-lime-400 focus:outline-none"
              >
                Open Dashboard
              </Link>
            ) : (
              <>
                <Link
                  to="/login"
                  className="rounded-lg border border-lime-400 px-4 py-2 text-sm font-semibold text-lime-400 transition duration-200 hover:bg-lime-400 hover:text-black hover:shadow-[0_0_25px_rgba(190,255,0,0.3)]"
                >
                  Log In
                </Link>

                <Link
                  to="/signup"
                  className="rounded-lg border border-lime-400 bg-lime-400 px-4 py-2 text-sm font-bold text-black transition duration-200 hover:bg-transparent hover:text-lime-400 hover:shadow-[0_0_25px_rgba(190,255,0,0.3)] focus:bg-transparent focus:text-lime-400 focus:outline-none"
                >
                  Sign Up
                </Link>
              </>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
}

export default Navbar;