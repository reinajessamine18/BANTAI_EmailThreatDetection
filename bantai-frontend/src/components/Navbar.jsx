import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Menu, X } from "lucide-react";
import { getToken, SESSION_EXPIRED_EVENT } from "../api/client";

function Navbar() {
  const [isSignedIn, setIsSignedIn] = useState(() => Boolean(getToken()));
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

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
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between gap-2 px-4 sm:h-20 sm:px-6 lg:px-8">
        {/* BANTAI */}
        <Link
          to="/"
          onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
          className="flex items-center"
        >
          <span className="select-none caret-transparent text-xl font-black italic tracking-tight text-white sm:text-2xl">
            BANTAI<span className="text-lime-400">.</span>
          </span>
        </Link>

        {/* Navigation */}
        <div className="flex items-center gap-2 sm:gap-8">
          <div className="hidden items-center gap-7 lg:flex">
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
          <div className="hidden items-center gap-2 sm:gap-3 lg:flex">
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
                  className="whitespace-nowrap rounded-lg border border-lime-400 px-2.5 py-2 text-xs font-semibold text-lime-400 transition duration-200 hover:bg-lime-400 hover:text-black hover:shadow-[0_0_25px_rgba(190,255,0,0.3)] sm:px-4 sm:text-sm"
                >
                  Log In
                </Link>

                <Link
                  to="/signup"
                  className="whitespace-nowrap rounded-lg border border-lime-400 bg-lime-400 px-2.5 py-2 text-xs font-bold text-black transition duration-200 hover:bg-transparent hover:text-lime-400 hover:shadow-[0_0_25px_rgba(190,255,0,0.3)] focus:bg-transparent focus:text-lime-400 focus:outline-none sm:px-4 sm:text-sm"
                >
                  Create Account
                </Link>
              </>
            )}
          </div>

          <button
            type="button"
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
            aria-label={isMobileMenuOpen ? "Close navigation menu" : "Open navigation menu"}
            aria-expanded={isMobileMenuOpen}
            aria-controls="mobile-navigation-menu"
            className="rounded-md p-2 text-zinc-300 transition hover:bg-zinc-900 hover:text-white lg:hidden"
          >
            {isMobileMenuOpen ? <X aria-hidden="true" size={22} /> : <Menu aria-hidden="true" size={22} />}
          </button>
        </div>
      </div>

      {isMobileMenuOpen && (
        <div id="mobile-navigation-menu" className="border-t border-zinc-800 bg-zinc-950 px-4 py-3 lg:hidden">
          <div className="mx-auto grid max-w-7xl gap-1">
            <a href="#technology" onClick={() => setIsMobileMenuOpen(false)} className="rounded-md px-3 py-3 text-sm font-medium text-zinc-300 hover:bg-zinc-900 hover:text-white">
              Technology
            </a>
            <a href="#advantages" onClick={() => setIsMobileMenuOpen(false)} className="rounded-md px-3 py-3 text-sm font-medium text-zinc-300 hover:bg-zinc-900 hover:text-white">
              Advantages
            </a>
            <a href="#about" onClick={() => setIsMobileMenuOpen(false)} className="rounded-md px-3 py-3 text-sm font-medium text-zinc-300 hover:bg-zinc-900 hover:text-white">
              About
            </a>
            {isSignedIn ? (
              <Link to="/app/dashboard" onClick={() => setIsMobileMenuOpen(false)} className="mt-2 rounded-lg bg-lime-400 px-4 py-3 text-center text-sm font-bold text-black">
                Open Dashboard
              </Link>
            ) : (
              <div className="mt-2 grid grid-cols-2 gap-3">
                <Link to="/login" onClick={() => setIsMobileMenuOpen(false)} className="rounded-lg border border-lime-400 px-4 py-3 text-center text-sm font-semibold text-lime-400">
                  Log In
                </Link>
                <Link to="/signup" onClick={() => setIsMobileMenuOpen(false)} className="rounded-lg bg-lime-400 px-4 py-3 text-center text-sm font-bold text-black">
                  Create Account
                </Link>
              </div>
            )}
          </div>
        </div>
      )}
    </nav>
  );
}

export default Navbar;