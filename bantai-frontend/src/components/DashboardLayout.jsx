import { useEffect, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  House,
  Search,
  Clock,
  Settings,
} from "lucide-react";
import { getProfile, logout } from "../api/client";

function DashboardLayout() {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false);
  const [showLogoutConfirmation, setShowLogoutConfirmation] = useState(false);
  const [isLoggingOut, setIsLoggingOut] = useState(false);

  const loadUser = async () => {
  try {
    setUser(await getProfile());
  } catch {
    setUser(null);
  }
};

  // const loadUser = () => {
  //   const storedUser = localStorage.getItem("bantaiUser");

  //   if (storedUser) {
  //     try {
  //       setUser(JSON.parse(storedUser));
  //     } catch {
  //       setUser(null);
  //     }
  //   } else {
  //     setUser(null);
  //   }
  // };

  useEffect(() => {
    loadUser();

    window.addEventListener("bantaiUserUpdated", loadUser);

    return () => {
      window.removeEventListener("bantaiUserUpdated", loadUser);
    };
  }, []);

  useEffect(() => {
    const handleUnsavedChanges = (event) => {
      setHasUnsavedChanges(event.detail);
    };

    window.addEventListener("bantai:unsaved-changes", handleUnsavedChanges);

    return () => {
      window.removeEventListener("bantai:unsaved-changes", handleUnsavedChanges);
    };
  }, []);

  const confirmLogout = async () => {
    setIsLoggingOut(true);
    await logout();
    navigate("/");
  };

  const closeLogoutConfirmation = () => {
    if (!isLoggingOut) setShowLogoutConfirmation(false);
  };

  // const handleLogout = () => {
  //   localStorage.removeItem("bantaiAuthenticated");
  //   navigate("/");
  // };

  const navigation = [
    {
      name: "Dashboard",
      path: "/app/dashboard",
      icon: House,
    },
    {
      name: "Analyze Email",
      path: "/app/analyze",
      icon: Search,
    },
    {
      name: "Threat History",
      path: "/app/threat-history",
      icon: Clock,
    },
    {
      name: "System Settings",
      path: "/app/settings",
      icon: Settings,
    },
  ];

  const displayName = user?.fullName || "Account";
  const email = user?.email || "";
  const profilePicture = user?.profilePicture || "";

  const initials = displayName
    .split(" ")
    .filter(Boolean)
    .slice(0, 2)
    .map((word) => word.charAt(0).toUpperCase())
    .join("");

  return (
    <div className="min-h-screen bg-black text-white">
      {/* Sidebar */}
      <aside className="fixed inset-y-0 left-0 z-50 flex w-64 flex-col border-r border-zinc-800 bg-zinc-950">
        <div className="flex h-20 items-center border-b border-zinc-800 px-6">
          <div className="flex items-center gap-3">
            <span className="text-xl font-black italic tracking-tight text-white">
              BANTAI<span className="text-lime-400">.</span>
            </span>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-4 py-6">
          <div className="space-y-2">
            {navigation.map((item) => {
              const Icon = item.icon;

              return (
                <NavLink
                  key={item.path}
                  to={item.path}
                  className={({ isActive }) =>
                    [
                      "flex items-center gap-3 rounded-lg px-3 py-3 text-sm font-bold transition",
                      isActive
                        ? "bg-lime-400/10 text-lime-400"
                        : "text-zinc-500 hover:bg-zinc-900 hover:text-white",
                    ].join(" ")
                  }
                >
                  <span className="flex h-6 w-6 items-center justify-center">
                    <Icon
                      size={21}
                      strokeWidth={3}
                    />
                  </span>

                  <span>{item.name}</span>
                </NavLink>
              );
            })}
          </div>
        </nav>

        {/* Account */}
        <div className="border-t border-zinc-800 p-4">
          <button
            type="button"
            onClick={() => navigate("/app/settings")}
            aria-label={`Open account profile settings for ${displayName}`}
            className="mb-4 flex w-full items-center gap-3 rounded-lg bg-zinc-900/70 p-3 text-left transition hover:bg-zinc-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-lime-400"
          >
            {profilePicture ? (
              <img
                src={profilePicture}
                alt={displayName}
                className="h-9 w-9 shrink-0 rounded-full object-cover"
              />
            ) : (
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-lime-400 text-xs font-black text-black">
                {initials || "B"}
              </div>
            )}

            <div className="min-w-0">
              <p className="truncate text-sm font-semibold text-white">
                {displayName}
              </p>

              <p className="truncate text-xs text-zinc-500">
                {email}
              </p>
            </div>
          </button>

          <button
            type="button"
            onClick={() => setShowLogoutConfirmation(true)}
            className="flex w-full items-center rounded-lg px-3 py-3 text-sm font-medium text-zinc-500 transition hover:bg-red-500/10 hover:text-red-400"
          >
            <span>Log Out</span>
          </button>
        </div>
      </aside>

      {showLogoutConfirmation && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 p-4">
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="logout-dialog-title"
            aria-describedby="logout-dialog-description"
            className="w-full max-w-md rounded-xl border border-zinc-800 bg-zinc-950 p-6 shadow-2xl"
          >
            <h2 id="logout-dialog-title" className="text-lg font-bold text-white">
              Log out?
            </h2>
            <p
              id="logout-dialog-description"
              className="mt-3 text-sm leading-6 text-zinc-400"
            >
              {hasUnsavedChanges
                ? "You have unsaved profile or settings changes. Logging out now may cause them to be lost. Do you want to log out anyway?"
                : "Are you sure you want to log out of BANTAI?"}
            </p>
            <div className="mt-6 flex justify-end gap-3">
              <button
                type="button"
                onClick={closeLogoutConfirmation}
                disabled={isLoggingOut}
                className="rounded-lg border border-zinc-700 px-4 py-2 text-sm font-semibold text-zinc-300 transition hover:bg-zinc-900 disabled:cursor-not-allowed disabled:opacity-60"
              >
                Stay signed in
              </button>
              <button
                type="button"
                onClick={confirmLogout}
                disabled={isLoggingOut}
                className="rounded-lg bg-red-500 px-4 py-2 text-sm font-bold text-white transition hover:bg-red-400 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {isLoggingOut ? "Logging out..." : "Log out"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Main */}
      <main className="ml-64 min-h-screen bg-black">
        <div className="px-8 py-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}

export default DashboardLayout;