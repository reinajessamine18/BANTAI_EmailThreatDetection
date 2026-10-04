import { useEffect, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";

function DashboardLayout() {
  const navigate = useNavigate();

  const [user, setUser] = useState(null);

  useEffect(() => {
    const storedUser = localStorage.getItem("bantaiUser");

    if (storedUser) {
      try {
        setUser(JSON.parse(storedUser));
      } catch {
        setUser(null);
      }
    }
  }, []);

  const handleLogout = () => {
    localStorage.removeItem("bantaiAuthenticated");

    navigate("/");
  };

  const navigation = [
    {
      name: "Dashboard",
      path: "/app/dashboard",
      icon: "▦",
    },
    {
      name: "Analyze Email",
      path: "/app/analyze",
      icon: "⌁",
    },
    {
      name: "Threat History",
      path: "/app/threat-history",
      icon: "◷",
    },
    {
      name: "System Settings",
      path: "/app/settings",
      icon: "⚙",
    },
  ];

  const displayName = user?.name || "BANTAI User";

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

            <span className="text-2xl font-black italic tracking-tight text-white">
                BANTAI<span className="text-lime-400">.</span>
            </span>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-4 py-6">

          <div className="space-y-2">
            {navigation.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  [
                    "flex items-center gap-3 rounded-lg px-3 py-3 text-sm font-medium transition",
                    isActive
                      ? "bg-lime-400/10 text-lime-400"
                      : "text-zinc-500 hover:bg-zinc-900 hover:text-white",
                  ].join(" ")
                }
              >
                <span className="flex h-6 w-6 items-center justify-center text-base">
                  {item.icon}
                </span>

                <span>{item.name}</span>
              </NavLink>
            ))}
          </div>
        </nav>

        {/* User Section */}
        <div className="border-t border-zinc-800 p-4">

          <div className="mb-4 flex items-center gap-3 rounded-lg bg-zinc-900/70 p-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-lime-400 text-xs font-black text-black">
              {initials || "B"}
            </div>

            <div className="min-w-0">
              <p className="truncate text-sm font-semibold text-white">
                {displayName}
              </p>

              <p className="truncate text-xs text-zinc-500">
                {user?.email || "BANTAI Account"}
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={handleLogout}
            className="flex w-full items-center gap-3 rounded-lg px-3 py-3 text-sm font-medium text-zinc-500 transition hover:bg-red-500/10 hover:text-red-400"
          >

            <span>Log Out</span>
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="ml-64 min-h-screen bg-black">

        {/* Page Content */}
        <div className="px-8 py-8">
          <Outlet />
        </div>

      </main>
    </div>
  );
}

export default DashboardLayout;