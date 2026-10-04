import { NavLink, Outlet, useNavigate } from "react-router-dom";
import logo from "../assets/BANTAI-logo.png";

function DashboardLayout() {
  const navigate = useNavigate();

  const navItems = [
    {
      name: "Dashboard",
      path: "/app/dashboard",
      icon: "▣",
    },
    {
      name: "Analyze Email",
      path: "/app/analyze",
      icon: "✉",
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

  const handleLogout = () => {
    localStorage.removeItem("bantaiAuthenticated");
    localStorage.removeItem("bantaiUser");

    navigate("/");
  };

  const storedUser = localStorage.getItem("bantaiUser");

  let userName = "User";

  if (storedUser) {
    try {
      const parsedUser = JSON.parse(storedUser);
      userName = parsedUser.name || "User";
    } catch {
      userName = "User";
    }
  }

  const initials = userName
    .split(" ")
    .map((word) => word[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();

  return (
    <div className="min-h-screen bg-black text-white">

      {/* SIDEBAR */}
      <aside className="fixed left-0 top-0 z-40 flex h-screen w-64 flex-col border-r border-zinc-800 bg-zinc-950">

        {/* LOGO */}
        <div className="flex h-20 items-center border-b border-zinc-800 px-6">

          <img
            src={logo}
            alt="BANTAI logo"
            className="h-9 w-9 object-contain"
          />

          <span className="ml-3 text-xl font-black tracking-tight text-white">
            BANTAI<span className="text-lime-400">.</span>
          </span>

        </div>

        {/* NAVIGATION */}
        <nav className="flex-1 px-4 py-6">

          <p className="mb-4 px-3 text-[10px] font-bold uppercase tracking-[0.25em] text-zinc-600">
            Navigation
          </p>

          <div className="space-y-2">

            {navItems.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `flex items-center gap-3 rounded-lg px-3 py-3 text-sm font-medium transition ${
                    isActive
                      ? "bg-lime-400 text-black"
                      : "text-zinc-400 hover:bg-zinc-900 hover:text-white"
                  }`
                }
              >

                <span className="w-5 text-center text-base">
                  {item.icon}
                </span>

                <span>
                  {item.name}
                </span>

              </NavLink>
            ))}

          </div>

        </nav>

        {/* USER ACCOUNT */}
        <div className="border-t border-zinc-800 p-4">

          <div className="flex items-center gap-3 rounded-lg px-2 py-3">

            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-lime-400 text-sm font-bold text-black">
              {initials || "U"}
            </div>

            <div className="min-w-0 flex-1">

              <p className="truncate text-sm font-semibold text-white">
                {userName}
              </p>

              <p className="truncate text-xs text-zinc-500">
                User Account
              </p>

            </div>

          </div>

          <button
            type="button"
            onClick={handleLogout}
            className="mt-2 w-full rounded-lg px-3 py-2 text-left text-xs font-medium text-zinc-500 transition hover:bg-zinc-900 hover:text-white"
          >
            Log Out
          </button>

        </div>

      </aside>

      {/* MAIN CONTENT */}
      <main className="ml-64 min-h-screen">
        <Outlet />
      </main>

    </div>
  );
}

export default DashboardLayout;