import { useEffect, useState } from "react";
import { Navigate, Outlet, useNavigate } from "react-router-dom";

import { getMe, getToken, SESSION_EXPIRED_EVENT } from "../api/client";

// Route guard for everything under /app. Wrap the dashboard routes in App.jsx with
// <Route element={<RequireAuth />}> ... </Route>.
// "in" is only set after the SERVER accepted the token (GET /auth/me), not just because one is stored.
function RequireAuth() {
  const navigate = useNavigate();
  const [state, setState] = useState(getToken() ? "checking" : "out");

  useEffect(() => {
    const onExpired = () => {
      setState("out");
      navigate("/login", { replace: true });
    };
    window.addEventListener(SESSION_EXPIRED_EVENT, onExpired);

    if (getToken()) {
      getMe()
        .then(() => setState("in"))
        .catch((err) => setState(err.status === 401 ? "out" : "unreachable"));
    }
    return () => window.removeEventListener(SESSION_EXPIRED_EVENT, onExpired);
  }, [navigate]);

  if (state === "out") return <Navigate to="/login" replace />;
  if (state === "checking") return null;
  if (state === "unreachable") {
    return (
      <p role="alert" className="p-8 text-sm text-red-400">
        Cannot reach the BANTAI server. Check that the backend is running, then reload.
      </p>
    );
  }
  return <Outlet />;
}

export default RequireAuth;
