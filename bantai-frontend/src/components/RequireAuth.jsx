import { useEffect, useRef, useState } from "react";
import { Navigate, Outlet, useNavigate } from "react-router-dom";

import {
  clearToken,
  exchangeWebHandoffTicket,
  getMe,
  getToken,
  SESSION_EXPIRED_EVENT,
} from "../api/client";

function readHandoffTicket() {
  return new URLSearchParams(window.location.hash.slice(1)).get("bantai_handoff");
}

// Route guard for everything under /app. Wrap the dashboard routes in App.jsx with
// <Route element={<RequireAuth />}> ... </Route>.
// "in" is only set after the SERVER accepted the token (GET /auth/me), not just because one is stored.
function RequireAuth() {
  const navigate = useNavigate();
  const handoffTicket = readHandoffTicket();
  const handoffPromise = useRef(null);
  const [state, setState] = useState(
    getToken() || handoffTicket ? "checking" : "out",
  );

  useEffect(() => {
    let active = true;
    const onExpired = () => {
      setState("out");
      navigate("/login", { replace: true });
    };
    window.addEventListener(SESSION_EXPIRED_EVENT, onExpired);

    if (handoffTicket) {
      if (!handoffPromise.current) {
        window.history.replaceState(
          window.history.state,
          "",
          `${window.location.pathname}${window.location.search}`,
        );
        clearToken();
        handoffPromise.current = exchangeWebHandoffTicket(handoffTicket).then(() => getMe());
      }
      handoffPromise.current
        .then(() => setState("in"))
        .catch((error) => {
          clearToken();
          const errorType = error?.status === 0 || error?.status >= 500
            ? "unavailable"
            : "expired";
          navigate(`/login?handoff_error=${errorType}`, { replace: true });
        });
      return () => {
        active = false;
        window.removeEventListener(SESSION_EXPIRED_EVENT, onExpired);
      };
    }

    if (getToken()) {
      getMe()
        .then(() => {
          if (active) setState("in");
        })
        .catch((err) => {
          if (active) setState(err.status === 401 ? "out" : "unreachable");
        });
    }
    return () => {
      active = false;
      window.removeEventListener(SESSION_EXPIRED_EVENT, onExpired);
    };
  }, [handoffTicket, navigate]);

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
