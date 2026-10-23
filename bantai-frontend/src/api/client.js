// BANTAI API client: the ONLY place the frontend talks to the backend.
//
// Rules this module enforces for every screen:
//  * The bearer token lives in ONE place (below). Passwords are never stored in the browser.
//  * The Authorization header is sent only when a token exists AND the call is not public.
//    (Sending "Bearer null" makes the backend answer 401, so we never do.)
//  * Every failure becomes an ApiError {status, code, message}; friendlyError() turns it into
//    text safe to show a user.
//  * On a 401 for a signed-in call the token is cleared and "bantai:session-expired" is fired.

const BASE_URL = String(import.meta.env?.VITE_API_BASE_URL ?? "http://localhost:8000/api/v1").replace(/\/+$/, "");
// localStorage keeps the signed-in session across tabs and browser restarts.
const tokenStore = () => globalThis.localStorage;
const TOKEN_KEY = "bantaiToken";
export const SESSION_EXPIRED_EVENT = "bantai:session-expired";

export const MAX_EML_BYTES = 5 * 1024 * 1024; // backend limit for one email

// ------------------------------------------------------------------ token
export function getToken() {
  try {
    const token = tokenStore()?.getItem(TOKEN_KEY);
    if (token) return token;

    const legacyToken = globalThis.sessionStorage?.getItem(TOKEN_KEY);
    if (!legacyToken) return null;
    tokenStore()?.setItem(TOKEN_KEY, legacyToken);
    globalThis.sessionStorage?.removeItem(TOKEN_KEY);
    return legacyToken;
  } catch { return null; }
}
export function setToken(token) {
  try { tokenStore()?.setItem(TOKEN_KEY, token); } catch { /* storage blocked: stay signed-out */ }
}
export function clearToken() {
  try {
    tokenStore()?.removeItem(TOKEN_KEY);
    globalThis.sessionStorage?.removeItem(TOKEN_KEY);
  } catch { /* ignore */ }
}

// Old prototype keys. 'bantaiUser' contains a PLAINTEXT password, so wipe it. Call once at startup.
export function purgeLegacyStorage() {
  try {
    for (const key of ["bantaiUser", "bantaiAuthenticated", "bantaiSystemPreferences"]) {
      globalThis.localStorage?.removeItem(key);
    }
  } catch { /* ignore */ }
}

// ------------------------------------------------------------------ errors
export class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

function toApiError(status, data) {
  const detail = data?.detail;
  if (detail && !Array.isArray(detail) && typeof detail === "object") {
    return new ApiError(status, detail.code || "error", detail.message || "The request failed.");
  }
  if (Array.isArray(detail) && detail.length) {            // request validation (422)
    const field = [...(detail[0].loc || [])].reverse().find((p) => typeof p === "string") || "input";
    return new ApiError(status, "validation_error", `Please check the "${field}" field: ${detail[0].msg || "invalid value"}.`);
  }
  return new ApiError(status, "error", "The request failed.");
}

const FRIENDLY = {
  network_error: "Cannot reach the BANTAI server. Check that the backend is running.",
  not_authenticated: "Your session has expired. Please sign in again.",
  invalid_token: "Your session has expired. Please sign in again.",
  too_large: "That email is too large (limit 5 MB).",
  file_too_large: "That file is larger than 5 MB.",
  body_too_long: "That email's text is too long to analyze.",
  invalid_base64: "The file could not be read. Please try another .eml file.",
  ml_unavailable: "The analysis service is unavailable right now. Please try again shortly.",
  storage_failed: "The scan could not be recorded, so no result was shown. Please try again.",
  configuration_error: "The server is misconfigured. Please contact an administrator.",
  password_reset_unavailable: "Password recovery is not configured. Please contact an administrator.",
  password_reset_rate_limited: "Too many password reset requests. Try again later.",
  invalid_reset_token: "This password reset link is invalid or has expired. Request a new link.",
  invalid_reset_authorization: "This password reset step expired. Request a new code.",
  invalid_otp: "That code is incorrect or expired. Check it and try again.",
  email_delivery_unavailable: "Email verification is not configured on the server.",
  email_delivery_failed: "The code could not be delivered. Please try again later.",
  verification_rate_limited: "A code was recently requested. Wait before requesting another.",
  email_not_verified: "Verify your email address before signing in.",
  username_already_registered: "That username is already in use.",
  google_login_unavailable: "Google sign-in is not configured on the server.",
  google_account_link_required: "Sign in to the existing account before linking Google.",
  invalid_oauth_ticket: "Google sign-in expired. Please try again.",
  invalid_web_handoff: "This sign-in link expired. Open the page from the BANTAI extension again.",
  google_state_invalid: "Google sign-in could not be verified. Please try again.",
  google_sign_in_failed: "Google sign-in could not be completed. Please try again.",
  google_sign_in_cancelled: "Google sign-in was cancelled.",
  password_setup_unavailable: "Password setup is not available for this account.",
};
export function friendlyError(error) {
  if (error instanceof ApiError) return FRIENDLY[error.code] || error.message;
  return "Something went wrong. Please try again.";
}

// ------------------------------------------------------------------ transport
function buildUrl(path, query) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query || {})) {
    if (value !== undefined && value !== null && value !== "") params.set(key, String(value));
  }
  const qs = params.toString();
  return `${BASE_URL}${path}${qs ? `?${qs}` : ""}`;
}

async function send(path, { method = "GET", body, query, auth = true } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const token = auth ? getToken() : null;
  if (token) headers.Authorization = `Bearer ${token}`;

  let response;
  try {
    response = await fetch(buildUrl(path, query), {
      method, headers, body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(0, "network_error", FRIENDLY.network_error);
  }

  if (!response.ok) {
    const data = await response.json().catch(() => null);
    if (response.status === 401 && token) {
      clearToken();
      globalThis.window?.dispatchEvent?.(new Event(SESSION_EXPIRED_EVENT));
    }
    throw toApiError(response.status, data);
  }
  return response;
}

async function json(path, options) {
  const response = await send(path, options);
  return response.status === 204 ? null : response.json();
}

// ------------------------------------------------------------------ auth
export async function register({ username, fullName, email, password, confirmPassword }) {
  return json("/auth/register", {
    method: "POST",
    auth: false,
    body: {
      username,
      full_name: fullName,
      email,
      password,
      confirm_password: confirmPassword,
    },
  });
}

export async function verifyRegistration({ email, code }) {
  const data = await json("/auth/register/verify", {
    method: "POST", auth: false, body: { email, code },
  });
  setToken(data.accessToken);
  return data.user;
}

export const resendRegistrationCode = (email) =>
  json("/auth/register/resend", { method: "POST", auth: false, body: { email } });

export async function login({ identifier, email, password }) {
  const data = await json("/auth/login", {
    method: "POST",
    auth: false,
    body: { identifier: identifier ?? email, password },
  });
  setToken(data.accessToken);
  return data.user;
}

export async function exchangeGoogleTicket(ticket) {
  const data = await json("/auth/google/exchange", {
    method: "POST", auth: false, body: { ticket },
  });
  setToken(data.accessToken);
  return data.user;
}

export async function exchangeWebHandoffTicket(ticket) {
  const data = await json("/auth/web-handoff/exchange", {
    method: "POST", auth: false, body: { ticket },
  });
  setToken(data.accessToken);
  return data.user;
}

export function startGoogleLogin() {
  globalThis.location.assign(`${BASE_URL}/auth/google/start`);
}

export const requestPasswordReset = (email) =>
  json("/auth/password-reset/request", {
    method: "POST",
    auth: false,
    body: { email },
  });

export const resendPasswordResetCode = (email) =>
  json("/auth/password-reset/resend", {
    method: "POST",
    auth: false,
    body: { email },
  });

export const verifyPasswordResetCode = ({ email, code }) =>
  json("/auth/password-reset/verify", {
    method: "POST",
    auth: false,
    body: { email, code },
  });

export const resetPassword = ({ token, newPassword, confirmPassword }) =>
  json("/auth/password-reset/confirm", {
    method: "POST",
    auth: false,
    body: {
      token,
      new_password: newPassword,
      confirm_password: confirmPassword,
    },
  });

export const requestGooglePasswordSetup = () =>
  json("/auth/google-password-setup/request", { method: "POST" });

export const confirmGooglePasswordSetup = ({ username, code, password, confirmPassword }) =>
  json("/auth/google-password-setup/confirm", {
    method: "POST",
    body: { username, code, password, confirm_password: confirmPassword },
  });

export async function logout() {
  try { await json("/auth/logout", { method: "POST" }); } catch { /* sign out locally regardless */ }
  clearToken();
}

export async function getMe() {
  return (await json("/auth/me")).user;
}

// ------------------------------------------------------------------ scanning
export async function fileToBase64(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

// Provide EITHER `file` (an .eml) OR `text` (pasted). Scanning always requires an account.
export async function scanEmail({ file, text }) {
  let body;
  if (file) {
    if (file.size > MAX_EML_BYTES) throw new ApiError(0, "file_too_large", FRIENDLY.file_too_large);
    body = { inputMethod: "eml_upload", encoding: "base64", fileName: file.name, content: await fileToBase64(file) };
  } else {
    body = { inputMethod: "raw_text", encoding: "text", content: text ?? "" };
  }
  return json("/scans", { method: "POST", body });
}

// ------------------------------------------------------------------ history / dashboard
export const listHistory = ({ q, level, range, limit, offset } = {}) =>
  json("/scans", { query: { q, level, range, limit, offset } });

export const getScan = (id) => json(`/scans/${encodeURIComponent(id)}`);

export const submitFeedback = (id, { isPredictionCorrect, suggestedLabel, explanationHelpful, comment }) =>
  json(`/scans/${encodeURIComponent(id)}/feedback`, {
    method: "POST", body: { isPredictionCorrect, suggestedLabel, explanationHelpful, comment },
  });

export const getDashboard = (range = "30") => json("/dashboard/summary", { query: { range } });

// CSV needs the Authorization header, so a plain <a href> cannot be used: fetch it, then save the blob.
export async function fetchHistoryCsv({ q, level, range } = {}) {
  const response = await send("/scans/export", { query: { q, level, range } });
  const disposition = response.headers.get("content-disposition") || "";
  const name = /filename="?([^";]+)"?/i.exec(disposition)?.[1] || "bantai-history.csv";
  return { blob: await response.blob(), fileName: name };
}

export function saveBlob(blob, fileName) {          // browser only
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

// ------------------------------------------------------------------ account
export const getProfile = () => json("/account/profile");

// changes: any of {fullName, jobTitle, profilePicture, email, currentPassword}. Only keys you pass are sent.
// Changing email REQUIRES currentPassword. profilePicture: null removes the picture.
export const updateProfile = (changes) => json("/account/profile", { method: "PATCH", body: changes });

export const changePassword = ({ currentPassword, newPassword }) =>
  json("/account/password", { method: "POST", body: { currentPassword, newPassword } });

export const getPreferences = () => json("/account/settings");
export const updatePreferences = (changes) => json("/account/settings", { method: "PATCH", body: changes });

// Settings.jsx calls the first toggle "enableShapAdvancedMode"; the API calls it "shapAdvancedMode".
export const preferencesToUi = (api) => ({
  enableShapAdvancedMode: !!api.shapAdvancedMode,
  autoSaveScanLogs: !!api.autoSaveScanLogs,
});
export const preferencesToApi = (ui) => {
  const out = {};
  if (typeof ui.enableShapAdvancedMode === "boolean") out.shapAdvancedMode = ui.enableShapAdvancedMode;
  if (typeof ui.autoSaveScanLogs === "boolean") out.autoSaveScanLogs = ui.autoSaveScanLogs;
  return out;
};

// ------------------------------------------------------------------ health
export const getHealth = () => json("/health", { auth: false });
