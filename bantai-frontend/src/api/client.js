// BANTAI API client: the ONLY place the frontend talks to the backend.
//
// Rules this module enforces for every screen:
//  * The bearer token lives in ONE place (below). Passwords are never stored in the browser.
//  * The Authorization header is sent only when a token exists AND the call is not a guest call.
//    (Sending "Bearer null" makes the backend answer 401, so we never do.)
//  * Every failure becomes an ApiError {status, code, message}; friendlyError() turns it into
//    text safe to show a user.
//  * On a 401 for a signed-in call the token is cleared and "bantai:session-expired" is fired.

const BASE_URL = String(import.meta.env?.VITE_API_BASE_URL ?? "http://localhost:8000/api/v1").replace(/\/+$/, "");

// sessionStorage = signed out when the tab closes (safer, fits the 8-hour sessions).
// Switch to localStorage here if you want "stay signed in" across tabs and restarts.
const tokenStore = () => globalThis.sessionStorage;
const TOKEN_KEY = "bantaiToken";
export const SESSION_EXPIRED_EVENT = "bantai:session-expired";

export const MAX_EML_BYTES = 5 * 1024 * 1024; // backend limit for one email

// ------------------------------------------------------------------ token
export function getToken() {
  try { return tokenStore()?.getItem(TOKEN_KEY) || null; } catch { return null; }
}
export function setToken(token) {
  try { tokenStore()?.setItem(TOKEN_KEY, token); } catch { /* storage blocked: stay signed-out */ }
}
export function clearToken() {
  try { tokenStore()?.removeItem(TOKEN_KEY); } catch { /* ignore */ }
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
export async function register({ fullName, email, password }) {
  const data = await json("/auth/register", {
    method: "POST", auth: false, body: { full_name: fullName, email, password },
  });
  setToken(data.accessToken);
  return data.user;
}

export async function login({ email, password }) {
  const data = await json("/auth/login", { method: "POST", auth: false, body: { email, password } });
  setToken(data.accessToken);
  return data.user;
}

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

// Provide EITHER `file` (an .eml) OR `text` (pasted). Pass signedIn:false from the GUEST page so a
// stored token is never attached (guest scans must stay anonymous).
export async function scanEmail({ file, text, signedIn }) {
  let body;
  if (file) {
    if (file.size > MAX_EML_BYTES) throw new ApiError(0, "file_too_large", FRIENDLY.file_too_large);
    body = { inputMethod: "eml_upload", encoding: "base64", fileName: file.name, content: await fileToBase64(file) };
  } else {
    body = { inputMethod: "raw_text", encoding: "text", content: text ?? "" };
  }
  return json("/scans", { method: "POST", body, auth: !!signedIn });
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
