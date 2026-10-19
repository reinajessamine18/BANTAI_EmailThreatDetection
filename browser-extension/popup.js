const app = document.querySelector("#app");
const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000/api/v1";
const DEFAULT_WEB_APP_URL = "http://localhost:5173";

let session = null;
let currentEmail = null;
let currentResult = null;
let currentError = "";
let authMode = "login";
let view = "loading";
let profileReturnView = "ready";

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

function send(message) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        resolve({ error: "The BANTAI extension could not complete that action." });
      } else {
        resolve(response || {});
      }
    });
  });
}

function api(path, { method = "GET", body, auth = true } = {}) {
  return send({
    type: "bantai:api-request",
    request: { path, method, body, auth },
  });
}

function footer(status = "SYNC ENGINE READY") {
  return `<footer class="footer"><span class="status">● ${escapeHtml(status)}</span><span>BANTAI · 1.0.0</span></footer>`;
}

function shell(content, status) {
  app.innerHTML = `<div class="shell">${content}${footer(status)}</div>`;
}

function header(action = "") {
  return `<header class="topbar"><div class="brand"><span class="brand-mark">⬟</span><span>Bantai.</span></div>${action}</header>`;
}

function showAuth(error = "") {
  view = "auth";
  const signup = authMode === "signup";
  shell(`
    ${header()}
    <section class="content">
      <div class="auth-intro">
        <span class="pill">● BANTAI SCAN ENGINE</span>
        <h1>${signup ? "Create your account" : "Sign in to BANTAI"}</h1>
        <p>Link this extension to your account to scan emails from Gmail.</p>
      </div>
      <div class="notice">Your existing BANTAI account and backend are used. Email content is sent only when you choose to scan.</div>
      <div class="tabs" role="tablist" aria-label="Account action">
        <button type="button" data-mode="login" aria-selected="${!signup}">Sign In</button>
        <button type="button" data-mode="signup" aria-selected="${signup}">Sign Up</button>
      </div>
      ${error ? `<div class="notice error" role="alert">${escapeHtml(error)}</div>` : ""}
      <form class="form" id="auth-form">
        ${signup ? `<div class="field"><label for="full-name">Full name</label><input id="full-name" name="fullName" autocomplete="name" required minlength="2" maxlength="120"></div>` : ""}
        <div class="field"><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" required maxlength="254"></div>
        <div class="field"><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="${signup ? "new-password" : "current-password"}" required minlength="${signup ? "10" : "1"}" maxlength="128"></div>
        <button class="button button-primary" type="submit">${signup ? "Create BANTAI Account →" : "Sign In to BANTAI →"}</button>
        ${!signup ? `<button class="text-button small" type="button" id="forgot-password">Forgot password?</button>` : ""}
      </form>
    </section>`, "ACCOUNT REQUIRED");

  app.querySelectorAll("[data-mode]").forEach((button) => {
    button.addEventListener("click", () => {
      authMode = button.dataset.mode;
      showAuth();
    });
  });
  app.querySelector("#auth-form").addEventListener("submit", submitAuth);
  app.querySelector("#forgot-password")?.addEventListener("click", () => {
    chrome.tabs.create({ url: `${session.webAppUrl}/forgot-password` });
  });
}

async function submitAuth(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const signup = authMode === "signup";
  const body = signup
    ? {
        full_name: String(form.get("fullName")).trim(),
        email: String(form.get("email")).trim(),
        password: String(form.get("password")),
      }
    : {
        email: String(form.get("email")).trim(),
        password: String(form.get("password")),
      };
  const button = app.querySelector('button[type="submit"]');
  button.disabled = true;
  button.innerHTML = `<span class="spinner"></span> Connecting...`;
  const response = await api(`/auth/${signup ? "register" : "login"}`, {
    method: "POST",
    body,
    auth: false,
  });
  if (!response.ok) {
    showAuth(response.error?.message || "Could not sign in. Please try again.");
    return;
  }
  if (
    typeof response.data?.accessToken !== "string" ||
    !response.data.accessToken ||
    !response.data.user
  ) {
    showAuth("The BANTAI account service returned an incomplete sign-in response.");
    return;
  }
  const saved = await send({
    type: "bantai:set-session",
    accessToken: response.data.accessToken,
    user: response.data.user,
  });
  if (!saved.ok) {
    showAuth(saved.error || "Could not save the sign-in session.");
    return;
  }
  session.accessToken = response.data.accessToken;
  session.user = response.data.user;
  await showReady();
}

async function extractActiveEmail() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id || !tab.url?.startsWith("https://mail.google.com/")) {
    return {
      ok: false,
      message: "Open an individual email in Gmail to begin. Gmail in Chrome is currently supported.",
    };
  }
  try {
    await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content.js"] });
    return await chrome.tabs.sendMessage(tab.id, { type: "bantai:extract-active-email" });
  } catch {
    return {
      ok: false,
      message: "BANTAI could not read this Gmail tab. Reload Gmail, open a message, and try again.",
    };
  }
}

async function showReady(error = "") {
  view = "ready";
  currentError = error;
  const [me] = await Promise.all([
    session.accessToken ? api("/auth/me") : Promise.resolve({ ok: false }),
  ]);
  if (!me.ok) {
    if (me.error?.status === 401) {
      await send({ type: "bantai:clear-session" });
      session.accessToken = null;
      session.user = null;
      showAuth("Your BANTAI session expired. Sign in again to continue.");
    } else {
      showConnectionError(me.error?.message || "The BANTAI server is unavailable.");
    }
    return;
  }
  session.user = me.data.user;

  const extracted = await extractActiveEmail();
  currentEmail = extracted?.ok ? extracted : null;
  const user = session.user || {};
  const emailCard = currentEmail
    ? `<article class="card message-card">
        <span class="pill">● EMAIL IN ACTIVE TAB</span>
        <h1 class="message-title">${escapeHtml(currentEmail.subject || "No subject")}</h1>
        <div class="message-sender">From: ${escapeHtml(currentEmail.sender || "Sender address unavailable")}</div>
        <div class="message-meta"><span>Gmail · message content stays in memory</span><span>READY</span></div>
      </article>`
    : `<article class="card center" style="padding:25px 16px">
        <div class="avatar">⌕</div>
        <h2 class="section-title">NO ACTIVE EMAIL</h2>
        <p class="muted">${escapeHtml(extracted?.message || "Open an individual email in Gmail to begin.")}</p>
        <button class="button button-quiet" id="retry-extract" type="button">CHECK ACTIVE TAB</button>
      </article>`;

  shell(`
    ${header(`<button class="icon-button" id="profile-button" aria-label="Open profile">◉</button>`)}
    <section class="content">
      <div class="status-row">
        <span class="account">● ${escapeHtml(user.fullName || user.email || "BANTAI ACCOUNT")}</span>
        <span class="pill">● ACCOUNT LINKED</span>
      </div>
      ${currentError ? `<div class="notice error" role="alert">${escapeHtml(currentError)}</div>` : ""}
      ${emailCard}
      <div class="stack" style="margin-top:14px">
        <button class="button button-primary" id="scan-button" type="button" ${currentEmail ? "" : "disabled"}>
          ◉ &nbsp; SCAN EMAIL FOR THREATS
        </button>
      </div>
      <p class="privacy">🔒 Scan results are handled by your BANTAI backend. Email body text is not saved in the extension. Server history behavior follows your existing BANTAI account settings.</p>
    </section>`, "SYNC ENGINE READY");

  app.querySelector("#profile-button").addEventListener("click", showProfile);
  app.querySelector("#retry-extract")?.addEventListener("click", () => showReady());
  app.querySelector("#scan-button").addEventListener("click", scanActiveEmail);
}

function showConnectionError(message) {
  view = "error";
  shell(`
    ${header()}
    <section class="content">
      <article class="card center" style="padding:24px 16px">
        <div class="avatar" style="border-color:var(--red);color:var(--red)">!</div>
        <h1 style="font-size:17px">BANTAI SERVICE UNAVAILABLE</h1>
        <p class="muted">${escapeHtml(message)}</p>
        <div class="stack" style="margin-top:16px">
          <button class="button button-danger" id="retry-connection" type="button">RETRY CONNECTION</button>
          <button class="button button-quiet" id="connection-settings" type="button">CONNECTION SETTINGS</button>
        </div>
      </article>
    </section>`, "SYSTEM DEGRADED");
  app.querySelector("#retry-connection").addEventListener("click", initialize);
  app.querySelector("#connection-settings").addEventListener("click", showSettings);
}

function showScanning() {
  view = "scanning";
  shell(`
    ${header()}
    <section class="content center" style="padding-top:42px">
      <div class="avatar" style="width:76px;height:76px;font-size:30px"><span class="spinner"></span></div>
      <h1 style="font-size:19px;margin:18px 0 8px">ANALYZING EMAIL</h1>
      <p class="muted">Sending the selected message to the BANTAI analysis service.</p>
      <div class="card" style="margin-top:25px;text-align:left">
        <div class="stack small">
          <span>✓ &nbsp; EXTRACTED ACTIVE GMAIL MESSAGE</span>
          <span>◌ &nbsp; RUNNING BANTAI ANALYSIS AND EXPLANATION</span>
          <span class="muted">◌ &nbsp; WAITING FOR SERVER RESULT</span>
        </div>
      </div>
    </section>`, "ANALYSIS IN PROGRESS");
}

async function scanActiveEmail() {
  if (!currentEmail || view === "scanning") return;
  showScanning();
  const headers = [];
  if (currentEmail.sender) headers.push(`From: ${currentEmail.sender}`);
  if (currentEmail.subject) headers.push(`Subject: ${currentEmail.subject}`);
  const unshownLinks = (currentEmail.links || []).filter((url) => !currentEmail.body.includes(url));
  const body = unshownLinks.length
    ? `${currentEmail.body}\n\nLinks:\n${unshownLinks.join("\n")}`
    : currentEmail.body;
  const content = `${headers.join("\n")}${headers.length ? "\n\n" : ""}${body}`;
  const response = await api("/scans", {
    method: "POST",
    body: { inputMethod: "raw_text", encoding: "text", content },
  });
  if (!response.ok) {
    const message = response.error?.status === 401
      ? "Your BANTAI session expired. Sign in again to continue."
      : response.error?.message || "The scan failed. Please try again.";
    if (response.error?.status === 401) {
      session.accessToken = null;
      session.user = null;
      showAuth(message);
    } else {
      await showReady(message);
    }
    return;
  }
  const data = response.data;
  if (
    !data ||
    !["safe", "suspicious", "phishing"].includes(data.riskLevel) ||
    !Number.isFinite(data.threatScore) ||
    data.threatScore < 0 ||
    data.threatScore > 100 ||
    !Array.isArray(data.explanations)
  ) {
    await showReady("The BANTAI server returned an incomplete analysis. No result was displayed.");
    return;
  }
  currentResult = data;
  showResult();
}

function showResult() {
  view = "result";
  const result = currentResult;
  const risk = result.riskLevel;
  const labels = { phishing: "Phishing detected", suspicious: "Suspicious email", safe: "No threat detected" };
  const score = Math.round(result.threatScore);
  const probability = Number.isFinite(Number(result.phishingProbability))
    ? `${(Number(result.phishingProbability) * 100).toFixed(1)}%`
    : "Not provided";
  const explanations = Array.isArray(result.explanations) ? result.explanations : [];
  const explanationCards = explanations.length
    ? explanations.slice(0, 6).map((item) => `
        <article class="explanation">
          <div class="explanation-title">${escapeHtml(item.title || item.feature || "Analysis indicator")}</div>
          <div class="explanation-text">${escapeHtml(item.insight || item.direction || "")}${item.kind === "word" && Number.isFinite(Number(item.value)) ? ` · SHAP ${Number(item.value).toFixed(3)} log-odds` : ""}</div>
        </article>`).join("")
    : `<div class="notice">The analysis returned no explanation items.</div>`;
  const saveNotice = result.saved
    ? `Recorded in Threat History (${escapeHtml(result.scanCode || "scan")}).`
    : "The scan was processed, but your account settings did not save it to Threat History.";

  shell(`
    ${header(`<button class="icon-button" id="profile-button" aria-label="Open profile">◉</button>`)}
    <section class="content stack">
      <div class="result-banner ${risk}">● &nbsp; ${labels[risk]}</div>
      <div class="card score-card">
        <div><div class="score ${risk}">${escapeHtml(score)}</div><div class="score-caption">THREAT SCORE / 100</div></div>
        <div class="score-detail"><strong>${escapeHtml(result.riskTier || "Risk tier not provided")}</strong><span class="muted small">Model phishing probability: ${escapeHtml(probability)}</span><span class="muted small">${escapeHtml(currentEmail?.subject || "Scanned Gmail message")}</span></div>
      </div>
      <div>
        <h2 class="section-title">◈ &nbsp; ANALYSIS EXPLANATION</h2>
        <div class="stack" style="margin-top:9px">${explanationCards}</div>
      </div>
      <div class="notice ${result.saved ? "success" : ""}">${saveNotice}</div>
      <button class="button button-primary" id="scan-another" type="button">SCAN ANOTHER EMAIL</button>
      <button class="text-button small" id="history-link" type="button">Open Threat History ↗</button>
    </section>`, "ANALYSIS COMPLETE");
  app.querySelector("#profile-button").addEventListener("click", showProfile);
  app.querySelector("#scan-another").addEventListener("click", () => showReady());
  app.querySelector("#history-link").addEventListener("click", () => {
    chrome.tabs.create({ url: `${session.webAppUrl}/app/threat-history` });
  });
}

function showProfile() {
  if (view !== "profile" && view !== "settings") profileReturnView = view;
  view = "profile";
  const user = session.user || {};
  const initials = (user.fullName || user.email || "B").trim().charAt(0).toUpperCase();
  shell(`
    ${header(`<button class="icon-button" id="back-button" aria-label="Back">‹</button>`)}
    <section class="content">
      <div class="drawer-profile">
        <div class="avatar">${escapeHtml(initials)}</div>
        <h1>${escapeHtml(user.fullName || "BANTAI User")}</h1>
        <div class="muted">${escapeHtml(user.email || "")}</div>
        <div style="margin-top:12px"><span class="pill">${escapeHtml(user.role || "ACCOUNT")}</span></div>
      </div>
      <div class="eyebrow">BANTAI ACCOUNT</div>
      <nav class="nav-list" aria-label="BANTAI account pages">
        <a class="nav-link" href="${escapeHtml(session.webAppUrl)}/app/dashboard" target="_blank">System Overview Dashboard <span>↗</span></a>
        <a class="nav-link" href="${escapeHtml(session.webAppUrl)}/app/threat-history" target="_blank">Threat History &amp; Audit Logs <span>↗</span></a>
        <a class="nav-link" href="${escapeHtml(session.webAppUrl)}/app/settings" target="_blank">System Settings &amp; Preferences <span>↗</span></a>
      </nav>
      <button class="button button-quiet" id="settings-button" type="button">Extension connection settings</button>
      <button class="button button-danger" id="logout-button" type="button" style="margin-top:12px">SIGN OUT OF EXTENSION</button>
    </section>`, "SESSION SECURE");
  app.querySelector("#back-button").addEventListener("click", () => {
    if (profileReturnView === "result" && currentResult) showResult();
    else showReady();
  });
  app.querySelector("#settings-button").addEventListener("click", showSettings);
  app.querySelector("#logout-button").addEventListener("click", logout);
}

function showSettings(error = "") {
  view = "settings";
  shell(`
    ${header(`<button class="icon-button" id="back-button" aria-label="Back">‹</button>`)}
    <section class="content">
      <h1 style="font-size:19px;margin:3px 0 7px">Connection settings</h1>
      <p class="muted small">Choose your BANTAI API server. A permission prompt appears if the server is not the local default.</p>
      ${error ? `<div class="notice error" role="alert">${escapeHtml(error)}</div>` : ""}
      <form class="form" id="settings-form">
        <div class="field"><label for="api-base">API base URL</label><input id="api-base" name="apiBaseUrl" value="${escapeHtml(session.apiBaseUrl || DEFAULT_API_BASE_URL)}" required></div>
        <div class="field"><label for="web-app">BANTAI web app URL</label><input id="web-app" name="webAppUrl" value="${escapeHtml(session.webAppUrl || DEFAULT_WEB_APP_URL)}" required></div>
        <button class="button button-primary" type="submit">SAVE CONNECTION</button>
      </form>
      <p class="privacy">Use HTTPS for remote servers. The extension requests access only to the server host you enter. Never use an untrusted API endpoint.</p>
    </section>`, "SETTINGS");
  app.querySelector("#back-button").addEventListener("click", showProfile);
  app.querySelector("#settings-form").addEventListener("submit", saveSettings);
}

async function saveSettings(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const apiBaseUrl = String(form.get("apiBaseUrl")).trim().replace(/\/+$/, "");
  const webAppUrl = String(form.get("webAppUrl")).trim().replace(/\/+$/, "");
  let apiUrl;
  let webUrl;
  try {
    apiUrl = new URL(apiBaseUrl);
    webUrl = new URL(webAppUrl);
    if (!["http:", "https:"].includes(apiUrl.protocol) || !["http:", "https:"].includes(webUrl.protocol)) {
      throw new Error("Addresses must use HTTP or HTTPS.");
    }
    if (apiUrl.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(apiUrl.hostname)) {
      throw new Error("Use HTTPS for non-local BANTAI servers.");
    }
    if (!/\/api\/v1$/i.test(apiUrl.pathname.replace(/\/+$/, ""))) {
      throw new Error("The API address must end with /api/v1.");
    }
    if (webUrl.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(webUrl.hostname)) {
      throw new Error("Use HTTPS for the remote web app.");
    }
  } catch (error) {
    showSettings(error.message || "Enter valid API and web app URLs.");
    return;
  }

  const originPattern = `${apiUrl.origin}/*`;
  const hasPermission = await chrome.permissions.contains({ origins: [originPattern] });
  if (!hasPermission) {
    const granted = await chrome.permissions.request({ origins: [originPattern] });
    if (!granted) {
      showSettings("The extension needs permission to contact that BANTAI API host.");
      return;
    }
  }
  const saved = await send({ type: "bantai:save-settings", apiBaseUrl, webAppUrl });
  if (!saved.ok) {
    showSettings(saved.error || "Could not save connection settings.");
    return;
  }
  session.apiBaseUrl = apiBaseUrl;
  session.webAppUrl = webAppUrl;
  await showProfile();
}

async function logout() {
  await api("/auth/logout", { method: "POST" });
  await send({ type: "bantai:clear-session" });
  session.accessToken = null;
  session.user = null;
  currentEmail = null;
  currentResult = null;
  authMode = "login";
  showAuth();
}

async function initialize() {
  session = await send({ type: "bantai:get-session" });
  if (session.error) {
    shell(`${header()}<section class="content"><div class="notice error">${escapeHtml(session.error)}</div></section>`, "EXTENSION ERROR");
    return;
  }
  session.apiBaseUrl ||= DEFAULT_API_BASE_URL;
  session.webAppUrl ||= DEFAULT_WEB_APP_URL;
  if (!session.accessToken) {
    showAuth();
    return;
  }
  const me = await api("/auth/me");
  if (!me.ok) {
    if (me.error?.status === 401) {
      await send({ type: "bantai:clear-session" });
      session.accessToken = null;
      session.user = null;
      showAuth("Your BANTAI session expired. Sign in again to continue.");
    } else {
      showConnectionError(me.error?.message || "The BANTAI server is unavailable.");
    }
    return;
  }
  session.user = me.data.user;
  await showReady();
}

initialize();
