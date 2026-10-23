const app = document.querySelector("#app");
const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000/api/v1";
const DEFAULT_WEB_APP_URL = "http://localhost:5173";

let session = null;
let currentEmail = null;
let currentResult = null;
let currentError = "";
let authStep = "login";
let authEmail = "";
let resetAuthorization = null;
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

function shell(content) {
  app.innerHTML = `<div class="shell">${content}</div>`;
}

function header(action = "") {
  return `<header class="topbar"><div class="brand">BANTAI<span>.</span></div>${action}</header>`;
}

function webAppPage(path) {
  return new URL(path, session.webAppUrl || DEFAULT_WEB_APP_URL).toString();
}

async function openAuthenticatedWebPage(path, trigger) {
  trigger.disabled = true;
  try {
    const response = await api("/auth/web-handoff", { method: "POST" });
    if (!response?.ok) {
      if (response?.error?.status === 401) {
        session.accessToken = null;
        session.user = null;
        showAuth("Your BANTAI session expired. Log in again to continue.");
        return;
      }
      throw new Error(
        response?.error?.message
          || response?.error
          || "BANTAI could not prepare your website sign-in.",
      );
    }
    if (typeof response.data?.ticket !== "string") {
      throw new Error("BANTAI could not prepare your website sign-in. Please try again.");
    }

    const target = new URL(path, session.webAppUrl || DEFAULT_WEB_APP_URL);
    target.hash = new URLSearchParams({
      bantai_handoff: response.data.ticket,
    }).toString();
    await new Promise((resolve, reject) => {
      chrome.tabs.create({ url: target.toString() }, (tab) => {
        const error = chrome.runtime.lastError;
        if (error) reject(new Error(error.message));
        else if (!tab?.id) reject(new Error("Chrome did not open the BANTAI website tab."));
        else resolve(tab);
      });
    });
  } catch (error) {
    let feedback = app.querySelector("#web-page-error");
    if (!feedback) {
      feedback = document.createElement("div");
      feedback.id = "web-page-error";
      feedback.className = "notice error";
      feedback.setAttribute("role", "alert");
      app.querySelector(".nav-list")?.before(feedback);
    }
    feedback.textContent = error.message || "BANTAI could not open the website. Please try again.";
  } finally {
    if (trigger.isConnected) trigger.disabled = false;
  }
}

function showAuth(error = "", notice = "") {
  view = "auth";
  const login = authStep === "login";
  const reset = authStep.startsWith("reset-");
  const title = {
    login: "Log in",
    "reset-email": "Reset your password",
    "reset-verify": "Verify your reset code",
    "reset-password": "Choose a new password",
  }[authStep];
  const passwordInput = (id, name, label, autocomplete, placeholder, confirmation = false) => `
    <div class="field">
      <div class="field-heading">
        <label for="${id}">${label}</label>
        ${login && id === "password" ? `<button class="forgot-link" type="button" id="forgot-password">Forgot password?</button>` : ""}
      </div>
      <div class="password-input">
        <input id="${id}" name="${name}" type="password" autocomplete="${autocomplete}" placeholder="${placeholder}" required minlength="${confirmation ? 10 : 1}" maxlength="128">
        <button class="password-toggle" type="button" data-password-toggle="${id}" aria-label="Show ${label.toLowerCase()}" aria-pressed="false">
          <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z"></path><circle cx="12" cy="12" r="3"></circle></svg>
        </button>
      </div>
    </div>`;
  const fields = login
    ? `
      <div class="field"><label for="identifier">Username or Email</label><input id="identifier" name="identifier" autocomplete="username" placeholder="Username or name@company.com" required maxlength="254" value="${escapeHtml(authEmail)}"></div>
      ${passwordInput("password", "password", "Password", "current-password", "••••••••••••")}`
    : authStep === "reset-email"
      ? `<div class="field"><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" placeholder="name@company.com" required maxlength="254" value="${escapeHtml(authEmail)}"></div>`
      : authStep === "reset-verify"
        ? `
          <div class="notice">Enter the six-digit code sent to <strong>${escapeHtml(authEmail)}</strong>.</div>
          <div class="field"><label for="code">Six-digit code</label><input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" placeholder="000000" required minlength="6" maxlength="6" pattern="[0-9]{6}"></div>`
        : `
          ${passwordInput("password", "password", "New password", "new-password", "At least 10 characters", true)}
          ${passwordInput("confirm-password", "confirmPassword", "Confirm new password", "new-password", "Confirm your password", true)}`;
  const submitLabel = {
    login: "Log In",
    "reset-email": "Send Reset Code",
    "reset-verify": "Verify Reset Code",
    "reset-password": "Save New Password",
  }[authStep];
  const contextButtons = login
    ? `<div class="auth-divider"><span>OR</span></div>
       <button class="button button-google" type="button" id="google-login"><span aria-hidden="true" class="google-mark">G</span><span>Continue with Google</span></button>
       <div class="signup-prompt"><p>New to BANTAI?</p>
       <a class="auth-link" id="website-signup" target="_blank" rel="noopener noreferrer">Create an account on our website</a></div>`
    : authStep === "reset-email"
      ? `<button class="text-button small" type="button" id="show-login">Back to log in</button>`
      : authStep === "reset-verify"
        ? `<button class="text-button small" type="button" id="resend-code">Resend reset code</button>
           <button class="text-button small" type="button" id="show-login">Back to log in</button>`
        : `<button class="text-button small" type="button" id="show-login">Back to log in</button>`;
  shell(`
    <section class="auth-screen">
      <div class="auth-card">
      <div class="auth-intro">
        <div class="auth-logo" aria-label="BANTAI">
          BANTAI<span>.</span>
        </div>
        <h1>${title}</h1>
        <p>${reset ? "Securely recover access to your BANTAI account." : "Access the BANTAI threat intelligence platform."}</p>
      </div>
      ${error || notice ? `<div class="auth-feedback">
        ${error ? `<div class="notice error" role="alert">${escapeHtml(error)}</div>` : ""}
        ${notice ? `<div class="notice success" role="status">${escapeHtml(notice)}</div>` : ""}
      </div>` : ""}
      <form class="form" id="auth-form">
        ${fields}
        <button class="button button-primary" type="submit">${submitLabel}</button>
      </form>
      ${contextButtons ? `<div class="auth-options">${contextButtons}</div>` : ""}
      </div>
    </section>`);

  app.querySelector("#auth-form").addEventListener("submit", submitAuth);
  app.querySelectorAll("[data-password-toggle]").forEach((button) => {
    button.addEventListener("click", () => {
      const input = app.querySelector(`#${button.dataset.passwordToggle}`);
      const reveal = input.type === "password";
      input.type = reveal ? "text" : "password";
      button.setAttribute("aria-pressed", String(reveal));
      const label = reveal ? "Hide password" : "Show password";
      button.setAttribute("aria-label", label);
      button.innerHTML = reveal
        ? `<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="m3 3 18 18M10.6 10.6a2 2 0 0 0 2.8 2.8"></path><path d="M9.9 5.2A10.8 10.8 0 0 1 12 5c6.4 0 10 7 10 7a17.2 17.2 0 0 1-3.1 3.8M6.2 6.2C3.5 8 2 12 2 12s3.6 7 10 7a10 10 0 0 0 4-.8"></path></svg>`
        : `<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
    });
  });
  app.querySelector("#forgot-password")?.addEventListener("click", () => {
    authStep = "reset-email";
    resetAuthorization = null;
    if (!authEmail.includes("@")) authEmail = "";
    showAuth();
  });
  const signupLink = app.querySelector("#website-signup");
  if (signupLink) {
    signupLink.href = webAppPage("/signup");
  }
  app.querySelector("#show-login")?.addEventListener("click", () => {
    authStep = "login";
    resetAuthorization = null;
    showAuth();
  });
  app.querySelector("#resend-code")?.addEventListener("click", resendAuthCode);
  app.querySelector("#google-login")?.addEventListener("click", googleLogin);
}

async function submitAuth(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const step = authStep;
  const button = app.querySelector('button[type="submit"]');
  button.disabled = true;
  button.innerHTML = `<span class="spinner"></span> Please wait...`;
  let response;
  if (step === "login") {
    authEmail = String(form.get("identifier")).trim();
    response = await api("/auth/login", {
      method: "POST",
      body: { identifier: authEmail, password: String(form.get("password")) },
      auth: false,
    });
  } else if (step === "reset-email") {
    authEmail = String(form.get("email")).trim();
    response = await api("/auth/password-reset/request", {
      method: "POST",
      body: { email: authEmail },
      auth: false,
    });
    if (response.ok) {
      authStep = "reset-verify";
      showAuth("", response.data?.message || "If the address is eligible, a code may be delivered. Check your inbox and spam folder.");
      return;
    }
  } else if (step === "reset-verify") {
    response = await api("/auth/password-reset/verify", {
      method: "POST",
      body: { email: authEmail, code: String(form.get("code")).trim() },
      auth: false,
    });
    if (response.ok && typeof response.data?.resetAuthorization === "string") {
      resetAuthorization = response.data.resetAuthorization;
      authStep = "reset-password";
      showAuth();
      return;
    }
  } else {
    const password = String(form.get("password"));
    if (password !== String(form.get("confirmPassword"))) {
      showAuth("Passwords do not match.");
      return;
    }
    response = await api("/auth/password-reset/confirm", {
      method: "POST",
      body: {
        token: resetAuthorization,
        new_password: password,
        confirm_password: String(form.get("confirmPassword")),
      },
      auth: false,
    });
    if (response.ok) {
      authStep = "login";
      resetAuthorization = null;
      showAuth("", response.data?.message || "Password reset successfully. Log in with your new password.");
      return;
    }
  }
  if (!response.ok) {
    showAuth(response.error?.message || "Could not sign in. Please try again.");
    return;
  }
  if (step === "login") {
    await establishSession(response.data);
  }
}

async function establishSession(data) {
  if (
    typeof data?.accessToken !== "string" ||
    !data.accessToken ||
    !data.user
  ) {
    showAuth("The BANTAI account service returned an incomplete sign-in response.");
    return;
  }
  const saved = await send({
    type: "bantai:set-session",
    accessToken: data.accessToken,
    user: data.user,
  });
  if (!saved.ok) {
    showAuth(saved.error || "Could not save the sign-in session.");
    return;
  }
  session.accessToken = data.accessToken;
  session.user = data.user;
  await showReady();
}

async function resendAuthCode() {
  const button = app.querySelector("#resend-code");
  button.disabled = true;
  button.innerHTML = `<span class="spinner"></span> Sending...`;
  const response = await api("/auth/password-reset/resend", {
    method: "POST",
    body: { email: authEmail },
    auth: false,
  });
  showAuth(
    response.ok ? "" : response.error?.message || "The code could not be resent.",
    response.ok
      ? response.data?.message || "If eligible, a new code may be delivered."
      : "",
  );
}

function googleOAuthErrorMessage(code) {
  const messages = {
    google_login_unavailable: "Google sign-in is not configured on this BANTAI server.",
    google_extension_not_configured: "This extension is not allowlisted for Google sign-in. Contact your BANTAI administrator.",
    google_sign_in_cancelled: "Google sign-in was cancelled. You can try again.",
    google_state_invalid: "The Google sign-in session expired or was invalid. Please try again.",
    google_account_link_required: "A BANTAI account already uses this email. Log in to that account instead of linking it through Google.",
    google_sign_in_failed: "Google could not verify this sign-in. Please try again.",
  };
  return messages[code] || "Google sign-in could not be completed. Please try again.";
}

async function googleLogin() {
  const button = app.querySelector("#google-login");
  if (!chrome.identity?.launchWebAuthFlow) {
    showAuth("Google sign-in is not available in this browser profile.");
    return;
  }
  button.disabled = true;
  button.innerHTML = `<span class="spinner"></span> Connecting to Google...`;
  let redirectUrl;
  try {
    const baseUrl = new URL(session.apiBaseUrl || DEFAULT_API_BASE_URL);
    const extensionRedirectUri = chrome.identity.getRedirectURL("oauth2");
    const start = new URL(`${baseUrl.toString().replace(/\/+$/, "")}/auth/google/start`);
    start.searchParams.set("extension_redirect_uri", extensionRedirectUri);
    redirectUrl = await new Promise((resolve, reject) => {
      chrome.identity.launchWebAuthFlow(
        { url: start.toString(), interactive: true },
        (result) => {
          if (chrome.runtime.lastError) reject(new Error("Google sign-in could not be completed."));
          else resolve(result);
        },
      );
    });
  } catch (error) {
    showAuth(error.message || "Google sign-in could not be completed.");
    return;
  }
  try {
    const result = new URL(redirectUrl);
    const params = new URLSearchParams(result.search);
    const errorCode = params.get("error");
    if (errorCode) {
      showAuth(googleOAuthErrorMessage(errorCode));
      return;
    }
    const ticket = params.get("oauth_ticket");
    if (!ticket) {
      showAuth("The Google sign-in response was incomplete. Please try again.");
      return;
    }
    const response = await api("/auth/google/exchange", {
      method: "POST",
      body: { ticket },
      auth: false,
    });
    if (!response.ok) {
      showAuth(response.error?.message || "Google sign-in could not be completed.");
      return;
    }
    await establishSession(response.data);
  } catch {
    showAuth("Google sign-in could not be completed. Please try again.");
  }
}

async function extractActiveEmail() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let activeUrl;
  try {
    activeUrl = new URL(tab?.url || "");
  } catch {
    activeUrl = null;
  }
  if (!tab?.id || activeUrl?.origin !== "https://mail.google.com") {
    return {
      ok: false,
      message: "Open an individual email in Gmail to begin. Gmail in Chrome is currently supported.",
    };
  }
  try {
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      files: ["content.js"],
    });
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
      showAuth("Your BANTAI session expired. Log in again to continue.");
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
        <h1 class="message-title">${escapeHtml(currentEmail.subject || "No subject")}</h1>
        ${currentEmail.sender ? `<div class="message-sender">From: ${escapeHtml(currentEmail.sender)}</div>` : ""}
        <div class="message-meta"><span>Gmail · content stays in memory</span><span>READY</span></div>
      </article>`
    : `<article class="card center" style="padding:25px 16px">
        <div class="avatar">⌕</div>
        <h2 class="section-title">NO SCANNABLE TEXT</h2>
        <p class="muted">${escapeHtml(extracted?.message || "Open an individual message in Gmail to begin.")}</p>
        <button class="button button-quiet" id="retry-extract" type="button">CHECK ACTIVE TAB</button>
      </article>`;

  shell(`
    ${header(`<button class="icon-button profile-button" id="profile-button" type="button" aria-label="Open profile" title="Open profile"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8" r="3.5"></circle><path d="M5 20c.7-3.4 3.1-5.5 7-5.5s6.3 2.1 7 5.5"></path></svg></button>`)}
    <section class="content">
      <div class="status-row">
        <span class="account">${escapeHtml(user.fullName || user.email || "BANTAI ACCOUNT")}</span>
      </div>
      ${currentError ? `<div class="notice error" role="alert">${escapeHtml(currentError)}</div>` : ""}
      ${emailCard}
      <div class="stack" style="margin-top:14px">
        <button class="button button-primary" id="scan-button" type="button" ${currentEmail ? "" : "disabled"}>
          SCAN EMAIL FOR THREATS
        </button>
      </div>
    </section>`);

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
        </div>
      </article>
    </section>`);
  app.querySelector("#retry-connection").addEventListener("click", initialize);
}

function showScanning() {
  view = "scanning";
  shell(`
    ${header()}
    <section class="content center" style="padding-top:42px">
      <div class="avatar" style="width:76px;height:76px;font-size:30px"><span class="spinner"></span></div>
      <h1 style="font-size:19px;margin:18px 0 8px">ANALYZING EMAIL</h1>
      <p class="muted">Checking the selected message for threats.</p>
      <div class="card" style="margin-top:25px;text-align:left">
        <div class="stack small">
          <span>Message ready for analysis</span>
          <span>Checking for threats and preparing an explanation</span>
          <span class="muted">Preparing results</span>
        </div>
      </div>
    </section>`);
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
    ${header(`<button class="icon-button profile-button" id="profile-button" type="button" aria-label="Open profile" title="Open profile"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8" r="3.5"></circle><path d="M5 20c.7-3.4 3.1-5.5 7-5.5s6.3 2.1 7 5.5"></path></svg></button>`)}
    <section class="content stack">
      <div class="result-banner ${risk}">${labels[risk]}</div>
      <div class="card score-card">
        <div><div class="score ${risk}">${escapeHtml(score)}</div><div class="score-caption">THREAT SCORE / 100</div></div>
        <div class="score-detail"><strong>${escapeHtml(result.riskTier || "Risk tier not provided")}</strong><span class="muted small">Model phishing probability: ${escapeHtml(probability)}</span><span class="muted small">${escapeHtml(currentEmail?.subject || "Scanned Gmail message")}</span></div>
      </div>
      <div>
        <h2 class="section-title">ANALYSIS EXPLANATION</h2>
        <div class="stack" style="margin-top:9px">${explanationCards}</div>
      </div>
      <div class="notice ${result.saved ? "success" : ""}">${saveNotice}</div>
      <button class="button button-primary" id="scan-another" type="button">SCAN ANOTHER EMAIL</button>
      <button class="text-button small" id="history-link" type="button">Open Threat History</button>
    </section>`);
  app.querySelector("#profile-button").addEventListener("click", showProfile);
  app.querySelector("#scan-another").addEventListener("click", () => showReady());
  app.querySelector("#history-link").addEventListener("click", (event) => {
    openAuthenticatedWebPage("/app/threat-history", event.currentTarget);
  });
}

function showProfile() {
  if (view !== "profile") profileReturnView = view;
  view = "profile";
  const user = session.user || {};
  const initials = (user.fullName || user.email || "B").trim().charAt(0).toUpperCase();
  shell(`
    ${header(`<button class="icon-button profile-back" id="back-button" aria-label="Back to scan">‹</button>`)}
    <section class="content">
      <div class="drawer-profile">
        <div class="avatar">${escapeHtml(initials)}</div>
        <h1>${escapeHtml(user.fullName || "BANTAI User")}</h1>
        <div class="muted">${escapeHtml(user.email || "")}</div>
      </div>
      <div class="eyebrow">BANTAI ACCOUNT</div>
      <nav class="nav-list" aria-label="BANTAI account pages">
        <button class="nav-link" type="button" data-web-path="/app/dashboard">System Overview Dashboard</button>
        <button class="nav-link" type="button" data-web-path="/app/threat-history">Threat History &amp; Audit Logs</button>
        <button class="nav-link" type="button" data-web-path="/app/settings">System Settings &amp; Preferences</button>
      </nav>
      <button class="button button-danger" id="logout-button" type="button" style="margin-top:12px">SIGN OUT OF EXTENSION</button>
    </section>`);
  app.querySelectorAll("[data-web-path]").forEach((button) => {
    button.addEventListener("click", (event) => {
      openAuthenticatedWebPage(button.dataset.webPath, event.currentTarget);
    });
  });
  app.querySelector("#back-button").addEventListener("click", () => {
    if (profileReturnView === "result" && currentResult) showResult();
    else showReady();
  });
  app.querySelector("#logout-button").addEventListener("click", logout);
}

async function logout() {
  await api("/auth/logout", { method: "POST" });
  await send({ type: "bantai:clear-session" });
  session.accessToken = null;
  session.user = null;
  currentEmail = null;
  currentResult = null;
  authStep = "login";
  resetAuthorization = null;
  showAuth();
}

async function initialize() {
  session = await send({ type: "bantai:get-session" });
  if (session.error) {
    shell(`${header()}<section class="content"><div class="notice error">${escapeHtml(session.error)}</div></section>`);
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
      showAuth("Your BANTAI session expired. Log in again to continue.");
    } else {
      showConnectionError(me.error?.message || "The BANTAI server is unavailable.");
    }
    return;
  }
  session.user = me.data.user;
  await showReady();
}

initialize();
