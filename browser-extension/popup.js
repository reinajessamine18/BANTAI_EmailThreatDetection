const app = typeof document !== "undefined" ? document.querySelector("#app") : null;
const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000/api/v1";
const DEFAULT_WEB_APP_URL = "http://localhost:5173";

let session = null;
let currentEmail = null;
let currentResult = null;
let currentError = "";
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
    try {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          const errMsg = chrome.runtime.lastError.message || "The BANTAI extension could not complete that action.";
          resolve({
            ok: false,
            error: errMsg,
            detail: errMsg,
            category: "extension_messaging_error",
          });
        } else {
          resolve(response || {});
        }
      });
    } catch (e) {
      resolve({
        ok: false,
        error: e?.message || "Failed to communicate with the extension service worker.",
        detail: String(e?.stack || e),
        category: "extension_messaging_error",
      });
    }
  });
}

async function api(path, { method = "GET", body, auth = true } = {}) {
  const res = await send({
    type: "bantai:api-request",
    request: { path, method, body, auth },
  });
  if (res && res.category === "extension_messaging_error") {
    try {
      const baseUrl = session?.apiBaseUrl || DEFAULT_API_BASE_URL;
      const headers = {};
      if (body !== undefined) headers["Content-Type"] = "application/json";
      if (auth && session?.accessToken) {
        headers.Authorization = `Bearer ${session.accessToken}`;
      }
      const response = await fetch(`${baseUrl}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        cache: "no-store",
      });
      if (!response.ok) {
        const data = await response.json().catch(() => null);
        return {
          ok: false,
          error: {
            status: response.status,
            code: data?.detail?.code || "request_failed",
            message: data?.detail?.message || "The BANTAI request failed.",
          },
        };
      }
      if (response.status === 204) return { ok: true, data: null };
      return { ok: true, data: await response.json() };
    } catch {
      return {
        ok: false,
        error: {
          status: 0,
          code: "network_error",
          message: "Cannot reach the BANTAI server. Check the server address and connection.",
        },
      };
    }
  }
  return res;
}

function shell(content) {
  app.innerHTML = `<div class="shell">${content}</div>`;
}

function header(action = "") {
  return `<header class="topbar"><div class="brand">BANTAI<span class="brand-dot" aria-hidden="true"></span></div>${action}</header>`;
}

function webAppPage(path) {
  return new URL(path, session.webAppUrl || DEFAULT_WEB_APP_URL).toString();
}

function isLocalHost(hostname) {
  const normalized = String(hostname || "").toLowerCase();
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "[::1]";
}

function isMatchingWebAppTab(tabUrl, webAppUrl) {
  if (typeof tabUrl !== "string" || !tabUrl.trim()) return false;
  try {
    const tab = new URL(tabUrl);
    const target = new URL(webAppUrl || DEFAULT_WEB_APP_URL);
    if (tab.protocol !== target.protocol) return false;
    const tabHost = tab.hostname.toLowerCase();
    const targetHost = target.hostname.toLowerCase();
    const tabLocal = isLocalHost(tabHost);
    const targetLocal = isLocalHost(targetHost);
    if (targetLocal) {
      if (!tabLocal) return false;
    } else {
      if (tabHost !== targetHost) return false;
    }
    const targetPort = target.port || (target.protocol === "https:" ? "443" : "80");
    const tabPort = tab.port || (tab.protocol === "https:" ? "443" : "80");
    return targetPort === tabPort;
  } catch {
    return false;
  }
}

function webAppHostPatterns() {
  const webApp = new URL(session?.webAppUrl || DEFAULT_WEB_APP_URL);
  if (!['http:', 'https:'].includes(webApp.protocol)) {
    throw new Error("The BANTAI website address must use HTTP or HTTPS.");
  }
  const hostnames = new Set([webApp.hostname]);
  if (webApp.hostname === "localhost") hostnames.add("127.0.0.1");
  if (webApp.hostname === "127.0.0.1") hostnames.add("localhost");
  const patterns = [];
  for (const hostname of hostnames) {
    patterns.push(`${webApp.protocol}//${hostname}/*`);
    if (webApp.port) {
      patterns.push(`${webApp.protocol}//${hostname}:${webApp.port}/*`);
    }
  }
  return [...new Set(patterns)];
}

const lastDiagnostic = {
  timestamp: "",
  extensionId: "",
  websiteOrigin: "",
  websiteTabUrl: "",
  websiteTabFound: false,
  permissionsGranted: {
    tabs: false,
    localhost5173: false,
    localhost8000: false,
  },
  scriptInjectionSucceeded: false,
  storageMechanism: "none",
  sessionValuePresent: false,
  backgroundWorkerReachable: false,
  backendRequestSent: false,
  backendEndpoint: "",
  backendHttpStatus: null,
  backendUserRecognized: false,
  extensionAcceptedSession: false,
  errorCategory: "",
  errorMessage: "",
  errorDetail: "",
};

function sanitizeUrl(urlString) {
  if (!urlString || typeof urlString !== "string") return "";
  try {
    const url = new URL(urlString);
    return `${url.protocol}//${url.host}${url.pathname}`;
  } catch {
    return "invalid_url";
  }
}

async function checkCurrentPermissions() {
  const result = {
    tabs: false,
    localhost5173: false,
    localhost8000: false,
  };
  try {
    if (typeof chrome !== "undefined" && chrome.permissions?.contains) {
      result.tabs = await chrome.permissions.contains({ permissions: ["tabs"] }).catch(() => false);
      result.localhost5173 = await chrome.permissions.contains({ origins: ["http://localhost:5173/*"] }).catch(() => false);
      result.localhost8000 = await chrome.permissions.contains({ origins: ["http://localhost:8000/*"] }).catch(() => false);
    }
  } catch {
    // Ignore permission check errors
  }
  return result;
}

async function signInWithWebsite(options = {}) {
  const opts = (options && typeof options === "object" && !(options instanceof (typeof Event !== "undefined" ? Event : Object)))
    ? options
    : {};
  const requestPermission = opts.requestPermission ?? true;
  const silent = opts.silent ?? false;

  lastDiagnostic.timestamp = new Date().toISOString();
  lastDiagnostic.extensionId = typeof chrome !== "undefined" && chrome.runtime?.id ? chrome.runtime.id : "unknown";
  const webAppUrl = session?.webAppUrl || DEFAULT_WEB_APP_URL;
  lastDiagnostic.websiteOrigin = webAppUrl;
  lastDiagnostic.websiteTabFound = false;
  lastDiagnostic.websiteTabUrl = "";
  lastDiagnostic.scriptInjectionSucceeded = false;
  lastDiagnostic.storageMechanism = "none";
  lastDiagnostic.sessionValuePresent = false;
  lastDiagnostic.backendRequestSent = false;
  lastDiagnostic.backendHttpStatus = null;
  lastDiagnostic.backendUserRecognized = false;
  lastDiagnostic.extensionAcceptedSession = false;
  lastDiagnostic.errorCategory = "";
  lastDiagnostic.errorMessage = "";
  lastDiagnostic.errorDetail = "";

  const button = app?.querySelector("#connect-website");
  if (button) {
    button.disabled = true;
    button.innerHTML = `<span class="spinner"></span> Connecting...`;
  }

  try {
    // 1. Verify current browser permissions
    const perms = await checkCurrentPermissions();
    lastDiagnostic.permissionsGranted = perms;

    const targetUrl = new URL(webAppUrl);
    const isLocal = isLocalHost(targetUrl.hostname);

    if (!isLocal) {
      const origins = [`${targetUrl.protocol}//${targetUrl.hostname}/*`];
      const hasPermission = await chrome.permissions.contains({ origins }).catch(() => false);
      if (!hasPermission) {
        if (requestPermission) {
          const granted = await chrome.permissions.request({ origins }).catch(() => false);
          if (!granted) {
            lastDiagnostic.errorCategory = "permission_denied";
            lastDiagnostic.errorMessage = "Allow access to your BANTAI website to use its signed-in account.";
            if (!silent) showAuth(lastDiagnostic.errorMessage, "", "permission_denied");
            return false;
          }
        } else {
          lastDiagnostic.errorCategory = "permission_denied";
          lastDiagnostic.errorMessage = "Permission required to access remote BANTAI website.";
          return false;
        }
      }
    }

    // 2. Discover website tabs
    let tabs = [];
    try {
      if (typeof chrome !== "undefined" && chrome.tabs?.query) {
        const allTabs = await chrome.tabs.query({});
        if (Array.isArray(allTabs)) {
          tabs = allTabs.filter((tab) => isMatchingWebAppTab(tab?.url, webAppUrl));
        }
      }
    } catch (tabErr) {
      lastDiagnostic.errorDetail = `chrome.tabs.query failed: ${tabErr.message}`;
    }

    if (!tabs.length && typeof chrome !== "undefined" && chrome.tabs?.query) {
      const patterns = webAppHostPatterns();
      for (const pattern of patterns) {
        try {
          const matched = await chrome.tabs.query({ url: pattern });
          if (Array.isArray(matched)) {
            for (const t of matched) {
              if (t?.id && !tabs.some((existing) => existing.id === t.id)) {
                tabs.push(t);
              }
            }
          }
        } catch {
          // Ignore pattern query errors
        }
      }
    }

    lastDiagnostic.websiteTabFound = tabs.length > 0;
    if (tabs.length > 0) {
      lastDiagnostic.websiteTabUrl = sanitizeUrl(tabs[0].url);
    }

    if (tabs.length === 0) {
      // Check if the extension was not reloaded after manifest permission changes
      if (!perms.tabs && !perms.localhost5173) {
        lastDiagnostic.errorCategory = "extension_reload_required";
        lastDiagnostic.errorMessage = "The extension permissions were updated. Click 'RELOAD EXTENSION NOW' below to reload in Chrome.";
      } else {
        lastDiagnostic.errorCategory = "website_not_found";
        lastDiagnostic.errorMessage = `No open BANTAI website tab was found (${webAppUrl}). Sign in on the website, then try again.`;
      }
      if (!silent) showAuth(lastDiagnostic.errorMessage, "", lastDiagnostic.errorCategory);
      return false;
    }

    // 3. Inject script to extract token
    tabs.sort((left, right) => Number(Boolean(right.active)) - Number(Boolean(left.active)));

    let websiteToken = "";
    let extractionError = "";
    for (const tab of tabs) {
      if (!tab.id) continue;
      // Try both MAIN world (page context) and ISOLATED world (content script context)
      for (const world of ["MAIN", "ISOLATED"]) {
        try {
          const [result] = await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            world,
            func: () => {
              try {
                const local = window.localStorage?.getItem("bantaiToken");
                if (local && typeof local === "string" && local.trim()) {
                  return { token: local.trim(), source: "localStorage" };
                }
                const session = window.sessionStorage?.getItem("bantaiToken");
                if (session && typeof session === "string" && session.trim()) {
                  return { token: session.trim(), source: "sessionStorage" };
                }
                return { token: null, source: "none", keys: Object.keys(window.localStorage || {}) };
              } catch (e) {
                return { token: null, error: e.message, source: "error" };
              }
            },
          });

          lastDiagnostic.scriptInjectionSucceeded = true;
          if (result?.result?.token) {
            websiteToken = result.result.token;
            lastDiagnostic.storageMechanism = result.result.source;
            lastDiagnostic.sessionValuePresent = true;
            break;
          } else if (result?.result?.error) {
            extractionError = result.result.error;
          }
        } catch (scriptErr) {
          extractionError = scriptErr.message;
          if (scriptErr.message?.includes("Missing host permission") || scriptErr.message?.includes("Cannot access contents")) {
            lastDiagnostic.errorCategory = "extension_reload_required";
            lastDiagnostic.errorMessage = "Extension host permissions need reload. Click 'RELOAD EXTENSION NOW' below.";
          }
        }
      }
      if (websiteToken) break;
    }

    if (!websiteToken) {
      if (lastDiagnostic.errorCategory !== "extension_reload_required") {
        if (extractionError && (extractionError.includes("permission") || extractionError.includes("denied"))) {
          lastDiagnostic.errorCategory = "permission_denied";
          lastDiagnostic.errorMessage = `Could not access website storage: ${extractionError}`;
        } else {
          lastDiagnostic.errorCategory = "not_signed_in";
          lastDiagnostic.errorMessage = "The BANTAI website tab is open, but no signed-in account session was found. Sign in on the website, then try again.";
        }
      }
      if (!silent) showAuth(lastDiagnostic.errorMessage, "", lastDiagnostic.errorCategory);
      return false;
    }

    // 4. Background handoff & validation
    lastDiagnostic.backgroundWorkerReachable = true;
    lastDiagnostic.backendRequestSent = true;
    lastDiagnostic.backendEndpoint = "/auth/web-handoff";

    let result = await send({ type: "bantai:website-handoff", accessToken: websiteToken });

    // Fallback: If background messaging encounters an error (e.g. extension not yet reloaded after manifest changes),
    // perform the exchange directly from the popup context against the backend API
    if (!result.ok && (result.category === "extension_messaging_error" || !lastDiagnostic.backendHttpStatus)) {
      try {
        const baseUrl = DEFAULT_API_BASE_URL;
        // 1. Verify user profile with website token
        const meResp = await fetch(`${baseUrl}/auth/me`, {
          headers: { Authorization: `Bearer ${websiteToken}` },
          cache: "no-store",
        });
        if (meResp.ok) {
          const meData = await meResp.json();
          // 2. Request handoff ticket
          const handoffResp = await fetch(`${baseUrl}/auth/web-handoff`, {
            method: "POST",
            headers: { Authorization: `Bearer ${websiteToken}` },
            cache: "no-store",
          });
          if (handoffResp.ok) {
            const handoffData = await handoffResp.json();
            // 3. Exchange ticket for extension session
            const exchResp = await fetch(`${baseUrl}/auth/web-handoff/exchange`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ ticket: handoffData.ticket }),
              cache: "no-store",
            });
            if (exchResp.ok) {
              const exchData = await exchResp.json();
              await chrome.storage.local.set({
                accessToken: exchData.accessToken,
                user: exchData.user,
              });
              result = { ok: true, user: exchData.user };
            } else {
              const errData = await exchResp.json().catch(() => ({}));
              result = { ok: false, status: exchResp.status, error: errData.detail?.message || "Handoff ticket exchange failed." };
            }
          } else {
            const errData = await handoffResp.json().catch(() => ({}));
            result = { ok: false, status: handoffResp.status, error: errData.detail?.message || "Failed to create handoff ticket." };
          }
        } else {
          result = { ok: false, status: meResp.status, category: meResp.status === 401 ? "session_expired" : "invalid_session_response", error: "The website session is not recognized or expired." };
        }
      } catch (directErr) {
        lastDiagnostic.errorDetail = `Direct handoff fallback error: ${directErr.message}`;
      }
    }
    websiteToken = "";

    if (!result.ok) {
      lastDiagnostic.backendHttpStatus = result.status || (result.category === "session_expired" ? 401 : null);
      lastDiagnostic.errorCategory = result.category || "invalid_session_response";
      lastDiagnostic.errorMessage = result.error?.message || result.error || "Could not use the website session.";
      lastDiagnostic.errorDetail = result.detail || lastDiagnostic.errorDetail || "";
      if (!silent) showAuth(lastDiagnostic.errorMessage, "", lastDiagnostic.errorCategory);
      return false;
    }

    lastDiagnostic.backendUserRecognized = true;
    lastDiagnostic.backendHttpStatus = 200;
    lastDiagnostic.extensionAcceptedSession = true;

    session = await send({ type: "bantai:get-session" });
    if (session.error || !session.accessToken) {
      const stored = await chrome.storage.local.get(["accessToken", "user", "apiBaseUrl", "webAppUrl"]).catch(() => ({}));
      if (stored.accessToken) {
        session = {
          accessToken: stored.accessToken,
          user: stored.user || null,
          apiBaseUrl: stored.apiBaseUrl || DEFAULT_API_BASE_URL,
          webAppUrl: stored.webAppUrl || DEFAULT_WEB_APP_URL,
        };
      } else {
        lastDiagnostic.errorCategory = "invalid_session_response";
        lastDiagnostic.errorMessage = "The extension could not save the new sign-in session.";
        lastDiagnostic.errorDetail = session.error || lastDiagnostic.errorDetail;
        if (!silent) showAuth(lastDiagnostic.errorMessage, "", lastDiagnostic.errorCategory);
        return false;
      }
    }

    await showReady();
    return true;
  } catch (error) {
    lastDiagnostic.errorCategory = "extension_error";
    lastDiagnostic.errorMessage = error.message || "Could not connect to the BANTAI website session.";
    if (!silent) showAuth(lastDiagnostic.errorMessage, "", "extension_error");
    return false;
  } finally {
    if (button?.isConnected) {
      button.disabled = false;
      button.textContent = "CHECK WEBSITE SESSION";
    }
  }
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

function showAuth(error = "", notice = "", category = "") {
  view = "website-required";
  const reloadNeeded = category === "extension_reload_required" || lastDiagnostic.errorCategory === "extension_reload_required";
  const displayMsg = error || notice;

  shell(`
    ${header()}
    <section class="content">
      <article class="card center" style="padding:20px 16px">
        <div class="avatar">${reloadNeeded ? "⚠" : "⌕"}</div>
        <h1 class="section-title">${reloadNeeded ? "EXTENSION RELOAD REQUIRED" : "USE YOUR BANTAI WEBSITE ACCOUNT"}</h1>
        <p class="muted">
          ${reloadNeeded
            ? "New permissions were added to the extension manifest. Chrome requires reloading unpacked extensions after permission changes."
            : "Sign in on the BANTAI website. The extension uses that account and does not have a separate login or signup."}
        </p>
        ${displayMsg ? `<div class="notice ${error || reloadNeeded ? "error" : ""}" role="${error ? "alert" : "status"}">${escapeHtml(displayMsg)}</div>` : ""}
        <div class="stack" style="margin-top:16px">
          ${reloadNeeded ? `<button class="button button-primary" id="reload-extension" type="button">RELOAD EXTENSION NOW</button>` : ""}
          <button class="button ${reloadNeeded ? "button-quiet" : "button-primary"}" id="open-website-login" type="button">OPEN BANTAI WEBSITE</button>
          <button class="button button-quiet" id="connect-website" type="button">CHECK WEBSITE SESSION</button>
        </div>
        <details class="diagnostic-details" style="margin-top:14px;font-size:11px;text-align:left;border-top:1px solid #27272a;padding-top:10px;">
          <summary style="cursor:pointer;color:#a1a1aa;user-select:none;">Diagnostic Details</summary>
          <pre style="background:#18181b;padding:8px;border-radius:6px;overflow:auto;margin-top:6px;font-size:10px;color:#a1a1aa;white-space:pre-wrap;word-break:break-all;">${escapeHtml(JSON.stringify(lastDiagnostic, null, 2))}</pre>
        </details>
      </article>
    </section>`);

  app.querySelector("#open-website-login")?.addEventListener("click", () => {
    chrome.tabs.create({ url: webAppPage("/login") });
  });
  app.querySelector("#connect-website")?.addEventListener("click", () => {
    signInWithWebsite({ requestPermission: true, silent: false });
  });
  app.querySelector("#reload-extension")?.addEventListener("click", () => {
    if (typeof chrome !== "undefined" && chrome.runtime?.reload) {
      chrome.runtime.reload();
      if (typeof window !== "undefined") window.close();
    }
  });
  return;

  view = "auth";
  const login = authStep === "login";
  const reset = authStep.startsWith("reset-");
  const title = {
    login: "Sign in",
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
     ? `<button class="button button-google" type="button" id="website-login">Continue with website account</button>
       <div class="auth-divider"><span>OR</span></div>
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
          BANTAI<span class="brand-dot" aria-hidden="true"></span>
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
  app.querySelector("#website-login")?.addEventListener("click", signInWithWebsite);
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
    google_account_unavailable: "This Google account has been deactivated or is unavailable.",
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

function normalizeExtractionResult(extracted) {
  if (!extracted || typeof extracted !== "object") {
    return {
      ok: false,
      code: "no_response",
      message: "No response was received from the Gmail page. Reload Gmail, open a message, and try again.",
    };
  }

  if (!extracted.ok) {
    return {
      ok: false,
      code: extracted.code || "extraction_failed",
      message: extracted.message || "BANTAI could not read this Gmail message. Try clicking inside the message.",
    };
  }

  // Canonicalize body text: accept canonical bodyText, support legacy body
  const candidate = typeof extracted.bodyText === "string"
    ? extracted.bodyText
    : (typeof extracted.body === "string" ? extracted.body : "");
  const bodyText = candidate.trim();

  if (!bodyText) {
    return {
      ok: false,
      code: "degenerate_content",
      message: "The open message contains no readable text to analyze.",
    };
  }

  const subject = (extracted.contextSubject || extracted.subject || "").trim();
  const sender = (extracted.contextSender || extracted.sender || "").trim();

  return {
    ok: true,
    bodyText,
    contextSubject: subject,
    contextSender: sender,
    // Compatibility aliases
    body: bodyText,
    subject,
    sender,
  };
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
      code: "invalid_tab",
      message: "Open an individual email in Gmail to begin. Gmail in Chrome is currently supported.",
    };
  }

  // Attempt direct messaging first (content script already running)
  try {
    const directResponse = await chrome.tabs.sendMessage(tab.id, { type: "bantai:extract-active-email" });
    if (directResponse && typeof directResponse === "object") {
      return directResponse;
    }
  } catch {
    // If not yet injected or port closed, fall back to dynamic injection
  }

  try {
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      files: ["content.js"],
    });
    const injectedResponse = await chrome.tabs.sendMessage(tab.id, { type: "bantai:extract-active-email" });
    if (injectedResponse && typeof injectedResponse === "object") {
      return injectedResponse;
    }
    return {
      ok: false,
      code: "no_response",
      message: "BANTAI could not read this Gmail tab. Reload Gmail, open a message, and try again.",
    };
  } catch {
    return {
      ok: false,
      code: "injection_failed",
      message: "BANTAI could not read this Gmail tab. Reload Gmail, open a message, and try again.",
    };
  }
}

async function showReady(error = "") {
  view = "ready";
  currentError = error;
  const me = session.accessToken ? await api("/auth/me") : { ok: false };
  if (!me.ok) {
    if (me.error?.status === 401) {
      await send({ type: "bantai:clear-session" });
      session.accessToken = null;
      session.user = null;
      showAuth("", "Your website session expired. Sign in on the BANTAI website, then reconnect.");
    } else {
      showConnectionError(me.error?.message || "The BANTAI server is unavailable.");
    }
    return;
  }
  session.user = me.data.user;

  const rawExtracted = await extractActiveEmail();
  const extracted = normalizeExtractionResult(rawExtracted);
  currentEmail = extracted.ok ? extracted : null;
  const user = session.user || {};
  const emailCard = currentEmail
    ? `<article class="card message-card">
        <h1 class="message-title">${escapeHtml(currentEmail.contextSubject || currentEmail.subject || "Gmail message")}</h1>
        ${(currentEmail.contextSender || currentEmail.sender) ? `<div class="message-sender">From: ${escapeHtml(currentEmail.contextSender || currentEmail.sender)}</div>` : ""}
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
        <span style="color:#fff;font-size:14px;font-weight:700;line-height:1.4">Welcome back, ${escapeHtml(user.fullName || user.email || "BANTAI user")}</span>
      </div>
      ${currentError ? `<div class="notice error" role="alert">${escapeHtml(currentError)}</div>` : ""}
      ${emailCard}
      <div class="stack" style="margin-top:14px">
        <button class="button button-primary" id="scan-button" type="button" ${currentEmail ? "" : "disabled"}>
          SCAN EMAIL FOR THREATS
        </button>
      </div>
    </section>`);

  app?.querySelector("#profile-button")?.addEventListener("click", showProfile);
  app?.querySelector("#retry-extract")?.addEventListener("click", () => showReady());
  app?.querySelector("#scan-button")?.addEventListener("click", scanActiveEmail);
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
  app?.querySelector("#retry-connection")?.addEventListener("click", initialize);
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
  if (view === "scanning") return;

  const normalized = normalizeExtractionResult(currentEmail);
  if (!normalized.ok) {
    await showReady(
      normalized.message
        || "The message contains no readable text to analyze. Open a valid message in Gmail and try again."
    );
    return;
  }

  showScanning();

  const scanButton = app?.querySelector("#scan-button");
  if (scanButton) scanButton.disabled = true;

  try {
    const subject = normalized.contextSubject || normalized.subject || "Gmail message";
    const response = await api("/scans/content-only", {
      method: "POST",
      body: {
        bodyText: normalized.bodyText,
        fileName: `${subject.slice(0, 50)}.txt`,
        explain: true,
        top_k: 10,
      },
      auth: true,
    });

    if (!response.ok) {
      const status = response.error?.status;
      const code = response.error?.code;
      if (status === 401) {
        session.accessToken = null;
        session.user = null;
        showAuth(
          response.error?.message
            || "Your website session expired. Sign in on the BANTAI website to continue."
        );
        return;
      }
      let message = response.error?.message || "The scan failed. Please try again.";
      if (status === 413 || code === "body_too_long") {
        message = "The email's text is longer than the 200,000-character analysis limit.";
      } else if (status === 422 || code === "degenerate_content" || code === "whitespace_only") {
        message = "The email contains no readable text to analyze.";
      } else if (status === 503 || code === "ml_unavailable") {
        message = "The content-only analysis service is unavailable right now. Please try again shortly.";
      }
      await showReady(message);
      return;
    }

    const data = response.data;
    if (
      !data ||
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
  } catch (err) {
    await showReady("An unexpected error occurred while analyzing the email. Please try again.");
  }
}

function showResult() {
  view = "result";
  const result = currentResult;
  const risk = result.riskLevel || (result.threatScore >= 80 ? "phishing" : result.threatScore >= 40 ? "suspicious" : "safe");
  const labels = { phishing: "Phishing detected", suspicious: "Suspicious email", safe: "No threat detected" };
  const classification = result.modelClassification || (result.phishingProbability >= 0.5 ? "Phishing" : "Legitimate");
  const score = Math.round(result.threatScore);
  const probability = Number.isFinite(Number(result.phishingProbability))
    ? `${(Number(result.phishingProbability) * 100).toFixed(1)}%`
    : "Not provided";
  const rawMargin = result.shap?.rawMargin != null && Number.isFinite(Number(result.shap.rawMargin))
    ? `${Number(result.shap.rawMargin) > 0 ? "+" : ""}${Number(result.shap.rawMargin).toFixed(3)} log-odds`
    : null;
  const explanations = Array.isArray(result.explanations) ? result.explanations : [];
  const explanationCards = explanations.length
    ? explanations.slice(0, 8).map((item) => {
        const isPushingPhish = item.direction === "toward_phishing" || (Number(item.value) > 0);
        const directionLabel = isPushingPhish ? "Toward Phishing" : "Toward Safe";
        const valStr = Number.isFinite(Number(item.value))
          ? ` · SHAP ${Number(item.value) > 0 ? "+" : ""}${Number(item.value).toFixed(3)} log-odds`
          : "";
        return `
        <article class="explanation">
          <div class="explanation-title">${escapeHtml(item.feature || item.title || "Token attribution")}</div>
          <div class="explanation-text">${escapeHtml(directionLabel)}${escapeHtml(valStr)}</div>
        </article>`;
      }).join("")
    : `<div class="notice">The analysis returned no explanation items.</div>`;
  const saveNotice = result.saved
    ? `Recorded in Threat History (${escapeHtml(result.scanCode || "scan")}).`
    : "The scan was processed, but your account settings did not save it to Threat History.";

  shell(`
    ${header(`<button class="icon-button profile-button" id="profile-button" type="button" aria-label="Open profile" title="Open profile"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8" r="3.5"></circle><path d="M5 20c.7-3.4 3.1-5.5 7-5.5s6.3 2.1 7 5.5"></path></svg></button>`)}
    <section class="content stack">
      <div class="result-banner ${risk}">${escapeHtml(classification.toUpperCase())} · ${escapeHtml(labels[risk] || "")}</div>
      <div class="card score-card">
        <div><div class="score ${risk}">${escapeHtml(score)}</div><div class="score-caption">THREAT SCORE / 100</div></div>
        <div class="score-detail">
          <strong>Risk Tier: ${escapeHtml(result.riskTier || "Low")}</strong>
          <span class="muted small">Model: <strong>${escapeHtml(classification)}</strong> (p = ${escapeHtml(probability)})</span>
          ${rawMargin ? `<span class="muted small">Raw Margin: ${escapeHtml(rawMargin)}</span>` : ""}
          <span class="muted small">${escapeHtml(currentEmail?.contextSubject || currentEmail?.subject || "Scanned Gmail message")}</span>
        </div>
      </div>
      <div>
        <h2 class="section-title">ANALYSIS EXPLANATION</h2>
        <div class="stack" style="margin-top:9px">${explanationCards}</div>
      </div>
      <div class="notice ${result.saved ? "success" : ""}">${saveNotice}</div>
      <button class="button button-primary" id="scan-another" type="button">SCAN ANOTHER EMAIL</button>
      <button class="text-button small" id="history-link" type="button">Open in Threat History</button>
    </section>`);
  app.querySelector("#profile-button").addEventListener("click", showProfile);
  app.querySelector("#scan-another").addEventListener("click", () => showReady());
  app.querySelector("#history-link").addEventListener("click", (event) => {
    const targetPath = result.saved && result.scanId
      ? `/app/threat-history/${result.scanId}`
      : "/app/threat-history";
    openAuthenticatedWebPage(targetPath, event.currentTarget);
  });
}

function showProfile() {
  if (view !== "profile") profileReturnView = view;
  view = "profile";
  const user = session.user || {};
  shell(`
    ${header(`<button class="icon-button profile-back" id="back-button" aria-label="Back to scan"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m14 18-6-6 6-6"></path></svg></button>`)}
    <section class="content">
      <div class="drawer-profile">
        <img class="avatar-logo" src="BANTAI-logo.png" alt="BANTAI logo">
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
  showAuth("", "Extension session cleared. Reconnect your signed-in website account to scan.");
}

async function initialize() {
  session = await send({ type: "bantai:get-session" });
  if (session?.error) {
    try {
      if (typeof chrome !== "undefined" && chrome.storage?.local) {
        const stored = await chrome.storage.local.get(["accessToken", "user", "apiBaseUrl", "webAppUrl"]);
        session = {
          accessToken: stored.accessToken || null,
          user: stored.user || null,
          apiBaseUrl: stored.apiBaseUrl || DEFAULT_API_BASE_URL,
          webAppUrl: stored.webAppUrl || DEFAULT_WEB_APP_URL,
        };
      }
    } catch {
      // Ignore storage error
    }
    if (!session || session.error) {
      shell(`${header()}<section class="content"><div class="notice error">${escapeHtml(session?.error || "Extension storage unavailable.")}</div></section>`);
      return;
    }
  }
  session ||= {};
  session.apiBaseUrl ||= DEFAULT_API_BASE_URL;
  session.webAppUrl ||= DEFAULT_WEB_APP_URL;

  // 1. If the extension already has a saved access token, validate it via showReady()
  if (session.accessToken) {
    await showReady();
    return;
  }

  // 2. Attempt automatic silent handoff from an open website tab
  const connected = await signInWithWebsite({ requestPermission: false, silent: true });
  if (connected) return;

  // 3. Present the specific failure state and diagnostics
  const msg = lastDiagnostic.errorMessage || "No signed-in BANTAI website account was found. Sign in on the website first, then reopen the extension.";
  showAuth("", msg, lastDiagnostic.errorCategory);
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    normalizeExtractionResult,
    escapeHtml,
    googleOAuthErrorMessage,
    isLocalHost,
    isMatchingWebAppTab,
    webAppHostPatterns,
    sanitizeUrl,
    checkCurrentPermissions,
    lastDiagnostic,
  };
}

if (typeof window !== "undefined" && typeof document !== "undefined") {
  initialize();
}
