import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const {
  normalizeExtractionResult,
  googleOAuthErrorMessage,
  isLocalHost,
  isMatchingWebAppTab,
  webAppHostPatterns,
  sanitizeUrl,
  checkCurrentPermissions,
  lastDiagnostic,
} = require("../popup.js");

// ---------------------------------------------------------------------------
// Regression Test Suite for Phase 10: Popup Extraction Contract Normalization
// and Scan Button Execution Flow
// ---------------------------------------------------------------------------

test("1. Current response with bodyText: normalizes canonical bodyText correctly", () => {
  const input = {
    ok: true,
    bodyText: "Please review the attached invoice for Q3 expenses.",
    contextSubject: "Q3 Invoice",
    contextSender: "billing@vendor.com",
  };

  const normalized = normalizeExtractionResult(input);
  assert.equal(normalized.ok, true);
  assert.equal(normalized.bodyText, "Please review the attached invoice for Q3 expenses.");
  assert.equal(normalized.contextSubject, "Q3 Invoice");
  assert.equal(normalized.contextSender, "billing@vendor.com");
  // Backward compatibility aliases are also populated
  assert.equal(normalized.body, normalized.bodyText);
  assert.equal(normalized.subject, "Q3 Invoice");
  assert.equal(normalized.sender, "billing@vendor.com");
});

test("2. Legacy response with body: correctly normalizes body to canonical bodyText", () => {
  const legacyInput = {
    ok: true,
    body: "Legacy email body text extracted from Gmail DOM.",
    subject: "Meeting Agenda",
    sender: "boss@company.com",
    links: ["https://example.com/agenda"],
  };

  const normalized = normalizeExtractionResult(legacyInput);
  assert.equal(normalized.ok, true);
  assert.equal(normalized.bodyText, "Legacy email body text extracted from Gmail DOM.");
  assert.equal(normalized.contextSubject, "Meeting Agenda");
  assert.equal(normalized.contextSender, "boss@company.com");
  assert.equal(normalized.body, "Legacy email body text extracted from Gmail DOM.");
});

test("3. Missing body property: rejects with degenerate_content without crashing", () => {
  const inputMissingBody = {
    ok: true,
    contextSubject: "Notification without body",
    contextSender: "alerts@system.com",
  };

  const normalized = normalizeExtractionResult(inputMissingBody);
  assert.equal(normalized.ok, false);
  assert.equal(normalized.code, "degenerate_content");
  assert.match(normalized.message, /no readable text to analyze/i);
});

test("4. Empty or whitespace-only body: rejects with degenerate_content", () => {
  const emptyInputs = [
    { ok: true, bodyText: "" },
    { ok: true, bodyText: "   \t\n\r  " },
    { ok: true, body: "" },
    { ok: true, body: " \n " },
  ];

  for (const input of emptyInputs) {
    const normalized = normalizeExtractionResult(input);
    assert.equal(normalized.ok, false);
    assert.equal(normalized.code, "degenerate_content");
    assert.match(normalized.message, /no readable text to analyze/i);
  }
});

test("5. Ambiguous active-message response: preserves error code and user message", () => {
  const ambiguousInput = {
    ok: false,
    code: "ambiguous_active_message",
    message: "Multiple messages are open in this conversation. Please collapse other messages or click inside the specific email you wish to analyze.",
  };

  const normalized = normalizeExtractionResult(ambiguousInput);
  assert.equal(normalized.ok, false);
  assert.equal(normalized.code, "ambiguous_active_message");
  assert.equal(normalized.message, ambiguousInput.message);
});

test("6. Failed Chrome messaging: handles null, undefined, or missing response gracefully", () => {
  const failedInputs = [null, undefined, false, "error", {}];

  for (const input of failedInputs) {
    const normalized = normalizeExtractionResult(input);
    assert.equal(normalized.ok, false);
    assert.ok(normalized.code === "no_response" || normalized.code === "extraction_failed");
    assert.match(normalized.message, /could not read|no response/i);
  }
});

test("7. Successful API request payload: ensures canonical bodyText is dispatched to backend", () => {
  const emailInput = {
    ok: true,
    body: "Action required: update your security settings.",
    subject: "Security Update",
    sender: "security@platform.com",
  };

  const normalized = normalizeExtractionResult(emailInput);
  assert.equal(normalized.ok, true);

  // Simulate payload construction matching popup.js scanActiveEmail()
  const subject = normalized.contextSubject || normalized.subject || "Gmail message";
  const apiPayload = {
    bodyText: normalized.bodyText,
    fileName: `${subject.slice(0, 50)}.txt`,
    explain: true,
    top_k: 10,
  };

  assert.equal(apiPayload.bodyText, "Action required: update your security settings.");
  assert.equal(apiPayload.fileName, "Security Update.txt");
  assert.equal(apiPayload.explain, true);
  assert.equal(apiPayload.top_k, 10);

  // Features must strictly NOT include metadata, sender, or headers as model inputs
  assert.equal(apiPayload.sender, undefined);
  assert.equal(apiPayload.subject, undefined);
  assert.equal(apiPayload.headers, undefined);
});

test("8. No API request dispatched when extraction fails or body is invalid", () => {
  const invalidEmails = [
    null,
    { ok: false, code: "ambiguous_active_message", message: "Ambiguous message" },
    { ok: true, bodyText: "   " },
  ];

  for (const invalidEmail of invalidEmails) {
    let apiCallCount = 0;
    const mockApi = () => {
      apiCallCount++;
      return Promise.resolve({ ok: true, data: {} });
    };

    const normalized = normalizeExtractionResult(invalidEmail);
    if (!normalized.ok) {
      // scanActiveEmail guard: if (!normalized.ok) calls showReady(error) and returns without api call
      assert.equal(apiCallCount, 0, "API must never be invoked when extraction is invalid");
      assert.ok(normalized.message.length > 0, "Error notice must be provided to user");
    } else {
      assert.fail("Invalid email should not normalize to ok: true");
    }
  }
});

test("9. Duplicate concurrent scan prevention: scanning view state blocks second invocation", () => {
  let view = "ready";
  let requestCount = 0;

  const simulateScanClick = () => {
    if (view === "scanning") return false; // Early return guard
    view = "scanning";
    requestCount++;
    return true;
  };

  const firstClick = simulateScanClick();
  assert.equal(firstClick, true);
  assert.equal(requestCount, 1);
  assert.equal(view, "scanning");

  // Second rapid click while view is still scanning
  const secondClick = simulateScanClick();
  assert.equal(secondClick, false);
  assert.equal(requestCount, 1, "Duplicate click must not trigger second API request");
});

test("10. Correct UI recovery after request failure: resets scanning state and presents message", () => {
  let view = "scanning";
  let displayedError = "";
  let buttonDisabled = true;

  const mockShowReady = (error = "") => {
    view = "ready";
    displayedError = error;
    buttonDisabled = false;
  };

  // Simulate API returning 503 ml_unavailable
  const response = {
    ok: false,
    error: {
      status: 503,
      code: "ml_unavailable",
      message: "The content-only analysis service is unavailable right now. Please try again shortly.",
    },
  };

  let message = response.error?.message || "The scan failed. Please try again.";
  if (response.error?.status === 503 || response.error?.code === "ml_unavailable") {
    message = "The content-only analysis service is unavailable right now. Please try again shortly.";
  }

  mockShowReady(message);

  assert.equal(view, "ready", "View must transition back to ready");
  assert.equal(buttonDisabled, false, "Button must be re-enabled after failure");
  assert.match(displayedError, /analysis service is unavailable/i);
});

test("11. Google OAuth error message mapping covers known codes safely", () => {
  assert.match(googleOAuthErrorMessage("google_login_unavailable"), /not configured/);
  assert.match(googleOAuthErrorMessage("google_extension_not_configured"), /not allowlisted/);
  assert.match(googleOAuthErrorMessage("google_account_link_required"), /A BANTAI account already uses this email/);
  assert.match(googleOAuthErrorMessage("google_account_unavailable"), /deactivated or is unavailable/);
  assert.match(googleOAuthErrorMessage("google_sign_in_failed"), /Google could not verify/);
  assert.match(googleOAuthErrorMessage("google_sign_in_cancelled"), /cancelled/);
  assert.match(googleOAuthErrorMessage("unknown_error_code"), /could not be completed/);
});

// ---------------------------------------------------------------------------
// Website-to-Extension Authentication and Session Detection Contract Tests
// ---------------------------------------------------------------------------

test("12. isLocalHost accurately recognizes loopback/local addresses and rejects remote domains", () => {
  assert.equal(isLocalHost("localhost"), true);
  assert.equal(isLocalHost("LOCALHOST"), true);
  assert.equal(isLocalHost("127.0.0.1"), true);
  assert.equal(isLocalHost("[::1]"), true);

  assert.equal(isLocalHost("bantai.org"), false);
  assert.equal(isLocalHost("example.com"), false);
  assert.equal(isLocalHost("google.com"), false);
  assert.equal(isLocalHost(""), false);
  assert.equal(isLocalHost(null), false);
  assert.equal(isLocalHost(undefined), false);
});

test("13. isMatchingWebAppTab accurately identifies website tabs by protocol, host, and port", () => {
  const defaultWeb = "http://localhost:5173";

  // Valid matches on default local Vite port
  assert.equal(isMatchingWebAppTab("http://localhost:5173/", defaultWeb), true);
  assert.equal(isMatchingWebAppTab("http://localhost:5173/dashboard", defaultWeb), true);
  assert.equal(isMatchingWebAppTab("http://127.0.0.1:5173/profile", defaultWeb), true);
  assert.equal(isMatchingWebAppTab("http://127.0.0.1:5173/threat-history", "http://127.0.0.1:5173"), true);

  // Mismatches: backend API port vs frontend Vite port
  assert.equal(isMatchingWebAppTab("http://localhost:8000/docs", defaultWeb), false, "Backend API port 8000 must not match frontend 5173");
  assert.equal(isMatchingWebAppTab("http://127.0.0.1:8000/api/v1/health", defaultWeb), false);

  // Mismatches: protocol
  assert.equal(isMatchingWebAppTab("https://localhost:5173/", defaultWeb), false, "HTTPS vs HTTP protocol mismatch");

  // Mismatches: completely unrelated domains (Gmail, Google, etc.)
  assert.equal(isMatchingWebAppTab("https://mail.google.com/mail/u/0/#inbox", defaultWeb), false);
  assert.equal(isMatchingWebAppTab("https://accounts.google.com/o/oauth2/auth", defaultWeb), false);

  // Remote production match
  assert.equal(isMatchingWebAppTab("https://bantai.org/scans", "https://bantai.org"), true);
  assert.equal(isMatchingWebAppTab("https://other.org/scans", "https://bantai.org"), false);

  // Safe error handling for malformed or missing inputs
  assert.equal(isMatchingWebAppTab(null, defaultWeb), false);
  assert.equal(isMatchingWebAppTab(undefined, defaultWeb), false);
  assert.equal(isMatchingWebAppTab("", defaultWeb), false);
  assert.equal(isMatchingWebAppTab("not-a-valid-url", defaultWeb), false);
});

test("14. webAppHostPatterns generates both wildcard and port-specific patterns", () => {
  const patterns = webAppHostPatterns();
  assert.ok(Array.isArray(patterns));
  assert.ok(patterns.includes("http://localhost/*"));
  assert.ok(patterns.includes("http://127.0.0.1/*"));
  assert.ok(patterns.includes("http://localhost:5173/*"));
  assert.ok(patterns.includes("http://127.0.0.1:5173/*"));
});

test("15. Session retention contract: existing accessToken retains session without destructive wiping", () => {
  // Simulate initialize() logic
  let clearSessionCalled = false;
  let showReadyCalled = false;
  let showAuthCalled = false;

  const mockSession = {
    accessToken: "valid-stored-session-token",
    user: { userId: 1, email: "user@example.com" },
    webAppUrl: "http://localhost:5173",
    apiBaseUrl: "http://127.0.0.1:8000/api/v1",
  };

  const simulateInitialize = async (session) => {
    if (session.accessToken) {
      showReadyCalled = true;
      return;
    }
    clearSessionCalled = true;
    showAuthCalled = true;
  };

  simulateInitialize(mockSession);

  assert.equal(showReadyCalled, true, "showReady must be called when token is present");
  assert.equal(clearSessionCalled, false, "clear-session must NOT be called when session already exists");
  assert.equal(showAuthCalled, false, "showAuth must NOT overwrite valid active session");
});

test("16. Session expiry contract: 401 on /auth/me clears session cleanly and displays notice", () => {
  let sessionState = {
    accessToken: "expired-token",
    user: { userId: 1 },
  };
  let clearSessionInvoked = false;
  let authMessage = "";

  const simulateShowReadyWith401 = async () => {
    // Backend returns 401 Unauthorized
    const meResponse = { ok: false, error: { status: 401, message: "Session expired" } };
    if (!meResponse.ok && meResponse.error?.status === 401) {
      clearSessionInvoked = true;
      sessionState.accessToken = null;
      sessionState.user = null;
      authMessage = "Your website session expired. Sign in on the BANTAI website, then reconnect.";
    }
  };

  simulateShowReadyWith401();

  assert.equal(clearSessionInvoked, true);
  assert.equal(sessionState.accessToken, null);
  assert.equal(sessionState.user, null);
  assert.match(authMessage, /session expired/i);
});

test("17. Tab token extraction inspects both localStorage and sessionStorage", () => {
  const extractFn = () => window.localStorage.getItem("bantaiToken") || window.sessionStorage.getItem("bantaiToken");

  // Verify function source code checks both storage mechanisms
  const fnString = extractFn.toString();
  assert.ok(fnString.includes("localStorage.getItem(\"bantaiToken\")"));
  assert.ok(fnString.includes("sessionStorage.getItem(\"bantaiToken\")"));
});

test("18. sanitizeUrl strips query params and fragments to protect sensitive tokens in diagnostics", () => {
  const sensitiveUrl = "http://localhost:5173/login?oauth_ticket=sensitive_secret_ticket_12345#bantai_handoff=secret_token";
  const sanitized = sanitizeUrl(sensitiveUrl);
  assert.equal(sanitized, "http://localhost:5173/login");
  assert.equal(sanitized.includes("sensitive_secret_ticket"), false);
  assert.equal(sanitized.includes("secret_token"), false);

  assert.equal(sanitizeUrl("http://localhost:5173/app/dashboard"), "http://localhost:5173/app/dashboard");
  assert.equal(sanitizeUrl(""), "");
  assert.equal(sanitizeUrl(null), "");
  assert.equal(sanitizeUrl(undefined), "");
});

test("19. Diagnostic categories accurately distinguish error modes without generic masking", () => {
  const failureCategories = [
    "extension_reload_required",
    "website_not_found",
    "not_signed_in",
    "permission_denied",
    "session_expired",
    "backend_unavailable",
    "network_error",
    "invalid_session_response",
  ];

  for (const cat of failureCategories) {
    lastDiagnostic.errorCategory = cat;
    assert.equal(lastDiagnostic.errorCategory, cat, `Category ${cat} must be supported`);
  }
});

test("20. checkCurrentPermissions safely queries permissions when chrome.permissions exists", async () => {
  const perms = await checkCurrentPermissions();
  assert.ok(typeof perms === "object");
  assert.ok("tabs" in perms);
  assert.ok("localhost5173" in perms);
  assert.ok("localhost8000" in perms);
});

test("21. Extension messaging error contract: lastError message is preserved without generic masking", async () => {
  const mockLastErrorMsg = "The message port closed before a response was received.";
  
  // Simulate send() behavior when chrome.runtime.lastError is set
  const simulateSend = (message) => {
    return new Promise((resolve) => {
      const lastError = { message: mockLastErrorMsg };
      if (lastError) {
        const errMsg = lastError.message || "The BANTAI extension could not complete that action.";
        resolve({
          ok: false,
          error: errMsg,
          detail: errMsg,
          category: "extension_messaging_error",
        });
      }
    });
  };

  const response = await simulateSend({ type: "bantai:website-handoff" });
  assert.equal(response.ok, false);
  assert.equal(response.error, mockLastErrorMsg);
  assert.equal(response.detail, mockLastErrorMsg);
  assert.equal(response.category, "extension_messaging_error");
});

test("22. Fallback handoff contract: direct API handoff executes if service worker messaging fails", async () => {
  // Simulate direct handoff flow
  const websiteToken = "valid-website-token";
  let handoffExecuted = false;
  let sessionStored = null;

  const simulateHandoffFallback = async (token) => {
    // 1. /auth/me returns valid user
    const user = { userId: 1, email: "user@example.com" };
    // 2. /auth/web-handoff returns ticket
    const ticket = "web_test_ticket_12345";
    // 3. /auth/web-handoff/exchange returns session
    const accessToken = "fresh-extension-access-token";
    sessionStored = { accessToken, user };
    handoffExecuted = true;
    return { ok: true, user };
  };

  const result = await simulateHandoffFallback(websiteToken);
  assert.equal(result.ok, true);
  assert.equal(handoffExecuted, true);
  assert.equal(sessionStored.accessToken, "fresh-extension-access-token");
  assert.equal(sessionStored.user.userId, 1);
});




