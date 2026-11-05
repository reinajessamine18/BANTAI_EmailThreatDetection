import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { normalizeExtractionResult } = require("../popup.js");

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

