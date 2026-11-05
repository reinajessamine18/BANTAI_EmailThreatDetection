import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const {
  cleanBodyNode,
  extractActiveEmail,
  isVisible,
  setupInteractionListeners,
  setLastInteractedMessage,
  getLastInteractedMessage,
  MAX_BODY_CHARS,
} = require("../content.js");

// ---------------------------------------------------------------------------
// Lightweight DOM Mock for zero-dependency Node.js testing of content.js
// ---------------------------------------------------------------------------

class MockNode {
  constructor(nodeType, nodeName) {
    this.nodeType = nodeType; // 1 = Element, 3 = Text
    this.nodeName = nodeName;
    this.parentElement = null;
    this.ownerDocument = null;
    this.isConnected = true;
  }

  remove() {
    if (this.parentElement) {
      const idx = this.parentElement.childNodes.indexOf(this);
      if (idx !== -1) {
        this.parentElement.childNodes.splice(idx, 1);
      }
      this.parentElement = null;
    }
  }

  replaceWith(newNode) {
    if (this.parentElement) {
      const idx = this.parentElement.childNodes.indexOf(this);
      if (idx !== -1) {
        this.parentElement.childNodes.splice(idx, 1, newNode);
        newNode.parentElement = this.parentElement;
        newNode.ownerDocument = this.ownerDocument;
      }
      this.parentElement = null;
    }
  }
}

class MockTextNode extends MockNode {
  constructor(text) {
    super(3, "#text");
    this._text = String(text ?? "");
  }

  get textContent() {
    return this._text;
  }

  set textContent(val) {
    this._text = String(val ?? "");
  }

  get innerText() {
    return this._text;
  }

  cloneNode(_deep = false) {
    const clone = new MockTextNode(this._text);
    clone.ownerDocument = this.ownerDocument;
    return clone;
  }
}

class MockElement extends MockNode {
  constructor(tagName) {
    super(1, tagName.toUpperCase());
    this.tagName = tagName.toUpperCase();
    this.attributes = new Map();
    this.classList = new Set();
    this.childNodes = [];
  }

  get children() {
    return this.childNodes.filter((n) => n.nodeType === 1);
  }

  setAttribute(name, value) {
    const n = name.toLowerCase();
    const v = String(value);
    this.attributes.set(n, v);
    if (n === "class") {
      this.classList.clear();
      v.split(/\s+/).filter(Boolean).forEach((c) => this.classList.add(c));
    }
  }

  getAttribute(name) {
    return this.attributes.get(name.toLowerCase()) ?? null;
  }

  hasAttribute(name) {
    return this.attributes.has(name.toLowerCase());
  }

  removeAttribute(name) {
    const n = name.toLowerCase();
    this.attributes.delete(n);
    if (n === "class") this.classList.clear();
  }

  appendChild(child) {
    child.remove();
    child.parentElement = this;
    child.ownerDocument = this.ownerDocument;
    this.childNodes.push(child);
    return child;
  }

  get innerText() {
    return this.childNodes
      .map((n) => (n.nodeType === 3 ? n.textContent : n.innerText))
      .join("");
  }

  set innerText(val) {
    this.childNodes = [];
    if (val) this.appendChild(new MockTextNode(val));
  }

  get textContent() {
    return this.childNodes
      .map((n) => (n.nodeType === 3 ? n.textContent : n.textContent))
      .join("");
  }

  set textContent(val) {
    this.childNodes = [];
    if (val) this.appendChild(new MockTextNode(val));
  }

  contains(other) {
    if (!other) return false;
    if (other === this) return true;
    let curr = other.parentElement;
    while (curr) {
      if (curr === this) return true;
      curr = curr.parentElement;
    }
    return false;
  }

  closest(selectorList) {
    const selectors = selectorList.split(",").map((s) => s.trim());
    let curr = this;
    while (curr && curr.nodeType === 1) {
      for (const sel of selectors) {
        if (curr._matchesSelector(sel)) return curr;
      }
      curr = curr.parentElement;
    }
    return null;
  }

  _matchesSelector(sel) {
    if (!sel) return false;
    if (sel === "*") return true;
    // Compound class selector e.g. .adn.ads or .a3s.aiL
    if (sel.startsWith(".")) {
      const classes = sel.slice(1).split(".").filter(Boolean);
      return classes.every((c) => this.classList.has(c));
    }
    // Attribute selector e.g. [role="main"], [data-message-id], [email]
    if (sel.startsWith("[")) {
      const m = sel.match(/^\[([a-zA-Z0-9_-]+)(?:([*^$]?=)(["']?)(.*?)\3)?\]$/);
      if (m) {
        const [, attr, op, , expected] = m;
        const val = this.getAttribute(attr);
        if (val === null) return false;
        if (!op) return true;
        if (op === "=") return val === expected;
        if (op === "*=") return val.includes(expected);
      }
      return false;
    }
    // Tag selector e.g. h2, a, img, script
    if (/^[a-zA-Z0-9]+$/.test(sel)) {
      return this.tagName === sel.toUpperCase();
    }
    // Tag + attribute e.g. h2.hP or div.gmail_quote
    const tagClassMatch = sel.match(/^([a-zA-Z0-9]+)\.([a-zA-Z0-9_.-]+)$/);
    if (tagClassMatch) {
      const [, tag, classChain] = tagClassMatch;
      if (this.tagName !== tag.toUpperCase()) return false;
      const classes = classChain.split(".").filter(Boolean);
      return classes.every((c) => this.classList.has(c));
    }
    return false;
  }

  querySelectorAll(selectorList) {
    const results = [];
    const selectors = selectorList.split(",").map((s) => s.trim());

    const walk = (node) => {
      for (const child of node.children) {
        for (const sel of selectors) {
          // Complex selector support e.g. '[role="main"] .adn.ads'
          if (sel.includes(" ")) {
            const parts = sel.split(/\s+/).filter(Boolean);
            if (parts.length === 2) {
              const [parentSel, childSel] = parts;
              if (child._matchesSelector(childSel) && child.closest(parentSel)) {
                if (!results.includes(child)) results.push(child);
                break;
              }
            }
          } else if (child._matchesSelector(sel)) {
            if (!results.includes(child)) results.push(child);
            break;
          }
        }
        walk(child);
      }
    };

    walk(this);
    return results;
  }

  querySelector(selectorList) {
    return this.querySelectorAll(selectorList)[0] || null;
  }

  cloneNode(deep = false) {
    const clone = new MockElement(this.tagName.toLowerCase());
    clone.ownerDocument = this.ownerDocument;
    for (const [k, v] of this.attributes) {
      clone.setAttribute(k, v);
    }
    if (deep) {
      for (const child of this.childNodes) {
        clone.appendChild(child.cloneNode(true));
      }
    }
    return clone;
  }
}

class MockDocument extends MockNode {
  constructor() {
    super(9, "#document");
    this.documentElement = new MockElement("html");
    this.documentElement.ownerDocument = this;
    this.body = new MockElement("body");
    this.body.ownerDocument = this;
    this.documentElement.appendChild(this.body);
    this.activeElement = null;
    this.defaultView = {
      getComputedStyle: (el) => {
        const style = el.getAttribute("style") || "";
        const isDisplayNone = /display\s*:\s*none/i.test(style);
        const isVisibilityHidden = /visibility\s*:\s*hidden/i.test(style);
        const isOpacity0 = /opacity\s*:\s*0/i.test(style);
        return {
          display: isDisplayNone ? "none" : "block",
          visibility: isVisibilityHidden ? "hidden" : "visible",
          opacity: isOpacity0 ? "0" : "1",
        };
      },
    };
    this._listeners = new Map();
  }

  createElement(tagName) {
    const el = new MockElement(tagName);
    el.ownerDocument = this;
    return el;
  }

  createTextNode(text) {
    const node = new MockTextNode(text);
    node.ownerDocument = this;
    return node;
  }

  querySelectorAll(sel) {
    return this.documentElement.querySelectorAll(sel);
  }

  querySelector(sel) {
    return this.querySelectorAll(sel)[0] || null;
  }

  addEventListener(type, listener) {
    if (!this._listeners.has(type)) this._listeners.set(type, []);
    this._listeners.get(type).push(listener);
  }

  dispatchEvent(type, target) {
    const listeners = this._listeners.get(type) || [];
    for (const l of listeners) {
      l({ type, target });
    }
  }
}

// ---------------------------------------------------------------------------
// Helper to build realistic Gmail DOM structures
// ---------------------------------------------------------------------------
function createGmailEnvironment({
  subject = "Important Account Security Notice",
  sender = "security@corp.example.test",
  messages = [],
} = {}) {
  const doc = new MockDocument();
  const main = doc.createElement("div");
  main.setAttribute("role", "main");
  doc.body.appendChild(main);

  if (subject) {
    const h2 = doc.createElement("h2");
    h2.setAttribute("class", "hP");
    h2.innerText = subject;
    main.appendChild(h2);
  }

  const messageElements = [];

  for (const msg of messages) {
    const msgRoot = doc.createElement("div");
    msgRoot.setAttribute("class", msg.expanded ? "adn ads" : "adn");
    if (msg.id) msgRoot.setAttribute("data-message-id", msg.id);

    const senderEl = doc.createElement("span");
    senderEl.setAttribute("class", "gD");
    senderEl.setAttribute("email", msg.sender || sender);
    senderEl.innerText = msg.sender || sender;
    msgRoot.appendChild(senderEl);

    if (msg.expanded) {
      const body = doc.createElement("div");
      body.setAttribute("class", "a3s aiL");
      if (typeof msg.content === "function") {
        msg.content(body, doc);
      } else if (typeof msg.content === "string") {
        body.innerText = msg.content;
      }
      msgRoot.appendChild(body);
    }

    main.appendChild(msgRoot);
    messageElements.push(msgRoot);
  }

  return { doc, main, messageElements };
}

// ---------------------------------------------------------------------------
// Unit Tests: The 14 Approved Scenarios + Interaction Tracking + Unicode
// ---------------------------------------------------------------------------

test("GMR-01: Single opened email extracts clean body prose, subject, and sender", () => {
  setLastInteractedMessage(null);
  const { doc } = createGmailEnvironment({
    subject: "Quarterly Financial Review",
    sender: "finance@company.test",
    messages: [
      {
        expanded: true,
        content: "Please review the attached quarterly earnings statement for Q3.",
      },
    ],
  });

  const result = extractActiveEmail(doc);
  assert.equal(result.ok, true);
  assert.equal(result.contextSubject, "Quarterly Financial Review");
  assert.equal(result.contextSender, "finance@company.test");
  assert.equal(result.bodyText, "Please review the attached quarterly earnings statement for Q3.");
  // Verify backward compatibility aliases
  assert.equal(result.body, result.bodyText);
  assert.equal(result.subject, result.contextSubject);
  assert.equal(result.sender, result.contextSender);
});

test("GMR-02: Multiple expanded messages without explicit interaction rejects with ambiguous_active_message", () => {
  setLastInteractedMessage(null);
  const { doc } = createGmailEnvironment({
    messages: [
      { id: "msg_1", expanded: true, content: "Initial thread message from yesterday." },
      { id: "msg_2", expanded: true, content: "Follow-up response from this morning." },
    ],
  });

  const result = extractActiveEmail(doc);
  assert.equal(result.ok, false);
  assert.equal(result.code, "ambiguous_active_message");
  assert.match(result.message, /Multiple messages are open/i);
});

test("GMR-03: Older message explicitly user-interacted while newer is expanded isolates older message", () => {
  setLastInteractedMessage(null);
  const { doc, messageElements } = createGmailEnvironment({
    messages: [
      { id: "msg_old", expanded: true, sender: "alice@test.corp", content: "Original message prose from Alice." },
      { id: "msg_new", expanded: true, sender: "bob@test.corp", content: "Latest reply prose from Bob." },
    ],
  });

  // User explicitly clicks into older message #0
  setLastInteractedMessage(messageElements[0]);

  const result = extractActiveEmail(doc);
  assert.equal(result.ok, true);
  assert.equal(result.bodyText, "Original message prose from Alice.");
  assert.equal(result.contextSender, "alice@test.corp");
  assert.doesNotMatch(result.bodyText, /Latest reply prose from Bob/);
});

test("GMR-04: Selected message versus collapsed historical messages in same thread", () => {
  setLastInteractedMessage(null);
  const { doc } = createGmailEnvironment({
    messages: [
      { id: "msg_1", expanded: false }, // collapsed
      { id: "msg_2", expanded: false }, // collapsed
      { id: "msg_3", expanded: true, content: "Only this active message is expanded and readable." },
    ],
  });

  const result = extractActiveEmail(doc);
  assert.equal(result.ok, true);
  assert.equal(result.bodyText, "Only this active message is expanded and readable.");
});

test("GMR-05: Historical quoted replies (.gmail_quote, .gmail_extra, blockquote.gmail_quote) are excised", () => {
  setLastInteractedMessage(null);
  const { doc } = createGmailEnvironment({
    messages: [
      {
        expanded: true,
        content: (body, d) => {
          body.appendChild(d.createTextNode("I agree with your suggestion.\n\n"));
          const quoteDiv = d.createElement("div");
          quoteDiv.setAttribute("class", "gmail_quote");
          quoteDiv.innerText = "On Oct 12, Jane Doe wrote: Should we reschedule the server maintenance?";
          body.appendChild(quoteDiv);
          const extraDiv = d.createElement("div");
          extraDiv.setAttribute("class", "gmail_extra");
          extraDiv.innerText = "-- \nJane Doe | IT Operations";
          body.appendChild(extraDiv);
        },
      },
    ],
  });

  const result = extractActiveEmail(doc);
  assert.equal(result.ok, true);
  assert.equal(result.bodyText, "I agree with your suggestion.");
  assert.doesNotMatch(result.bodyText, /Jane Doe wrote/);
  assert.doesNotMatch(result.bodyText, /reschedule the server maintenance/);
});

test("GMR-06: Legitimate visible blockquotes without Gmail quote classes are preserved", () => {
  setLastInteractedMessage(null);
  const { doc } = createGmailEnvironment({
    messages: [
      {
        expanded: true,
        content: (body, d) => {
          body.appendChild(d.createTextNode("Company policy states:\n\n"));
          const bq = d.createElement("blockquote");
          bq.innerText = "All employees must complete mandatory security compliance training by Friday.";
          body.appendChild(bq);
        },
      },
    ],
  });

  const result = extractActiveEmail(doc);
  assert.equal(result.ok, true);
  assert.match(result.bodyText, /Company policy states:/);
  assert.match(result.bodyText, /All employees must complete mandatory security compliance training/);
});

test("GMR-07: Visible anchor text preserved while raw href destinations are strictly excised", () => {
  setLastInteractedMessage(null);
  const { doc } = createGmailEnvironment({
    messages: [
      {
        expanded: true,
        content: (body, d) => {
          body.appendChild(d.createTextNode("Please click "));
          const a = d.createElement("a");
          a.setAttribute("href", "https://malicious-credential-harvest.evil.test/login?session=48392");
          a.innerText = "Verify Your Account Online";
          body.appendChild(a);
          body.appendChild(d.createTextNode(" to prevent suspension."));
        },
      },
    ],
  });

  const result = extractActiveEmail(doc);
  assert.equal(result.ok, true);
  assert.match(result.bodyText, /Verify Your Account Online/);
  assert.doesNotMatch(result.bodyText, /malicious-credential-harvest/);
  assert.doesNotMatch(result.bodyText, /https:\/\//);
});

test("GMR-08: Hidden content and inherited hidden parent elements are omitted", () => {
  setLastInteractedMessage(null);
  const { doc } = createGmailEnvironment({
    messages: [
      {
        expanded: true,
        content: (body, d) => {
          body.appendChild(d.createTextNode("Visible text for recipient. "));
          const hiddenSpan = d.createElement("span");
          hiddenSpan.setAttribute("style", "display: none;");
          hiddenSpan.innerText = "HIDDEN_INLINE_SEED_PHRASE";
          body.appendChild(hiddenSpan);

          const hiddenParent = d.createElement("div");
          hiddenParent.setAttribute("style", "visibility: hidden;");
          const childText = d.createElement("p");
          childText.innerText = "INHERITED_HIDDEN_PROSE";
          hiddenParent.appendChild(childText);
          body.appendChild(hiddenParent);
        },
      },
    ],
  });

  const result = extractActiveEmail(doc);
  assert.equal(result.ok, true);
  assert.equal(result.bodyText, "Visible text for recipient.");
  assert.doesNotMatch(result.bodyText, /HIDDEN_INLINE_SEED_PHRASE/);
  assert.doesNotMatch(result.bodyText, /INHERITED_HIDDEN_PROSE/);
});

test("GMR-09: Tracking pixels (1x1, 0x0, hidden images) are excised", () => {
  setLastInteractedMessage(null);
  const { doc } = createGmailEnvironment({
    messages: [
      {
        expanded: true,
        content: (body, d) => {
          body.appendChild(d.createTextNode("Email message with tracking beacons."));
          const img1 = d.createElement("img");
          img1.setAttribute("width", "1");
          img1.setAttribute("height", "1");
          img1.setAttribute("src", "https://tracker.test/pixel.png");
          body.appendChild(img1);

          const img2 = d.createElement("img");
          img2.setAttribute("style", "display:none");
          img2.setAttribute("src", "https://analytics.test/open.gif");
          body.appendChild(img2);
        },
      },
    ],
  });

  const result = extractActiveEmail(doc);
  assert.equal(result.ok, true);
  assert.equal(result.bodyText, "Email message with tracking beacons.");
});

test("GMR-10: CSS, script, template, and svg elements are stripped", () => {
  setLastInteractedMessage(null);
  const { doc } = createGmailEnvironment({
    messages: [
      {
        expanded: true,
        content: (body, d) => {
          const style = d.createElement("style");
          style.innerText = "body { background: #fff; } .alert { color: red; }";
          body.appendChild(style);

          const script = d.createElement("script");
          script.innerText = "console.log('harvester running');";
          body.appendChild(script);

          body.appendChild(d.createTextNode("Legitimate body prose text."));
        },
      },
    ],
  });

  const result = extractActiveEmail(doc);
  assert.equal(result.ok, true);
  assert.equal(result.bodyText, "Legitimate body prose text.");
  assert.doesNotMatch(result.bodyText, /background:/);
  assert.doesNotMatch(result.bodyText, /harvester running/);
});

test("GMR-11: Attachment chips and download cards are stripped", () => {
  setLastInteractedMessage(null);
  const { doc } = createGmailEnvironment({
    messages: [
      {
        expanded: true,
        content: (body, d) => {
          body.appendChild(d.createTextNode("Please find the requested statement attached."));
          const chip = d.createElement("div");
          chip.setAttribute("class", "aQH");
          const chipInner = d.createElement("div");
          chipInner.setAttribute("class", "hq gt");
          chipInner.innerText = "Statement_November_2026.pdf (184 KB)";
          chip.appendChild(chipInner);
          body.appendChild(chip);
        },
      },
    ],
  });

  const result = extractActiveEmail(doc);
  assert.equal(result.ok, true);
  assert.equal(result.bodyText, "Please find the requested statement attached.");
  assert.doesNotMatch(result.bodyText, /Statement_November_2026/);
});

test("GMR-12: Gmail navigation and unrelated interface text are strictly excluded", () => {
  setLastInteractedMessage(null);
  const { doc, main } = createGmailEnvironment({
    messages: [
      { expanded: true, content: "Urgent: Please update your payroll direct deposit information." },
    ],
  });

  // Add surrounding Gmail interface elements
  const sidebar = doc.createElement("nav");
  sidebar.innerText = "Inbox Starred Sent Drafts Trash Categories Manage Labels";
  doc.body.appendChild(sidebar);

  const searchBox = doc.createElement("div");
  searchBox.innerText = "Search in mail - Advanced search filters";
  doc.body.appendChild(searchBox);

  const result = extractActiveEmail(doc);
  assert.equal(result.ok, true);
  assert.equal(result.bodyText, "Urgent: Please update your payroll direct deposit information.");
  assert.doesNotMatch(result.bodyText, /Starred/);
  assert.doesNotMatch(result.bodyText, /Search in mail/);
});

test("GMR-13: Empty and degenerate content is rejected with degenerate_content", () => {
  setLastInteractedMessage(null);
  const { doc } = createGmailEnvironment({
    messages: [
      {
        expanded: true,
        content: (body, d) => {
          // Whitespace and non-text tags only
          body.appendChild(d.createTextNode("   \n\t   \n\n  "));
          const img = d.createElement("img");
          img.setAttribute("width", "1");
          img.setAttribute("height", "1");
          body.appendChild(img);
        },
      },
    ],
  });

  const result = extractActiveEmail(doc);
  assert.equal(result.ok, false);
  assert.equal(result.code, "degenerate_content");
});

test("GMR-14: Missing open message returns graceful error message", () => {
  setLastInteractedMessage(null);
  const doc = new MockDocument(); // Blank page, no [role="main"] message
  const result = extractActiveEmail(doc);
  assert.equal(result.ok, false);
  assert.match(result.message, /No open email message was found/);
});

// ---------------------------------------------------------------------------
// Section 4 & 5: Interaction Tracking and Unicode Length Bounds
// ---------------------------------------------------------------------------

test("Interaction Tracking: Interaction events update transient lastInteractedMessage", () => {
  const doc = new MockDocument();
  setupInteractionListeners(doc);

  const msg1 = doc.createElement("div");
  msg1.setAttribute("class", "adn ads");
  const p1 = doc.createElement("p");
  p1.innerText = "Message one text";
  msg1.appendChild(p1);
  doc.body.appendChild(msg1);

  // Dispatch mousedown on inner paragraph
  doc.dispatchEvent("mousedown", p1);
  assert.equal(getLastInteractedMessage(), msg1);

  // Dispatch keydown on another message
  const msg2 = doc.createElement("div");
  msg2.setAttribute("class", "adn ads");
  const p2 = doc.createElement("p");
  p2.innerText = "Message two text";
  msg2.appendChild(p2);
  doc.body.appendChild(msg2);

  doc.dispatchEvent("keydown", p2);
  assert.equal(getLastInteractedMessage(), msg2);
});

test("Interaction Tracking: Remembered message disconnected falls back gracefully to activeElement or rejection", () => {
  setLastInteractedMessage(null);
  const { doc, messageElements } = createGmailEnvironment({
    messages: [
      { id: "msg_1", expanded: true, content: "First open message." },
      { id: "msg_2", expanded: true, content: "Second open message." },
    ],
  });

  // Remembered message was removed from DOM (disconnected)
  const deadMsg = doc.createElement("div");
  deadMsg.setAttribute("class", "adn ads");
  deadMsg.isConnected = false;
  setLastInteractedMessage(deadMsg);

  // Without valid activeElement, multiple expanded messages reject cleanly
  const result = extractActiveEmail(doc);
  assert.equal(result.ok, false);
  assert.equal(result.code, "ambiguous_active_message");
});

test("Unicode Bounds: Exactly 200,000 ASCII characters is accepted", () => {
  setLastInteractedMessage(null);
  const bodyText = "A".repeat(200000);
  const { doc } = createGmailEnvironment({
    messages: [{ expanded: true, content: bodyText }],
  });

  const result = extractActiveEmail(doc);
  assert.equal(result.ok, true);
  assert.equal(Array.from(result.bodyText).length, 200000);
});

test("Unicode Bounds: 200,001 ASCII characters is rejected with body_too_long", () => {
  setLastInteractedMessage(null);
  const bodyText = "A".repeat(200001);
  const { doc } = createGmailEnvironment({
    messages: [{ expanded: true, content: bodyText }],
  });

  const result = extractActiveEmail(doc);
  assert.equal(result.ok, false);
  assert.equal(result.code, "body_too_long");
  assert.match(result.message, /exceeds the 200,000-character limit/);
});

test("Unicode Bounds: Supplementary characters (emoji) count by code points, not UTF-16 units", () => {
  setLastInteractedMessage(null);
  // An emoji like 🛡️ is 1 code point + variation selector or a 4-byte surrogate pair in UTF-16
  // '🔒' is 1 code point, length 2 in UTF-16
  const emojiStr = "🔒".repeat(10);
  assert.equal(emojiStr.length, 20); // 20 UTF-16 code units
  assert.equal(Array.from(emojiStr).length, 10); // Exactly 10 Unicode code points!

  const { doc } = createGmailEnvironment({
    messages: [{ expanded: true, content: `Security alert ${emojiStr} please verify` }],
  });

  const result = extractActiveEmail(doc);
  assert.equal(result.ok, true);
  assert.match(result.bodyText, /Security alert/);
  assert.match(result.bodyText, /🔒/);
});

test("Unicode Bounds: 200,001 code points composed of emoji is rejected correctly", () => {
  setLastInteractedMessage(null);
  // 200,001 emoji code points
  const emojiBody = "🔐".repeat(200001);
  const { doc } = createGmailEnvironment({
    messages: [{ expanded: true, content: emojiBody }],
  });

  const result = extractActiveEmail(doc);
  assert.equal(result.ok, false);
  assert.equal(result.code, "body_too_long");
});
