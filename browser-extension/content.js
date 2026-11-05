(() => {
  if (typeof window !== "undefined" && window.__bantaiContentScriptLoaded) {
    return;
  }
  if (typeof window !== "undefined") {
    window.__bantaiContentScriptLoaded = true;
  }
  const MAX_BODY_CHARS = 200000;
  let lastInteractedMessage = null;

  function isVisible(element) {
    if (!element) return false;
    if (typeof element.getClientRects === "function" && element.getClientRects().length === 0) {
      // Elements with no layout rects might be display:none or unrendered
    }
    const doc = element.ownerDocument || (typeof document !== "undefined" ? document : null);
    const win = doc?.defaultView || (typeof window !== "undefined" ? window : null);
    if (win && typeof win.getComputedStyle === "function") {
      const style = win.getComputedStyle(element);
      if (style && (style.display === "none" || style.visibility === "hidden" || style.opacity === "0")) {
        return false;
      }
    }
    const inlineStyle = element.getAttribute ? element.getAttribute("style") || "" : "";
    if (/display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0/i.test(inlineStyle)) {
      return false;
    }
    if (element.getAttribute && element.getAttribute("aria-hidden") === "true") {
      return false;
    }
    if (element.hasAttribute && element.hasAttribute("hidden")) {
      return false;
    }
    // Check if any ancestor is explicitly hidden
    if (element.parentElement && element.parentElement !== doc?.body && element.parentElement !== doc?.documentElement) {
      const parentInline = element.parentElement.getAttribute ? element.parentElement.getAttribute("style") || "" : "";
      if (/display\s*:\s*none|visibility\s*:\s*hidden/i.test(parentInline)) {
        return false;
      }
      if (element.parentElement.getAttribute && element.parentElement.getAttribute("aria-hidden") === "true") {
        return false;
      }
    }
    return true;
  }

  function cleanBodyNode(sourceNode) {
    const clone = sourceNode.cloneNode(true);

    // 1. Remove scripts, styles, templates, metadata
    clone.querySelectorAll("script, style, noscript, template, svg").forEach((el) => el.remove());

    // 2. Remove hidden tracking elements and tracking pixels
    clone.querySelectorAll("img").forEach((img) => {
      const w = img.getAttribute("width");
      const h = img.getAttribute("height");
      const style = img.getAttribute("style") || "";
      if (w === "1" || h === "1" || w === "0" || h === "0" || /display\s*:\s*none|visibility\s*:\s*hidden/i.test(style)) {
        img.remove();
      }
    });

    // 3. Remove attachment chips and download cards
    clone.querySelectorAll(".aQH, .hq.gt, .aZo, .aZp, [aria-label*='Attachment'], [data-tooltip*='Attachment']").forEach((el) => el.remove());

    // 4. Remove identifiable historical quoted reply containers
    // Target Gmail-specific quote classes while preserving standalone blockquotes
    clone.querySelectorAll(".gmail_quote, .gmail_extra, blockquote.gmail_quote, div.gmail_quote, div.gmail_default_quote").forEach((el) => el.remove());

    // 5. Remove elements explicitly or inherited styled as hidden
    clone.querySelectorAll("*").forEach((el) => {
      if (!isVisible(el)) {
        el.remove();
      }
    });

    // 6. Convert links to visible anchor text only (strictly excise raw href destinations)
    clone.querySelectorAll("a").forEach((anchor) => {
      const visibleText = (anchor.innerText || anchor.textContent || "").trim();
      anchor.replaceWith(clone.ownerDocument ? clone.ownerDocument.createTextNode(visibleText ? ` ${visibleText} ` : " ") : document.createTextNode(visibleText ? ` ${visibleText} ` : " "));
    });

    return clone;
  }

  function setupInteractionListeners(doc) {
    if (!doc || doc.__bantaiInteractionListenersAttached) return;
    doc.__bantaiInteractionListenersAttached = true;

    const trackInteraction = (event) => {
      const target = event.target;
      if (!target || typeof target.closest !== "function") return;
      const msg = target.closest(".adn.ads, .adn, [data-message-id], .gs");
      if (msg) {
        lastInteractedMessage = msg;
      }
    };

    doc.addEventListener("mousedown", trackInteraction, true);
    doc.addEventListener("keydown", trackInteraction, true);
    doc.addEventListener("click", trackInteraction, true);
    doc.addEventListener("focusin", trackInteraction, true);
  }

  function extractActiveEmail(doc = (typeof document !== "undefined" ? document : null)) {
    if (!doc) {
      return { ok: false, message: "No document context available." };
    }

    // 1. Identify all candidate expanded message containers in main view
    const candidateRoots = [
      ...doc.querySelectorAll(
        '[role="main"] .adn.ads, [role="main"] [data-message-id], [role="main"] .adn, [role="main"] .gs, .adn.ads, [data-message-id]'
      ),
    ].filter((el) => {
      if (!isVisible(el)) return false;
      const body = el.querySelector(".a3s, .ii.gt");
      return body && isVisible(body);
    });

    // Deduplicate nested matching containers: keep top-level message root
    const expandedRoots = candidateRoots.filter((root, idx, arr) => {
      return !arr.some((other) => other !== root && other.contains(root));
    });

    let targetMessageRoot = null;

    if (expandedRoots.length === 0) {
      return {
        ok: false,
        message: "No open email message was found. Open an individual message in Gmail and try again.",
      };
    } else if (expandedRoots.length === 1) {
      targetMessageRoot = expandedRoots[0];
    } else {
      // Multiple messages are expanded in this thread: determine active message without .at(-1)
      // Check 1: Last user-interacted message container
      if (lastInteractedMessage && lastInteractedMessage.isConnected !== false && isVisible(lastInteractedMessage)) {
        targetMessageRoot = expandedRoots.find(
          (root) => root === lastInteractedMessage || root.contains(lastInteractedMessage) || lastInteractedMessage.contains(root)
        ) || null;
      }

      // Check 2: Active focused element inside one of the expanded roots
      if (!targetMessageRoot && doc.activeElement && doc.activeElement !== doc.body) {
        const focusedContainer = typeof doc.activeElement.closest === "function"
          ? doc.activeElement.closest(".adn.ads, .adn, [data-message-id], .gs")
          : null;
        if (focusedContainer && isVisible(focusedContainer)) {
          targetMessageRoot = expandedRoots.find(
            (root) => root === focusedContainer || root.contains(focusedContainer) || focusedContainer.contains(root)
          ) || null;
        }
      }

      // Check 3: If still ambiguous, reject explicitly with code ambiguous_active_message
      if (!targetMessageRoot) {
        return {
          ok: false,
          code: "ambiguous_active_message",
          message: "Multiple messages are open in this conversation. Please collapse other messages or click inside the specific email you wish to analyze.",
        };
      }
    }

    // 2. Target the body element of the selected message
    const bodySelector = ".a3s.aiL, .a3s, .ii.gt";
    const bodyElements = [...targetMessageRoot.querySelectorAll(bodySelector)].filter(isVisible);
    const targetBodyElement = bodyElements[0] || targetMessageRoot;

    // 3. Clean and extract readable prose
    const cleaned = cleanBodyNode(targetBodyElement);
    let bodyText = (cleaned.innerText || cleaned.textContent || "")
      .replace(/\r\n/g, "\n")
      .replace(/[ \t]+/g, " ")
      .replace(/\n\s*\n\s*\n+/g, "\n\n")
      .trim();

    // 4. Validate extraction bounds and Unicode code-point length
    if (!bodyText) {
      return {
        ok: false,
        code: "degenerate_content",
        message: "The open message contains no readable text to analyze.",
      };
    }

    const codePointLength = Array.from(bodyText).length;
    if (codePointLength > MAX_BODY_CHARS) {
      return {
        ok: false,
        code: "body_too_long",
        message: `The message text length (${codePointLength} characters) exceeds the 200,000-character limit.`,
      };
    }

    // Context metadata (subject from heading, sender from selected message root)
    const subjectElement = [...doc.querySelectorAll(
      '[role="main"] h2.hP, h2.hP, h2[role="heading"]',
    )].find(isVisible);
    const senderElement = targetMessageRoot.querySelector('.gD[email], [email].gD, [email]')
      || doc.querySelector('[role="main"] .gD[email], .gD[email]');

    const contextSubject = subjectElement?.innerText?.replace(/\s+/g, " ")?.trim() || "";
    const contextSender = senderElement?.getAttribute?.("email")?.replace(/[\r\n]/g, "")?.trim()
      || senderElement?.innerText?.replace(/[\r\n]/g, "")?.trim()
      || "";

    return {
      ok: true,
      bodyText,
      body: bodyText,
      contextSubject,
      subject: contextSubject,
      contextSender,
      sender: contextSender,
    };
  }

  // Setup in browser context
  if (typeof document !== "undefined") {
    setupInteractionListeners(document);
  }

  if (typeof chrome !== "undefined" && chrome.runtime?.onMessage) {
    chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
      if (message?.type !== "bantai:extract-active-email") return false;
      sendResponse(extractActiveEmail());
      return false;
    });
  }

  // Export for testing in Node.js environments
  if (typeof module !== "undefined" && module.exports) {
    module.exports = {
      cleanBodyNode,
      extractActiveEmail,
      isVisible,
      setupInteractionListeners,
      setLastInteractedMessage: (el) => { lastInteractedMessage = el; },
      getLastInteractedMessage: () => lastInteractedMessage,
      MAX_BODY_CHARS,
    };
  }
})();
