(() => {
  if (window.__bantaiGmailContentReady) return;
  window.__bantaiGmailContentReady = true;

  function isVisible(element) {
    if (!element || !element.getClientRects().length) return false;
    const style = window.getComputedStyle(element);
    return style.display !== "none" && style.visibility !== "hidden";
  }

  function extractActiveEmail() {
    const subjectElement = [...document.querySelectorAll(
      '[role="main"] h2.hP, h2.hP, h2[role="heading"]',
    )].find(isVisible);
    const senderElement = [...document.querySelectorAll(
      '[role="main"] .gD[email], .gD[email], [email].gD',
    )].filter(isVisible).at(-1);
    const messageRoot = senderElement?.closest(".adn.ads, .adn, [data-message-id], .gs")
      || subjectElement?.closest(".adn.ads, .adn, [data-message-id], .gs")
      || [...document.querySelectorAll(
        '[role="main"] .adn.ads, [role="main"] .adn, [role="main"] [data-message-id], [role="main"] .gs',
      )].filter(isVisible).at(-1);
    const bodySelector = [
      ".a3s",
      ".ii.gt",
      ".adn.ads .ii.gt",
      "[data-message-id] .ii.gt",
    ].join(", ");
    const bodies = [...document.querySelectorAll(bodySelector)]
      .filter(isVisible)
      .map((element) => ({ element, text: element.innerText.trim() }))
      .filter((item) => item.text);
    const activeBody = bodies
      .filter((item) => !messageRoot || messageRoot.contains(item.element))
      .at(-1) || bodies.at(-1);
    let body = activeBody?.text || "";
    let contentRoot = activeBody?.element || messageRoot;

    if (!body && messageRoot && isVisible(messageRoot)) {
      body = messageRoot.innerText?.trim() || "";
    }
    if (!body) {
      const subject = subjectElement?.innerText?.replace(/\s+/g, " ").trim() || "";
      const sender = senderElement?.getAttribute("email")?.replace(/[\r\n]/g, "").trim() || "";
      return {
        ok: false,
        message: subject || sender
          ? "The email is open, but Gmail has not rendered its message text yet. Wait a moment and check the active tab again."
          : "No open email message was found. Open an individual message in Gmail and try again.",
      };
    }
    if (!contentRoot) {
      contentRoot = messageRoot || activeBody?.element;
    }

    if (!contentRoot) {
      return {
        ok: false,
        message: "No open email message was found. Open an individual message in Gmail and try again.",
      };
    }
    const visibleLinks = [...new Set(
      [...contentRoot.querySelectorAll("a[href]")]
        .map((anchor) => anchor.href)
        .filter((href) => /^https?:\/\//i.test(href) && href.length <= 4096),
    )].slice(0, 100);

    const subject = subjectElement?.innerText?.replace(/\s+/g, " ").trim() || "";
    return {
      ok: true,
      subject,
      sender: senderElement?.getAttribute("email")?.replace(/[\r\n]/g, "").trim() || "",
      body,
      links: visibleLinks,
    };
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type !== "bantai:extract-active-email") return false;
    sendResponse(extractActiveEmail());
    return false;
  });
})();
