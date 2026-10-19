(() => {
  if (window.__bantaiGmailContentReady) return;
  window.__bantaiGmailContentReady = true;

  function isVisible(element) {
    return Boolean(element && element.getClientRects().length);
  }

  function extractActiveEmail() {
    const bodies = [...document.querySelectorAll("div.a3s")]
      .filter(isVisible)
      .map((element) => ({ element, text: element.innerText.trim() }))
      .filter((item) => item.text);
    const activeBody = bodies.at(-1);
    if (!activeBody) {
      return {
        ok: false,
        message: "No open email message was found. Open an individual message in Gmail and try again.",
      };
    }
    const visibleLinks = [...new Set(
      [...activeBody.element.querySelectorAll("a[href]")]
        .map((anchor) => anchor.href)
        .filter((href) => /^https?:\/\//i.test(href) && href.length <= 4096),
    )].slice(0, 100);

    const subjectElement = [...document.querySelectorAll("h2.hP, h2[role='heading']")]
      .find(isVisible);
    const subject = subjectElement?.innerText?.replace(/\s+/g, " ").trim() || "";

    let messageRoot = activeBody.element;
    for (let depth = 0; depth < 7 && messageRoot; depth += 1) {
      const senderElement = [...messageRoot.querySelectorAll(".gD[email], [email].gD")]
        .find(isVisible);
      const sender = senderElement?.getAttribute("email")?.replace(/[\r\n]/g, "").trim() || "";
      if (sender) {
        return { ok: true, subject, sender, body: activeBody.text, links: visibleLinks };
      }
      messageRoot = messageRoot.parentElement;
    }

    const senderElement = [...document.querySelectorAll(".gD[email]")]
      .filter(isVisible)
      .at(-1);
    return {
      ok: true,
      subject,
      sender: senderElement?.getAttribute("email")?.replace(/[\r\n]/g, "").trim() || "",
      body: activeBody.text,
      links: visibleLinks,
    };
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type !== "bantai:extract-active-email") return false;
    sendResponse(extractActiveEmail());
    return false;
  });
})();
