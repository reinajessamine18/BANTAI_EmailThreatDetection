const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000/api/v1";

function normalizeBaseUrl(value) {
  const parsed = new URL(value);
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("The API address must use HTTP or HTTPS.");
  }
  if (
    parsed.protocol !== "https:" &&
    !["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname)
  ) {
    throw new Error("Use HTTPS for non-local BANTAI servers.");
  }
  parsed.pathname = parsed.pathname.replace(/\/+$/, "");
  parsed.search = "";
  parsed.hash = "";
  return parsed.toString().replace(/\/+$/, "");
}

function apiError(status, data) {
  const detail = data?.detail;
  if (detail && !Array.isArray(detail) && typeof detail === "object") {
    return {
      status,
      code: detail.code || "request_failed",
      message: detail.message || "The BANTAI request failed.",
    };
  }
  if (Array.isArray(detail) && detail.length) {
    return {
      status,
      code: "validation_error",
      message: "Some submitted fields are invalid. Check them and try again.",
    };
  }
  return {
    status,
    code: "request_failed",
    message: "The BANTAI request failed. Please try again.",
  };
}

async function requestApi({ path, method = "GET", body, auth = true, authorizationToken }) {
  const stored = await chrome.storage.local.get(["apiBaseUrl", "accessToken"]);
  const baseUrl = normalizeBaseUrl(stored.apiBaseUrl || DEFAULT_API_BASE_URL);
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (authorizationToken) {
    headers.Authorization = `Bearer ${authorizationToken}`;
  } else if (auth && stored.accessToken) {
    headers.Authorization = `Bearer ${stored.accessToken}`;
  }

  let response;
  try {
    response = await fetch(`${baseUrl}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
    });
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

  if (!response.ok) {
    const data = await response.json().catch(() => null);
    if (response.status === 401 && auth) {
      await chrome.storage.local.remove(["accessToken", "user"]);
    }
    return { ok: false, error: apiError(response.status, data) };
  }

  if (response.status === 204) return { ok: true, data: null };
  return { ok: true, data: await response.json() };
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "bantai:website-handoff") {
    (async () => {
      const websiteToken = typeof message.accessToken === "string"
        ? message.accessToken
        : "";
      if (!websiteToken) {
        sendResponse({ ok: false, error: "The website session is unavailable." });
        return;
      }

      const websiteProfile = await requestApi({
        path: "/auth/me",
        auth: false,
        authorizationToken: websiteToken,
      });
      if (!websiteProfile.ok || !websiteProfile.data?.user) {
        sendResponse({
          ok: false,
          error: websiteProfile.error?.message || "Sign in on the BANTAI website to continue.",
        });
        return;
      }

      const currentProfile = await requestApi({ path: "/auth/me" });
      if (
        currentProfile.ok &&
        currentProfile.data?.user?.userId === websiteProfile.data.user.userId
      ) {
        sendResponse({ ok: true, user: websiteProfile.data.user, reused: true });
        return;
      }
      if (currentProfile.ok) {
        await requestApi({ path: "/auth/logout", method: "POST" });
      }

      const created = await requestApi({
        path: "/auth/web-handoff",
        method: "POST",
        auth: false,
        authorizationToken: websiteToken,
      });
      if (!created.ok || typeof created.data?.ticket !== "string") {
        sendResponse({
          ok: false,
          error: created.error?.message || "Could not prepare the website sign-in.",
        });
        return;
      }

      const exchanged = await requestApi({
        path: "/auth/web-handoff/exchange",
        method: "POST",
        body: { ticket: created.data.ticket },
        auth: false,
      });
      if (!exchanged.ok || typeof exchanged.data?.accessToken !== "string" || !exchanged.data.user) {
        sendResponse({
          ok: false,
          error: exchanged.error?.message || "Could not complete the website sign-in.",
        });
        return;
      }

      await chrome.storage.local.set({
        accessToken: exchanged.data.accessToken,
        user: exchanged.data.user,
      });
      sendResponse({ ok: true, user: exchanged.data.user });
    })().catch(() => {
      sendResponse({ ok: false, error: "Could not complete the website sign-in." });
    });
    return true;
  }

  if (message?.type === "bantai:api-request") {
    requestApi(message.request)
      .then(sendResponse)
      .catch(() => {
        sendResponse({
          ok: false,
          error: {
            status: 0,
            code: "extension_error",
            message: "The extension could not complete the request.",
          },
        });
      });
    return true;
  }

  if (message?.type === "bantai:get-session") {
    chrome.storage.local
      .get(["accessToken", "user", "apiBaseUrl", "webAppUrl"])
      .then((stored) =>
        sendResponse({
          accessToken: stored.accessToken || null,
          user: stored.user || null,
          apiBaseUrl: stored.apiBaseUrl || DEFAULT_API_BASE_URL,
          webAppUrl: stored.webAppUrl || "http://localhost:5173",
        }),
      )
      .catch(() => sendResponse({ error: "Extension storage is unavailable." }));
    return true;
  }

  if (message?.type === "bantai:set-session") {
    chrome.storage.local
      .set({ accessToken: message.accessToken, user: message.user })
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false, error: "Could not save the sign-in session." }));
    return true;
  }

  if (message?.type === "bantai:clear-session") {
    chrome.storage.local
      .remove(["accessToken", "user"])
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false, error: "Could not clear the sign-in session." }));
    return true;
  }

  if (message?.type === "bantai:save-settings") {
    chrome.storage.local
      .set({
        apiBaseUrl: message.apiBaseUrl,
        webAppUrl: message.webAppUrl,
      })
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false, error: "Could not save extension settings." }));
    return true;
  }

  return false;
});
