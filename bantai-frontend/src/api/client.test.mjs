// Run with:  node --test src/api/client.test.mjs      (no extra packages needed; Node 20+)
import test from "node:test";
import assert from "node:assert/strict";

// ---- fakes installed BEFORE the client is imported --------------------------------------------
const memory = () => {
  const data = new Map();
  return { getItem: (k) => (data.has(k) ? data.get(k) : null), setItem: (k, v) => data.set(k, String(v)),
           removeItem: (k) => data.delete(k), has: (k) => data.has(k) };
};
globalThis.sessionStorage = memory();
globalThis.localStorage = memory();
const events = [];
globalThis.window = { dispatchEvent: (e) => events.push(e.type) };

let calls = [];
let reply = () => ({ status: 200, body: {} });
globalThis.fetch = async (url, init = {}) => {
  calls.push({ url, ...init });
  const r = reply(url, init);
  if (r instanceof Error) throw r;
  return {
    status: r.status, ok: r.status >= 200 && r.status < 300,
    headers: { get: (k) => (r.headers || {})[k.toLowerCase()] ?? null },
    json: async () => { if (r.body === undefined) throw new Error("no json"); return r.body; },
    blob: async () => new Blob([r.text ?? ""]),
  };
};

const api = await import("./client.js");
const reset = () => { calls = []; events.length = 0; globalThis.sessionStorage.removeItem("bantaiToken"); reply = () => ({ status: 200, body: {} }); };
const lastHeaders = () => calls.at(-1).headers;

// ---- token + header rules ---------------------------------------------------------------------
test("no token means no Authorization header (never 'Bearer null')", async () => {
  reset();
  await api.getDashboard("7");
  assert.equal(lastHeaders().Authorization, undefined);
});

test("a stored token is sent as a Bearer header", async () => {
  reset(); api.setToken("tok123");
  await api.getDashboard("7");
  assert.equal(lastHeaders().Authorization, "Bearer tok123");
});

test("a guest scan NEVER attaches the token, even when one is stored", async () => {
  reset(); api.setToken("tok123");
  await api.scanEmail({ text: "hello", signedIn: false });
  assert.equal(lastHeaders().Authorization, undefined);
  await api.scanEmail({ text: "hello", signedIn: true });
  assert.equal(lastHeaders().Authorization, "Bearer tok123");
});

// ---- auth flows -------------------------------------------------------------------------------
test("register sends snake_case full_name, stores the token, returns the user", async () => {
  reset();
  reply = () => ({ status: 201, body: { accessToken: "abc", user: { fullName: "Ana" } } });
  const user = await api.register({ fullName: "Ana Test", email: "a@x.example", password: "longenough1!" });
  assert.deepEqual(JSON.parse(calls[0].body), { full_name: "Ana Test", email: "a@x.example", password: "longenough1!" });
  assert.equal(api.getToken(), "abc");
  assert.equal(user.fullName, "Ana");
  assert.match(calls[0].url, /\/auth\/register$/);
});

test("login stores the token; the password is never written to browser storage", async () => {
  reset();
  reply = () => ({ status: 200, body: { accessToken: "t9", user: { email: "a@x.example" } } });
  await api.login({ email: "a@x.example", password: "SuperSecret-12345" });
  assert.equal(api.getToken(), "t9");
  assert.equal(globalThis.localStorage.has("bantaiUser"), false);
  const everything = JSON.stringify([...["bantaiToken"].map((k) => globalThis.sessionStorage.getItem(k))]);
  assert.ok(!everything.includes("SuperSecret"));
});

test("logout clears the token even when the server is unreachable", async () => {
  reset(); api.setToken("tok");
  reply = () => new Error("offline");
  await api.logout();
  assert.equal(api.getToken(), null);
});

test("logout handles the server's empty 204 reply", async () => {
  reset(); api.setToken("tok");
  reply = () => ({ status: 204 });
  await api.logout();
  assert.equal(api.getToken(), null);
  assert.equal(calls[0].method, "POST");
});

test("a 401 on a signed-in call clears the token and announces the expiry", async () => {
  reset(); api.setToken("old");
  reply = () => ({ status: 401, body: { detail: { code: "invalid_token", message: "expired" } } });
  await assert.rejects(api.getMe(), (e) => e.status === 401 && e.code === "invalid_token");
  assert.equal(api.getToken(), null);
  assert.deepEqual(events, [api.SESSION_EXPIRED_EVENT]);
});

test("a 401 from a WRONG PASSWORD (no token yet) does not fire the session-expired event", async () => {
  reset();
  reply = () => ({ status: 401, body: { detail: { code: "invalid_credentials", message: "Email or password is incorrect." } } });
  await assert.rejects(api.login({ email: "a@x.example", password: "x" }), (e) => e.code === "invalid_credentials");
  assert.deepEqual(events, []);
});

// ---- errors -----------------------------------------------------------------------------------
test("error shapes: detail object, validation list, network failure, non-JSON body", async () => {
  reset();
  reply = () => ({ status: 413, body: { detail: { code: "too_large", message: "big" } } });
  await assert.rejects(api.getDashboard(), (e) => e.code === "too_large" && e.status === 413);

  reply = () => ({ status: 422, body: { detail: [{ loc: ["body", "newPassword"], msg: "too short", type: "x" }] } });
  await assert.rejects(api.getDashboard(), (e) => e.code === "validation_error" && /newPassword/.test(e.message));

  reply = () => new Error("fetch failed");
  await assert.rejects(api.getDashboard(), (e) => e.code === "network_error" && e.status === 0);

  reply = () => ({ status: 500, body: undefined });
  await assert.rejects(api.getDashboard(), (e) => e.status === 500 && e.code === "error");
});

test("friendlyError maps known codes and never leaks unknown internals", () => {
  assert.match(api.friendlyError(new api.ApiError(503, "ml_unavailable", "x")), /unavailable/);
  assert.match(api.friendlyError(new api.ApiError(401, "invalid_token", "x")), /sign in again/);
  assert.equal(api.friendlyError(new api.ApiError(403, "invalid_current_password", "Server text.")), "Server text.");
  assert.match(api.friendlyError(new TypeError("boom")), /Something went wrong/);
});

// ---- scanning ---------------------------------------------------------------------------------
test("an .eml file is sent as base64 and decodes back to the exact original bytes", async () => {
  reset();
  const original = new Uint8Array([70, 114, 111, 109, 58, 32, 0xe9, 0x00, 0xff, 13, 10, 13, 10, 104, 105]);  // includes non-UTF-8 bytes
  const file = new File([original], "C:\\mail\\test.eml", { type: "message/rfc822" });
  await api.scanEmail({ file, signedIn: false });
  const body = JSON.parse(calls[0].body);
  assert.deepEqual(Object.keys(body).sort(), ["content", "encoding", "fileName", "inputMethod"]);
  assert.equal(body.inputMethod, "eml_upload"); assert.equal(body.encoding, "base64"); assert.equal(body.fileName, "C:\\mail\\test.eml");
  assert.deepEqual(new Uint8Array(Buffer.from(body.content, "base64")), original);
});

test("pasted text is sent as raw_text", async () => {
  reset();
  await api.scanEmail({ text: "Subject: Hi\n\nHello", signedIn: true });
  assert.deepEqual(JSON.parse(calls[0].body), { inputMethod: "raw_text", encoding: "text", content: "Subject: Hi\n\nHello" });
});

test("a file over 5 MB is refused BEFORE any request is made", async () => {
  reset();
  const big = new File([new Uint8Array(api.MAX_EML_BYTES + 1)], "big.eml");
  await assert.rejects(api.scanEmail({ file: big }), (e) => e.code === "file_too_large");
  assert.equal(calls.length, 0);
});

test("base64 handles a file larger than one encoding chunk", async () => {
  const bytes = Uint8Array.from({ length: 100_000 }, (_, i) => i % 251);
  assert.deepEqual(new Uint8Array(Buffer.from(await api.fileToBase64(new Blob([bytes])), "base64")), bytes);
});

// ---- history / dashboard / csv ----------------------------------------------------------------
test("history filters become a clean query string; empty values are omitted", async () => {
  reset();
  await api.listHistory({ q: "paypal & co", level: "phishing", range: "7", limit: 50, offset: 0 });
  const url = new URL(calls[0].url);
  assert.equal(url.pathname.endsWith("/scans"), true);
  assert.equal(url.searchParams.get("q"), "paypal & co");
  assert.equal(url.searchParams.get("offset"), "0");
  await api.listHistory({ q: "", level: undefined, range: "all" });
  const second = new URL(calls[1].url);
  assert.equal(second.searchParams.has("q"), false); assert.equal(second.searchParams.has("level"), false);
});

test("scan id is URL-encoded in detail and feedback paths", async () => {
  reset();
  await api.getScan("12/../x");
  assert.ok(calls[0].url.endsWith("/scans/12%2F..%2Fx"));
  await api.submitFeedback(5, { isPredictionCorrect: false, suggestedLabel: "Safe" });
  assert.deepEqual(JSON.parse(calls[1].body), { isPredictionCorrect: false, suggestedLabel: "Safe" });
});

test("CSV download sends the token and reads the filename from the server", async () => {
  reset(); api.setToken("tok");
  reply = () => ({ status: 200, text: "a,b", headers: { "content-disposition": 'attachment; filename="bantai-history.csv"' } });
  const { blob, fileName } = await api.fetchHistoryCsv({ level: "phishing" });
  assert.equal(fileName, "bantai-history.csv");
  assert.equal(await blob.text(), "a,b");
  assert.equal(lastHeaders().Authorization, "Bearer tok");
});

// ---- account ----------------------------------------------------------------------------------
test("profile updates send only the keys given; picture null is preserved", async () => {
  reset(); api.setToken("tok");
  await api.updateProfile({ profilePicture: null });
  assert.deepEqual(JSON.parse(calls[0].body), { profilePicture: null });
  assert.equal(calls[0].method, "PATCH");
});

test("preference names are translated between the UI and the API", () => {
  assert.deepEqual(api.preferencesToUi({ shapAdvancedMode: true, autoSaveScanLogs: false }),
                   { enableShapAdvancedMode: true, autoSaveScanLogs: false });
  assert.deepEqual(api.preferencesToApi({ enableShapAdvancedMode: false }), { shapAdvancedMode: false });
  assert.deepEqual(api.preferencesToApi({ autoSaveScanLogs: true, junk: 1 }), { autoSaveScanLogs: true });
});

test("purgeLegacyStorage removes the old plaintext-password record", () => {
  globalThis.localStorage.setItem("bantaiUser", JSON.stringify({ email: "a", password: "plaintext" }));
  globalThis.localStorage.setItem("bantaiAuthenticated", "true");
  globalThis.localStorage.setItem("bantaiSystemPreferences", "{}");
  globalThis.localStorage.setItem("somethingElse", "keep");
  api.purgeLegacyStorage();
  assert.equal(globalThis.localStorage.has("bantaiUser"), false);
  assert.equal(globalThis.localStorage.has("bantaiAuthenticated"), false);
  assert.equal(globalThis.localStorage.has("bantaiSystemPreferences"), false);
  assert.equal(globalThis.localStorage.has("somethingElse"), true);
});

test("health is a guest call", async () => {
  reset(); api.setToken("tok");
  await api.getHealth();
  assert.equal(lastHeaders().Authorization, undefined);
  assert.ok(calls[0].url.endsWith("/health"));
});
