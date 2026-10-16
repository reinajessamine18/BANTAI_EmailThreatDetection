# BANTAI Frontend Wiring Guide

Connects `bantai-frontend` (React 19 + Vite) to `bantai-backend` (FastAPI, `/api/v1`). Every endpoint used here exists and is tested. **Line numbers refer to the frontend in your original zip.** If a teammate changed a file, search for the quoted text instead (each quote was verified unique in that version).

## 0. Fix first (security)

1. **SignUp stores the plaintext password in the browser** (`SignUp.jsx` line 30). Login and Settings compare passwords in the browser. Steps below remove all of it, and `purgeLegacyStorage()` erases the old record from browsers that already hold it.
2. **No route guard.** `/app/*` opens without signing in; `bantaiAuthenticated` is written but never read. Fixed by `RequireAuth`.
3. **No screen calls the API yet.** Every table, chart and toggle is a placeholder.

## 1. One-time setup

1. Copy from the zip into `bantai-frontend`: `src/api/client.js`, `src/api/client.test.mjs`, `src/components/RequireAuth.jsx`, `src/components/ScanDetail.jsx`, `.env.development`.
2. Run `node --test src/api/client.test.mjs`. Expect **22 pass**.
3. Start the backend (port 8000). Open the app at **`http://localhost:5173`, not `127.0.0.1`**: the backend allows only that origin (change with `BANTAI_CORS_ORIGINS`).
4. Restart `npm run dev` after adding `.env.development`.

## 2. Rules for every screen

- Import from `../api/client`. Never call `fetch` directly.
- Wrap each call like this, so the UI never shows a raw error:

```jsx
setBusy(true);
setError("");
try {
  await someApiCall();
} catch (err) {
  setError(friendlyError(err));
} finally {
  setBusy(false);
}
```

- Never start a POST (a scan) from `useEffect`: React StrictMode runs effects twice in development.
- The token lives in `localStorage` (`bantaiToken`) and is sent only by the client. Never read or write it elsewhere. Because browser scripts can access it, an XSS vulnerability could expose the token.
- The **guest** page must call `scanEmail({ ..., signedIn: false })` so a stored token is never attached.

## 3. File by file

### 3.1 `main.jsx`

Add above `createRoot(...)`:

```jsx
import { purgeLegacyStorage } from "./api/client";

purgeLegacyStorage();
```

### 3.2 `App.jsx`

Add `import RequireAuth from "./components/RequireAuth";` and `import ScanDetail from "./components/ScanDetail";`. Wrap the layout route (lines 64-69):

```jsx
<Route element={<RequireAuth />}>
  <Route element={<DashboardLayout />}>
    <Route path="/app/dashboard" element={<Dashboard />} />
    <Route path="/app/analyze" element={<AnalyzeEmail />} />
    <Route path="/app/threat-history" element={<ThreatHistory />} />
    <Route path="/app/threat-history/:scanId" element={<ScanDetail />} />
    <Route path="/app/settings" element={<Settings />} />
  </Route>
</Route>
```

### 3.3 `SignUp.jsx`

Add `import { friendlyError, register } from "../api/client";` and `const [busy, setBusy] = useState(false);`. **Replace lines 17-44** (all of `handleSubmit`) and add `disabled={busy}` to the submit button:

```jsx
const handleSubmit = async (event) => {
  event.preventDefault();
  setError("");

  if (password !== confirmPassword) {
    setError("Passwords do not match.");
    return;
  }
  if (password.length < 10) {
    setError("Password must be at least 10 characters.");
    return;
  }

  setBusy(true);
  try {
    await register({ fullName: name.trim(), email: email.trim(), password });
    navigate("/app/dashboard");
  } catch (err) {
    setError(friendlyError(err));
  } finally {
    setBusy(false);
  }
};
```

### 3.4 `Login.jsx`

Add `import { friendlyError, login } from "../api/client";` and `const [busy, setBusy] = useState(false);`. **Replace lines 17-79**; add `disabled={busy}` to the submit button:

```jsx
const handleSubmit = async (event) => {
  event.preventDefault();
  setError("");
  setBusy(true);
  try {
    await login({ email: email.trim(), password });
    navigate("/app/dashboard");
  } catch (err) {
    setError(friendlyError(err));
  } finally {
    setBusy(false);
  }
};
```

After 5 wrong passwords the server locks the account for 15 minutes and answers every attempt with the same message ("...or the account is temporarily locked"). Show it as is.

### 3.5 `ForgotPassword.jsx`

The backend has **no password reset**, so the current screen (which resets any account knowing only its email, in the browser) must not keep working. **Replace lines 17-83** with:

```jsx
const handleSubmit = (event) => {
  event.preventDefault();
  setError("Password reset is not available yet. Please contact your BANTAI administrator.");
};
```

Delete the now-unused `success` state and the `bantaiUser` code. Optionally hide the password fields and show only that message.

### 3.6 `DashboardLayout.jsx`

Add `import { getProfile, logout } from "../api/client";`. **Replace lines 14-26** and **lines 38-41**:

```jsx
const loadUser = async () => {
  try {
    setUser(await getProfile());
  } catch {
    setUser(null);
  }
};
```

```jsx
const handleLogout = async () => {
  await logout();
  navigate("/");
};
```

Keep the `bantaiUserUpdated` listener (Settings fires it after a save). Replace `user?.name` (line 66) with `user?.fullName`. `profilePicture` (line 68) keeps working: `getProfile()` returns it.

### 3.7 `GuestAnalyzeEmail.jsx`

Add `import { friendlyError, scanEmail } from "../api/client";` and these states next to the others:

```jsx
const [result, setResult] = useState(null);
const [scanning, setScanning] = useState(false);
const [scanError, setScanError] = useState("");
```

**Replace lines 47-67** (`handleScan`). The free-scan counter now increases only after a *successful* scan:

```jsx
const handleScan = async () => {
  if (limitReached || scanning) return;

  if (inputMethod === "upload" && !selectedFile) {
    alert("Select an .eml file before scanning.");
    return;
  }
  if (inputMethod === "paste" && !pasteContent.trim()) {
    alert("Paste email content before scanning.");
    return;
  }

  setScanning(true);
  setScanError("");
  try {
    const data = await scanEmail({
      file: inputMethod === "upload" ? selectedFile : undefined,
      text: inputMethod === "paste" ? pasteContent : undefined,
      signedIn: false,
    });
    const nextCount = scanCount + 1;
    sessionStorage.setItem(STORAGE_KEY, String(nextCount));
    setScanCount(nextCount);
    setResult(data);
    setScannedAt(data.scannedAt);
    setScanCompleted(true);
  } catch (err) {
    setScanError(friendlyError(err));
  } finally {
    setScanning(false);
  }
};
```

Change `result={null}` (line 80) to `result={result}`. Show `{scanError}` as a red message near the Scan button and add `disabled={scanning}` to it.

### 3.8 `AnalyzeEmail.jsx` (signed-in scanner)

Same changes with `signedIn: true`. Add the three states and the import, **replace lines 66-79**, change `result={null}` (line 84) to `result={result}`:

```jsx
const handleScan = async () => {
  if (scanning) return;

  if (inputMethod === "upload" && !selectedFile) {
    alert("Select an .eml file before scanning.");
    return;
  }
  if (inputMethod === "paste" && !pasteContent.trim()) {
    alert("Paste email content before scanning.");
    return;
  }

  setScanning(true);
  setScanError("");
  try {
    const data = await scanEmail({
      file: inputMethod === "upload" ? selectedFile : undefined,
      text: inputMethod === "paste" ? pasteContent : undefined,
      signedIn: true,
    });
    setResult(data);
    setScannedAt(data.scannedAt);
    setScanCompleted(true);
  } catch (err) {
    setScanError(friendlyError(err));
  } finally {
    setScanning(false);
  }
};
```

### 3.9 `AnalysisResults.jsx` (three text fixes)

It already reads `riskLevel`, `threatScore`, `explanations`, `fileName`, `scannedAt`, `inferenceTimeMs`, `sender`, `subject`, `emailBody`, so no data wiring is needed. Fix wording that would now be false:

| Find (exact text) | Replace with |
|---|---|
| `{result?.emailBody \|\| "Awaiting analysis service"}` (line 250; the same words also appear at line 240, leave that one) | `{result?.emailBody ?? (result?.emailBodyStored === false ? "The email text is never stored, so it is not shown for past scans." : "No email text available.")}` |
| `"Account scan history requires the backend to be connected."` | `{result?.saved ? "This scan was saved to your account history." : "This scan was not saved (Auto-save Scan Logs is off)."}` (drop the surrounding quotes, it is now an expression) |
| `Email content is not stored by this results screen.` | `The email body is never stored.` |

Optional: under the "SHAP attribution & insights" heading show `{result?.shap?.note}`, so users see the values are log-odds, not percentages. Word items have `kind: "word"`; rule-based findings have `kind: "indicator"` and no number.

### 3.10 `ThreatHistory.jsx` (+ the new `ScanDetail`)

Add imports `useEffect`, `useNavigate` (react-router-dom) and `fetchHistoryCsv, friendlyError, listHistory, saveBlob` from the client. **Replace lines 9-22** (`history` and `filteredHistory`). Filtering and search now happen on the server:

```jsx
const navigate = useNavigate();
const [items, setItems] = useState([]);
const [total, setTotal] = useState(0);
const [loading, setLoading] = useState(true);
const [error, setError] = useState("");
const [debouncedSearch, setDebouncedSearch] = useState("");

useEffect(() => {
  const timer = setTimeout(() => setDebouncedSearch(search), 300);
  return () => clearTimeout(timer);
}, [search]);

useEffect(() => {
  let cancelled = false;
  setLoading(true);
  setError("");
  listHistory({ q: debouncedSearch, level: threatFilter, range: dateFilter, limit: 50, offset: 0 })
    .then((data) => {
      if (!cancelled) {
        setItems(data.items);
        setTotal(data.total);
      }
    })
    .catch((err) => {
      if (!cancelled) setError(friendlyError(err));
    })
    .finally(() => {
      if (!cancelled) setLoading(false);
    });
  return () => {
    cancelled = true;
  };
}, [debouncedSearch, threatFilter, dateFilter]);

const handleExport = async () => {
  try {
    const { blob, fileName } = await fetchHistoryCsv({
      q: debouncedSearch,
      level: threatFilter,
      range: dateFilter,
    });
    saveBlob(blob, fileName);
  } catch (err) {
    setError(friendlyError(err));
  }
};
```

Then in the JSX: rename every `filteredHistory` to `items`; show `{total}` as the record count (it is the full match count, `items` holds at most 50); add `onClick={handleExport}` to the Export CSV button; show `{error}` and `loading`; and in each row:

| Cell | Use |
|---|---|
| Date & Time | `{new Date(item.date).toLocaleString()}` |
| Email / Subject | `item.subject`, `item.email` (unchanged) |
| Threat Level badge | `{item.classification}` ("Safe", "Suspicious", "Phishing") |
| Result | `item.result` (unchanged) |
| Action | `<button type="button" onClick={() => navigate(`/app/threat-history/${item.id}`)}>View</button>` |

If `total > items.length`, show "Showing the newest 50 of {total}. Narrow the filters to see others." (add a "Load more" with `offset` later).

### 3.11 `Dashboard.jsx`

Change line 9 to `import { useEffect, useState } from "react";` and add:

```jsx
import { Link } from "react-router-dom";
import { Doughnut, Line } from "react-chartjs-2";
import {
  ArcElement,
  CategoryScale,
  Chart as ChartJS,
  Legend,
  LineElement,
  LinearScale,
  PointElement,
  Tooltip,
} from "chart.js";
import { friendlyError, getDashboard } from "../api/client";

ChartJS.register(ArcElement, CategoryScale, Legend, LineElement, LinearScale, PointElement, Tooltip);
```

Inside `Dashboard()`, after `const [dateFilter, ...]` (line 43):

```jsx
const [data, setData] = useState(null);
const [error, setError] = useState("");

useEffect(() => {
  let cancelled = false;
  getDashboard(dateFilter)
    .then((d) => {
      if (!cancelled) {
        setData(d);
        setError("");
      }
    })
    .catch((err) => {
      if (!cancelled) setError(friendlyError(err));
    });
  return () => {
    cancelled = true;
  };
}, [dateFilter]);

const m = data?.metrics;
const values = {
  "Total Emails Scanned": m ? String(m.totalScanned) : "—",
  "Phishing Blocked": m ? String(m.phishingBlocked) : "—",
  "Safe Emails": m ? String(m.safeEmails) : "—",
  "Avg. Inference Time": m?.avgInferenceMs != null ? `${m.avgInferenceMs} ms` : "—",
};
const distribution = data?.riskDistribution;
const points = data?.trend?.points ?? [];
const lineData = {
  labels: points.map((p) => p.bucket),
  datasets: [
    { label: "Phishing", data: points.map((p) => p.phishing), borderColor: "#f87171" },
    { label: "Suspicious", data: points.map((p) => p.suspicious), borderColor: "#fbbf24" },
    { label: "Safe", data: points.map((p) => p.safe), borderColor: "#34d399" },
  ],
};
const doughnutData = {
  labels: ["Safe", "Phishing", "Suspicious"],
  datasets: [
    {
      data: distribution ? [distribution.safe, distribution.phishing, distribution.suspicious] : [],
      backgroundColor: ["#34d399", "#f87171", "#fbbf24"],
    },
  ],
};
```

Then in the JSX:

- Cards (lines 79-80): `{value}` becomes `{values[label]}`. The `detail` line can stay or show `"in this period"`.
- "Scanning Activity": replace the placeholder (`No scan data available`) with `<Line data={lineData} options={{ responsive: true, maintainAspectRatio: false }} />` inside a fixed-height box, shown when `points.length > 0`. Daily points for 7/30 days; monthly for "This Year"/"All Time".
- "Risk Distribution": replace the empty chart and "No data" with `<Doughnut data={doughnutData} />`. In the SAFE / PHISHING / SUSPECT grid, replace the `—` with `distribution?.safe`, `distribution?.phishing`, `distribution?.suspicious` (in that order).
- "Recent Scan Activity": make "View All" `<Link to="/app/threat-history">`, and render `data.recent` rows: Timestamp `item.date`, Subject `item.subject`, Sender `item.email`, Threat Score `item.threatScore`, Status `item.classification`. Keep the empty-state row when `data?.recent` is empty.
- Show `{error}` if set.

### 3.12 `Settings.jsx`

Add the client imports `changePassword, friendlyError, getHealth, getPreferences, getProfile, preferencesToApi, preferencesToUi, updatePreferences, updateProfile`.

**Preferences.** Delete `PREFERENCES_KEY` (line 4) and the whole `loadPreferences` function (lines 10-34). **Keep** `DEFAULT_PREFERENCES` (lines 5-8). Change line 53 to `useState(DEFAULT_PREFERENCES)`. Add states `emailPassword`, `profileError`. **Replace the load effect (lines 58-73):**

```jsx
useEffect(() => {
  let cancelled = false;
  Promise.all([getProfile(), getPreferences()])
    .then(([profile, prefs]) => {
      if (cancelled) return;
      setUser(profile);
      setName(profile.fullName || "");
      setEmail(profile.email || "");
      setProfilePicture(profile.profilePicture || "");
      setPreferences(preferencesToUi(prefs));
    })
    .catch((err) => {
      if (!cancelled) setPreferencesError(friendlyError(err));
    });
  return () => {
    cancelled = true;
  };
}, []);
```

**Picture** (lines 75-88). Add this at the top of `handleProfilePicture`, after `if (!file) return;`, and change `accept="image/*"` (line 285) to `accept="image/png,image/jpeg,image/webp,image/gif"`. The server refuses SVG and anything over about 300 KB:

```jsx
if (!["image/png", "image/jpeg", "image/webp", "image/gif"].includes(file.type) || file.size > 250 * 1024) {
  setProfileError("Use a PNG, JPEG, WebP or GIF under 250 KB.");
  return;
}
```

**Save profile** (lines 90-109). The email field needs the current password when it changed, so show an extra "Current password" input bound to `emailPassword` whenever `email.trim().toLowerCase() !== (user?.email || "").toLowerCase()`:

```jsx
const handleSaveProfile = async () => {
  setProfileError("");
  const changes = { fullName: name.trim(), profilePicture: profilePicture || null };
  if (email.trim().toLowerCase() !== (user?.email || "").toLowerCase()) {
    changes.email = email.trim();
    changes.currentPassword = emailPassword;
  }
  try {
    const updated = await updateProfile(changes);
    setUser(updated);
    setEmailPassword("");
    window.dispatchEvent(new Event("bantaiUserUpdated"));
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  } catch (err) {
    setProfileError(friendlyError(err));
  }
};
```

**Password** (lines 119-165). Delete the two checks that read `user.password` (lines 128-136) and make the function async:

```jsx
const handleChangePassword = async () => {
  setPasswordMessage("");
  setPasswordError("");

  if (!currentPassword || !newPassword || !confirmPassword) {
    setPasswordError("Please complete all password fields.");
    return;
  }
  if (newPassword !== confirmPassword) {
    setPasswordError("New passwords do not match.");
    return;
  }
  if (newPassword.length < 10) {
    setPasswordError("New password must be at least 10 characters.");
    return;
  }

  try {
    await changePassword({ currentPassword, newPassword });
    setCurrentPassword("");
    setNewPassword("");
    setConfirmPassword("");
    setPasswordMessage("Password changed. Other devices were signed out.");
    setTimeout(() => setPasswordMessage(""), 3000);
  } catch (err) {
    setPasswordError(friendlyError(err));
  }
};
```

**Toggles** (lines 167-185):

```jsx
const togglePreference = async (key) => {
  const next = { ...preferences, [key]: !preferences[key] };
  setPreferences(next);
  try {
    setPreferences(preferencesToUi(await updatePreferences(preferencesToApi({ [key]: next[key] }))));
    setPreferencesError("");
  } catch (err) {
    setPreferences(preferences);
    setPreferencesError(friendlyError(err));
  }
};
```

Replace the paragraph starting "These preferences are saved in this browser only" with: "Auto-save off means scans are still analyzed, but only an audit entry is kept (no history)."

**API & Databases** (the badges "Not Connected" line 447, "Backend Required" lines 463 and 479). Call `getHealth()` in an effect and show: FastAPI Backend "Connected" if the call succeeds; XGBoost Engine "Ready" when `ml_ready` is true, else "Unavailable"; storage "Connected" when the call succeeds (the server will not start without its database).

## 4. What the API returns, where it shows

| API field | Screen |
|---|---|
| `riskLevel` (`safe`/`suspicious`/`phishing`), `threatScore` | badge and gauge in AnalysisResults |
| `explanations[]`: `title`, `insight`, `value` (log-odds), `kind`, `direction` | "SHAP attribution & insights" |
| `links[]` (defanged), `auth` (spf/dkim/dmarc), `modelClassification` | not displayed yet; optional extras |
| `saved`, `scanId`, `scanCode` | footer text; link to detail |
| `items[]`: `id`, `date`, `subject`, `email`, `classification`, `result` | History and Dashboard tables |
| `metrics`, `riskDistribution`, `trend.points`, `recent` | Dashboard |

## 5. Errors to expect

| Code (HTTP) | Where | What happens |
|---|---|---|
| `invalid_credentials` (401) | Login | server message; includes "temporarily locked" |
| `email_already_registered` (409) | SignUp, email change | show server message |
| `invalid_token` / `not_authenticated` (401) | any signed-in call | token cleared, redirect to `/login` |
| `invalid_current_password` (403) | password / email change | same text covers "wrong" and "locked" |
| `password_required` (422) | email change | show the password input |
| `too_large`, `file_too_large`, `body_too_long` | scanners | "too large" messages |
| `unparseable`, `invalid_base64` (422) | scanners | file/paste could not be read |
| `ml_unavailable` (503) | scanners | "service unavailable, try again" |
| `storage_failed` (500) | scanners | scan not recorded, so no result is shown |
| `network_error` (0) | any | "Cannot reach the BANTAI server" |

## 6. Verify it works (in order)

1. `node --test src/api/client.test.mjs` passes 22.
2. Backend running; open `http://localhost:5173`. DevTools > Application: after the steps above there is **no** `bantaiUser` in Local Storage.
3. Sign up with a 10+ character password. You land on the Dashboard with zeros. Session Storage holds `bantaiToken`.
4. Visit `/app/dashboard` in a private window: you are sent to `/login`.
5. Analyze Email: upload an `.eml`. The Network tab shows `POST /api/v1/scans` 200 with an `Authorization` header. Score, badge and SHAP words appear.
6. Threat History shows that scan. View opens the detail (no email body, by design). Export CSV downloads a file that opens in Excel.
7. Dashboard: total 1, a chart point for today, the scan in Recent Scan Activity.
8. Settings: change the name (sidebar updates); toggle Auto-save off, scan again: results say not saved and History still shows 1; toggle it back on.
9. Change the password in one tab while signed in on another: the other tab is sent to `/login` on its next request.
10. Log out: `/app/dashboard` redirects to `/login`.
11. Open `/analyze` (signed in or not): scan works, the request has **no** `Authorization` header, History is unchanged.
12. Stop the backend: screens show "Cannot reach the BANTAI server", not a blank page.
13. Five wrong passwords: the sixth attempt (even the right password) fails with the "temporarily locked" message. This needs the lockout patch from the Step 7b zip.

## 7. If something fails

- **Every request is blocked in the console (CORS):** you opened `127.0.0.1` or another port. Use `http://localhost:5173`, or set `BANTAI_CORS_ORIGINS`.
- **401 on a guest scan:** a header like `Bearer null` is being sent. Only `client.js` may set it.
- **Calls go to the wrong URL:** `.env.development` was added without restarting `npm run dev`; the variable must start with `VITE_`.
- **Profile picture rejected:** over about 300 KB, or SVG. Resize or convert.
- **ESLint `react-hooks` complains about `setLoading(true)` in an effect:** harmless for the build; move that call into an event handler if you want it silent.

## 8. Decisions and known gaps

1. **Token storage.** Tokens are stored in `localStorage` so users stay signed in across tabs and browser restarts. To migrate a token left in `sessionStorage` by an earlier version, reload the tab that currently has that token; that tab copies it to `localStorage`. Any XSS bug could read the token; avoid unsafe HTML/script injection and keep token lifetimes appropriately limited.
2. **Auto-save default disagrees.** The Settings screen defaults it **off**; the database and the backend default it **on**. After wiring, the server value wins. Decide the product default, then change `UserSettings` creation in `auth.py` register and the `user_settings` column default.
3. **The guest "3 free scans" limit is cosmetic.** It lives in `sessionStorage`, so clearing storage resets it, and the backend has no limit. A real limit needs per-IP rate limiting on the server (not built).
4. **History search by scan ID is not supported.** The search box placeholder mentions "scan ID", but the API searches only subject and sender. Change the placeholder, or ask for the backend change.
5. **No password reset** until a way to verify the user exists (admin-issued code, or email).
6. **The SHAP advanced-mode toggle has no effect yet.** It is saved on the server; nothing reads it. For example, hide the numeric `value` when it is off.
7. **"Phishing Blocked"** counts scans scored Critical. Nothing is blocked; consider renaming the card "Phishing Detected".
8. **Feedback buttons do not exist yet.** `POST /scans/{id}/feedback` is ready: send `{ isPredictionCorrect, suggestedLabel?, explanationHelpful?, comment? }` via `submitFeedback(id, ...)`.
9. **History shows at most 50 rows** per request (server cap 200); add "Load more" using `offset`.
