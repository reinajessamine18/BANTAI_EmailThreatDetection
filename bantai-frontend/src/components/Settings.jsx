import { useEffect, useRef, useState } from "react";
import eyeIcon from "../assets/eye-icon.png";

const PREFERENCES_KEY = "bantaiSystemPreferences";
const DEFAULT_PREFERENCES = {
  enableShapAdvancedMode: true,
  autoSaveScanLogs: false,
};

function loadPreferences() {
  try {
    const savedPreferences = JSON.parse(
      localStorage.getItem(PREFERENCES_KEY) || "{}"
    );
    const normalizedPreferences = {
      enableShapAdvancedMode:
        savedPreferences.enableShapAdvancedMode ??
        savedPreferences.showShapExplainability,
      autoSaveScanLogs:
        savedPreferences.autoSaveScanLogs ?? savedPreferences.saveThreatHistory,
    };

    return {
      ...DEFAULT_PREFERENCES,
      ...Object.fromEntries(
        Object.keys(DEFAULT_PREFERENCES)
          .filter((key) => typeof normalizedPreferences[key] === "boolean")
          .map((key) => [key, normalizedPreferences[key]])
      ),
    };
  } catch {
    return DEFAULT_PREFERENCES;
  }
}

function Settings() {
  const [activeSection, setActiveSection] = useState("profile");
  const [user, setUser] = useState(null);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [profilePicture, setProfilePicture] = useState("");
  const [saved, setSaved] = useState(false);

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordMessage, setPasswordMessage] = useState("");
  const [passwordError, setPasswordError] = useState("");

  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [preferences, setPreferences] = useState(loadPreferences);
  const [preferencesError, setPreferencesError] = useState("");

  const fileInputRef = useRef(null);

  useEffect(() => {
    const storedUser = localStorage.getItem("bantaiUser");

    if (storedUser) {
      try {
        const parsedUser = JSON.parse(storedUser);

        setUser(parsedUser);
        setName(parsedUser.name || "");
        setEmail(parsedUser.email || "");
        setProfilePicture(parsedUser.profilePicture || "");
      } catch {
        setUser(null);
      }
    }
  }, []);

  const handleProfilePicture = (event) => {
    const file = event.target.files?.[0];

    if (!file) return;

    const reader = new FileReader();

    reader.onload = () => {
      setProfilePicture(reader.result);
      setSaved(false);
    };

    reader.readAsDataURL(file);
  };

  const handleSaveProfile = () => {
    const updatedUser = {
      ...user,
      name: name.trim(),
      email: email.trim(),
      profilePicture,
    };

    localStorage.setItem("bantaiUser", JSON.stringify(updatedUser));

    setUser(updatedUser);

    window.dispatchEvent(new Event("bantaiUserUpdated"));

    setSaved(true);

    setTimeout(() => {
      setSaved(false);
    }, 2500);
  };

  const initials = name
    .trim()
    .split(" ")
    .filter(Boolean)
    .slice(0, 2)
    .map((word) => word.charAt(0).toUpperCase())
    .join("");

  const handleChangePassword = () => {
    setPasswordMessage("");
    setPasswordError("");

    if (!currentPassword || !newPassword || !confirmPassword) {
      setPasswordError("Please complete all password fields.");
      return;
    }

    if (!user?.password) {
      setPasswordError("Your account password could not be found.");
      return;
    }

    if (currentPassword !== user.password) {
      setPasswordError("Current password is incorrect.");
      return;
    }

    if (newPassword !== confirmPassword) {
      setPasswordError("New passwords do not match.");
      return;
    }

    const updatedUser = {
      ...user,
      password: newPassword,
    };

    localStorage.setItem("bantaiUser", JSON.stringify(updatedUser));

    setUser(updatedUser);

    setCurrentPassword("");
    setNewPassword("");
    setConfirmPassword("");

    setShowCurrentPassword(false);
    setShowNewPassword(false);
    setShowConfirmPassword(false);

    setPasswordMessage("Password changed successfully.");

    setTimeout(() => {
      setPasswordMessage("");
    }, 3000);
  };

  const togglePreference = (key) => {
    const updatedPreferences = {
      ...preferences,
      [key]: !preferences[key],
    };

    try {
      localStorage.setItem(
        PREFERENCES_KEY,
        JSON.stringify(updatedPreferences)
      );
      setPreferences(updatedPreferences);
      setPreferencesError("");
    } catch {
      setPreferencesError(
        "Could not save this preference in this browser. Please check browser storage settings."
      );
    }
  };

  const settingsNavigation = [
    { id: "profile", name: "Account Profile" },
    { id: "preferences", name: "System Preferences" },
    { id: "api", name: "API & Databases" },
    { id: "security", name: "Security" },
  ];

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-black tracking-tight text-white">
          System Settings
        </h1>

      </div>

      <div className="grid gap-10 lg:grid-cols-[220px_minmax(0,1fr)]">
        <aside className="h-fit">
          <nav className="space-y-1">
            {settingsNavigation.map((item) => {
              const isActive = activeSection === item.id;

              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setActiveSection(item.id)}
                  className={`w-full rounded-lg px-4 py-3 text-left text-sm font-semibold transition ${
                    isActive
                      ? "bg-lime-400/10 text-lime-400"
                      : "text-zinc-500 hover:bg-zinc-900 hover:text-white"
                  }`}
                >
                  {item.name}
                </button>
              );
            })}
          </nav>
        </aside>

        <div className="min-w-0 max-w-3xl">
          {activeSection === "profile" && (
            <div>
              <div className="border-b border-zinc-800 pb-6">
                <h2 className="text-xl font-bold text-white">
                  Account Profile
                </h2>

                <p className="mt-2 text-sm text-zinc-500">
                  Update your personal account information.
                </p>
              </div>

              <div className="space-y-8 pt-8">
                <div className="flex items-center gap-6">
                  <div className="relative">
                    {profilePicture ? (
                      <img
                        src={profilePicture}
                        alt="Profile"
                        className="h-24 w-24 rounded-full border border-zinc-700 object-cover"
                      />
                    ) : (
                      <div className="flex h-24 w-24 items-center justify-center rounded-full bg-lime-400 text-2xl font-black text-black">
                        {initials || "B"}
                      </div>
                    )}

                    <button
                      type="button"
                      onClick={() => fileInputRef.current?.click()}
                      className="absolute bottom-0 right-0 flex h-8 w-8 items-center justify-center rounded-full border-2 border-black bg-zinc-800 text-sm text-white transition hover:bg-lime-400 hover:text-black"
                      title="Change profile picture"
                    >
                      ✎
                    </button>
                  </div>

                  <div>
                    <h3 className="text-sm font-semibold text-white">
                      Profile Picture
                    </h3>

                    <p className="mt-1 text-xs leading-5 text-zinc-600">
                      Upload a JPG, PNG, or other supported image.
                    </p>

                    <button
                      type="button"
                      onClick={() => fileInputRef.current?.click()}
                      className="mt-3 text-xs font-semibold text-lime-400 transition hover:text-lime-300"
                    >
                      Change picture
                    </button>

                    <input
                      ref={fileInputRef}
                      type="file"
                      accept="image/*"
                      onChange={handleProfilePicture}
                      className="hidden"
                    />
                  </div>
                </div>

                <div>
                  <label className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-500">
                    Full Name
                  </label>

                  <input
                    type="text"
                    value={name}
                    onChange={(event) => {
                      setName(event.target.value);
                      setSaved(false);
                    }}
                    className="w-full rounded-lg border border-zinc-800 bg-black px-4 py-3 text-sm text-white outline-none transition placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400"
                  />
                </div>

                <div>
                  <label className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-500">
                    Email Address
                  </label>

                  <input
                    type="email"
                    value={email}
                    onChange={(event) => {
                      setEmail(event.target.value);
                      setSaved(false);
                    }}
                    className="w-full rounded-lg border border-zinc-800 bg-black px-4 py-3 text-sm text-white outline-none transition placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400"
                  />
                </div>

                <div className="flex items-center gap-4 border-t border-zinc-800 pt-6">
                  <button
                    type="button"
                    onClick={handleSaveProfile}
                    className="rounded-lg bg-lime-400 px-6 py-3 text-sm font-bold text-black transition hover:bg-lime-300 hover:shadow-[0_0_20px_rgba(190,255,0,0.2)]"
                  >
                    Save Changes
                  </button>

                  {saved && (
                    <span className="text-xs font-medium text-lime-400">
                      Changes saved.
                    </span>
                  )}
                </div>
              </div>
            </div>
          )}

          {activeSection === "preferences" && (
            <div>
              <div className="border-b border-zinc-800 pb-6">
                <h2 className="text-xl font-bold text-white">
                  Display Preferences
                </h2>

                <p className="mt-2 text-sm text-zinc-500">
                  Customize how analysis results and scan logs should be
                  handled when those features are available.
                </p>
              </div>

              <div className="divide-y divide-zinc-800">
                {[
                  {
                    key: "enableShapAdvancedMode",
                    title: "Enable SHAP Advanced Mode",
                    description:
                      "Show detailed explainability visualizations in threat analysis.",
                  },
                  {
                    key: "autoSaveScanLogs",
                    title: "Auto-save Scan Logs",
                    description:
                      "Automatically save scan results to your account's history when scan storage is available.",
                  },
                ].map(({ key, title, description }) => (
                  <div
                    key={key}
                    className="flex items-center justify-between gap-6 py-6"
                  >
                    <div>
                      <h3 className="text-sm font-semibold text-white">
                        {title}
                      </h3>
                      <p className="mt-1 max-w-xl text-sm leading-6 text-zinc-600">
                        {description}
                      </p>
                    </div>

                    <button
                      type="button"
                      role="switch"
                      aria-checked={preferences[key]}
                      aria-label={title}
                      onClick={() => togglePreference(key)}
                      className={`relative h-6 w-11 shrink-0 rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-lime-400 focus:ring-offset-2 focus:ring-offset-zinc-950 ${
                        preferences[key] ? "bg-lime-400" : "bg-zinc-800"
                      }`}
                    >
                      <span
                        className={`absolute top-1 h-4 w-4 rounded-full transition-all ${
                          preferences[key]
                            ? "right-1 bg-black"
                            : "left-1 bg-zinc-500"
                        }`}
                      />
                    </button>
                  </div>
                ))}
              </div>
              {preferencesError && (
                <p
                  role="alert"
                  className="mt-4 rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-400"
                >
                  {preferencesError}
                </p>
              )}
              <p className="mt-5 text-xs leading-5 text-zinc-600">
                These preferences are saved in this browser only. SHAP
                explainability and scan-history storage are not connected yet,
                so changing these options will not enable those features until
                their services are implemented.
              </p>
            </div>
          )}

          {activeSection === "api" && (
            <div>
              <div className="border-b border-zinc-800 pb-6">
                <h2 className="text-xl font-bold text-white">
                  API & Databases
                </h2>

                <p className="mt-2 text-sm text-zinc-500">
                  View BANTAI's backend services and database connections.
                </p>
              </div>

              <div className="space-y-4 pt-6">
                <div className="flex items-center justify-between border-b border-zinc-800 pb-5">
                  <div>
                    <h3 className="text-sm font-semibold text-white">
                      FastAPI Backend
                    </h3>

                    <p className="mt-1 text-xs text-zinc-600">
                      Threat analysis API
                    </p>
                  </div>

                  <span className="text-xs font-medium text-zinc-600">
                    Not Connected
                  </span>
                </div>

                <div className="flex items-center justify-between border-b border-zinc-800 pb-5">
                  <div>
                    <h3 className="text-sm font-semibold text-white">
                      XGBoost Engine
                    </h3>

                    <p className="mt-1 text-xs text-zinc-600">
                      Email threat classification
                    </p>
                  </div>

                  <span className="text-xs font-medium text-zinc-600">
                    Backend Required
                  </span>
                </div>

                <div className="flex items-center justify-between border-b border-zinc-800 pb-5">
                  <div>
                    <h3 className="text-sm font-semibold text-white">
                      Database
                    </h3>

                    <p className="mt-1 text-xs text-zinc-600">
                      Account and threat-history storage
                    </p>
                  </div>

                  <span className="text-xs font-medium text-zinc-600">
                    Backend Required
                  </span>
                </div>
              </div>
            </div>
          )}

          {activeSection === "security" && (
            <div>
              <div className="border-b border-zinc-800 pb-6">
                <h2 className="text-xl font-bold text-white">
                  Security
                </h2>

                <p className="mt-2 text-sm text-zinc-500">
                  Manage your account security and authentication.
                </p>
              </div>

              <div className="divide-y divide-zinc-800">
                <div className="py-6">
                  <h3 className="text-sm font-semibold text-white">
                    Password
                  </h3>

                  <p className="mt-1 text-sm text-zinc-600">
                    Change the password associated with your BANTAI account.
                  </p>

                  <div className="mt-6 space-y-5">
                    <div>
                      <label className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-500">
                        Current Password
                      </label>

                      <div className="relative">
                        <input
                          type={showCurrentPassword ? "text" : "password"}
                          value={currentPassword}
                          onChange={(event) => {
                            setCurrentPassword(event.target.value);
                            setPasswordError("");
                            setPasswordMessage("");
                          }}
                          placeholder="Enter your current password"
                          className="w-full rounded-lg border border-zinc-800 bg-black px-4 py-3 pr-12 text-sm text-white outline-none transition placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400"
                        />

                        <button
                          type="button"
                          onClick={() =>
                            setShowCurrentPassword(!showCurrentPassword)
                          }
                          className="absolute right-3 top-1/2 flex -translate-y-1/2 items-center justify-center"
                          aria-label={
                            showCurrentPassword
                              ? "Hide current password"
                              : "Show current password"
                          }
                        >
                          <img
                            src={eyeIcon}
                            alt=""
                            className={`h-5 w-5 object-contain ${
                              showCurrentPassword
                                ? "opacity-100"
                                : "opacity-60"
                            }`}
                          />
                        </button>
                      </div>
                    </div>

                    <div>
                      <label className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-500">
                        New Password
                      </label>

                      <div className="relative">
                        <input
                          type={showNewPassword ? "text" : "password"}
                          value={newPassword}
                          onChange={(event) => {
                            setNewPassword(event.target.value);
                            setPasswordError("");
                            setPasswordMessage("");
                          }}
                          placeholder="Enter your new password"
                          className="w-full rounded-lg border border-zinc-800 bg-black px-4 py-3 pr-12 text-sm text-white outline-none transition placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400"
                        />

                        <button
                          type="button"
                          onClick={() => setShowNewPassword(!showNewPassword)}
                          className="absolute right-3 top-1/2 flex -translate-y-1/2 items-center justify-center"
                          aria-label={
                            showNewPassword
                              ? "Hide new password"
                              : "Show new password"
                          }
                        >
                          <img
                            src={eyeIcon}
                            alt=""
                            className={`h-5 w-5 object-contain ${
                              showNewPassword
                                ? "opacity-100"
                                : "opacity-60"
                            }`}
                          />
                        </button>
                      </div>
                    </div>

                    <div>
                      <label className="mb-2 block text-xs font-bold uppercase tracking-wider text-zinc-500">
                        Confirm New Password
                      </label>

                      <div className="relative">
                        <input
                          type={showConfirmPassword ? "text" : "password"}
                          value={confirmPassword}
                          onChange={(event) => {
                            setConfirmPassword(event.target.value);
                            setPasswordError("");
                            setPasswordMessage("");
                          }}
                          placeholder="Confirm your new password"
                          className="w-full rounded-lg border border-zinc-800 bg-black px-4 py-3 pr-12 text-sm text-white outline-none transition placeholder:text-zinc-600 focus:border-lime-400 focus:ring-1 focus:ring-lime-400"
                        />

                        <button
                          type="button"
                          onClick={() =>
                            setShowConfirmPassword(!showConfirmPassword)
                          }
                          className="absolute right-3 top-1/2 flex -translate-y-1/2 items-center justify-center"
                          aria-label={
                            showConfirmPassword
                              ? "Hide confirmed password"
                              : "Show confirmed password"
                          }
                        >
                          <img
                            src={eyeIcon}
                            alt=""
                            className={`h-5 w-5 object-contain ${
                              showConfirmPassword
                                ? "opacity-100"
                                : "opacity-60"
                            }`}
                          />
                        </button>
                      </div>
                    </div>

                    {passwordError && (
                      <div className="rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-400">
                        {passwordError}
                      </div>
                    )}

                    {passwordMessage && (
                      <div className="rounded-lg border border-lime-400/20 bg-lime-400/10 px-4 py-3 text-sm text-lime-400">
                        {passwordMessage}
                      </div>
                    )}

                    <div className="pt-2">
                      <button
                        type="button"
                        onClick={handleChangePassword}
                        className="rounded-lg bg-lime-400 px-6 py-3 text-sm font-bold text-black transition hover:bg-lime-300 hover:shadow-[0_0_20px_rgba(190,255,0,0.2)]"
                      >
                        Change Password
                      </button>
                    </div>
                  </div>
                </div>

                <div className="py-6">
                  <h3 className="text-sm font-semibold text-white">
                    Active Session
                  </h3>

                  <p className="mt-1 text-sm text-zinc-600">
                    Your current BANTAI session is active on this device.
                  </p>

                  <div className="mt-4 flex items-center gap-2">
                    <span className="h-2 w-2 rounded-full bg-lime-400" />

                    <span className="text-xs font-medium text-lime-400">
                      Session Active
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default Settings;