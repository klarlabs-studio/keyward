// Keyward Passbook — popup logic
//
// Reads vault items from the local Passbook bridge over Chrome native messaging
// (via the background service worker → host `com.klarlabs.keyward.passbook`).
//
// Flow:
//   1. Resolve the active tab and derive its origin/host.
//   2. Ask the bridge for `list` scoped to that origin — titles/usernames only,
//      NO passwords.
//   3. On click, ask the bridge for `get` (secrets, fetched only at fill time),
//      then relay a `fill` message to the active tab's content script.
//
// Secrets from `get` are handed straight to the content script and are never
// logged (no console.log) and never stored.
//
// NO DEMO DATA: the popup never fabricates vault items. If the bridge is not
// installed/available it shows a "connect the bridge" banner and an empty list —
// what you see is always your real vault, or nothing.

"use strict";

const state = {
  hostname: "",
  origin: "",
  url: "",
  query: "",
  hasPasswordField: false,
  // "live" once the bridge answers, "disconnected" when it is unavailable.
  source: "disconnected",
  // Normalized items currently rendered.
  items: []
};

const els = {
  list: document.getElementById("vault-list"),
  search: document.getElementById("search"),
  empty: document.getElementById("empty-state"),
  siteLabel: document.getElementById("site-label"),
  banner: document.getElementById("site-banner"),
  bannerText: document.getElementById("site-banner-text"),
  bridgeBanner: document.getElementById("bridge-banner"),
  bridgeBannerText: document.getElementById("bridge-banner-text"),
  toast: document.getElementById("toast")
};

// ---- Helpers ---------------------------------------------------------------

function baseDomain(hostname) {
  if (!hostname) return "";
  const parts = hostname.replace(/^www\./, "").split(".");
  if (parts.length <= 2) return parts.join(".");
  return parts.slice(-2).join(".");
}

// Stable-ish colour from a string so live items (which carry no colour) still
// get a consistent, distinct badge tint.
function colorFor(seed) {
  let hash = 0;
  for (let i = 0; i < seed.length; i++) {
    hash = (hash * 31 + seed.charCodeAt(i)) & 0xffffff;
  }
  const hue = hash % 360;
  return `hsl(${hue}, 52%, 42%)`;
}

function initialsFor(title) {
  const words = String(title || "").trim().split(/\s+/).filter(Boolean);
  if (words.length === 0) return "?";
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
  return (words[0][0] + words[1][0]).toUpperCase();
}

function hostFromUrl(url) {
  try {
    return new URL(url).hostname;
  } catch (_) {
    return "";
  }
}

// Normalize a bridge `list` item ({id,title,username,url,hasTotp}) into the
// shape the renderer expects.
function normalizeLiveItem(raw) {
  return {
    id: raw.id,
    title: raw.title || raw.url || raw.id,
    username: raw.username || "",
    url: raw.url || "",
    hasTotp: !!raw.hasTotp,
    initials: initialsFor(raw.title || raw.url || raw.id),
    color: colorFor(String(raw.id || raw.title || raw.url || "")),
    source: "live",
    // The bridge already scoped `list` to this origin, so every live item is a
    // match for the current site.
    isMatch: true
  };
}

function sendMessage(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      resolve(response);
    });
  });
}

function getActiveTab() {
  return new Promise((resolve, reject) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      const tab = tabs && tabs[0];
      if (!tab) {
        reject(new Error("No active tab."));
        return;
      }
      resolve(tab);
    });
  });
}

let toastTimer = null;
function showToast(text, kind) {
  els.toast.textContent = text;
  els.toast.className = "toast " + (kind || "success");
  els.toast.hidden = false;
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    els.toast.hidden = true;
  }, 2600);
}

// ---- Rendering -------------------------------------------------------------

function filteredItems() {
  const query = state.query.trim().toLowerCase();
  let items = state.items.slice();

  if (query) {
    items = items.filter((item) => {
      const inTitle = (item.title || "").toLowerCase().includes(query);
      const inUser = (item.username || "").toLowerCase().includes(query);
      const inUrl = (item.url || "").toLowerCase().includes(query);
      const inDomains = Array.isArray(item.domains)
        ? item.domains.some((d) => d.includes(query))
        : false;
      return inTitle || inUser || inUrl || inDomains;
    });
  }

  // Site matches first, then alphabetical by title.
  items.sort((a, b) => {
    const am = a.isMatch ? 0 : 1;
    const bm = b.isMatch ? 0 : 1;
    if (am !== bm) return am - bm;
    return (a.title || "").localeCompare(b.title || "");
  });

  return items;
}

function fillIcon() {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", "16");
  svg.setAttribute("height", "16");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", "M5 12h11M12 8l4 4-4 4");
  path.setAttribute("fill", "none");
  path.setAttribute("stroke", "currentColor");
  path.setAttribute("stroke-width", "1.8");
  path.setAttribute("stroke-linecap", "round");
  path.setAttribute("stroke-linejoin", "round");
  svg.appendChild(path);
  return svg;
}

function renderItem(item) {
  const li = document.createElement("li");
  const isMatch = item.isMatch;

  const button = document.createElement("button");
  button.type = "button";
  button.className = "item" + (isMatch ? " match" : "");
  button.setAttribute("data-id", item.id);

  const badge = document.createElement("span");
  badge.className = "item-badge";
  badge.style.background = item.color;
  badge.textContent = item.initials;

  const body = document.createElement("div");
  body.className = "item-body";
  const title = document.createElement("span");
  title.className = "item-title";
  title.textContent = item.title;
  const user = document.createElement("span");
  user.className = "item-user";
  user.textContent = item.username;
  body.appendChild(title);
  body.appendChild(user);

  button.appendChild(badge);
  button.appendChild(body);

  if (isMatch) {
    const tag = document.createElement("span");
    tag.className = "item-tag";
    tag.textContent = "This site";
    button.appendChild(tag);
  }

  const fill = document.createElement("span");
  fill.className = "item-fill";
  fill.appendChild(fillIcon());
  button.appendChild(fill);

  button.addEventListener("click", () => onFill(item, button));

  li.appendChild(button);
  return li;
}

function render() {
  const items = filteredItems();
  els.list.textContent = "";

  if (items.length === 0) {
    if (state.source === "disconnected") {
      els.empty.textContent = "Connect the Passbook bridge to see your vault.";
    } else if (state.query.trim()) {
      els.empty.textContent = "No matching items.";
    } else {
      els.empty.textContent = "Your vault is empty — add items in Passbook.";
    }
    els.empty.hidden = false;
    return;
  }
  els.empty.hidden = true;

  const fragment = document.createDocumentFragment();
  for (const item of items) {
    fragment.appendChild(renderItem(item));
  }
  els.list.appendChild(fragment);
}

// ---- Actions ---------------------------------------------------------------

// Resolve the credentials to fill. Secrets are fetched from the bridge (`get`)
// only now, at fill time — never held in the popup ahead of a deliberate fill.
async function resolveCredentials(item) {
  const result = await sendMessage({ type: "native", payload: { type: "get", id: item.id } });
  if (!result || !result.ok || !result.response) {
    throw new Error((result && result.error) || "Bridge did not return the secret");
  }
  const secret = result.response;
  // NOTE: `secret` holds the password (and possibly a TOTP). Do NOT log it.
  return { username: secret.username, password: secret.password };
}

async function onFill(item, button) {
  button.disabled = true;
  try {
    const creds = await resolveCredentials(item);

    const result = await sendMessage({
      type: "relay",
      payload: { type: "fill", username: creds.username, password: creds.password }
    });

    if (!result || !result.ok) {
      showToast(result && result.error ? "Can’t fill this page" : "No response from page", "error");
      return;
    }

    const inner = result.response;
    if (inner && inner.ok) {
      const parts = [];
      if (inner.filledUsername) parts.push("username");
      if (inner.filledPassword) parts.push("password");
      showToast("Filled " + parts.join(" + ") + " for " + item.title, "success");
      // Close shortly so the user sees the filled form.
      setTimeout(() => window.close(), 700);
    } else {
      showToast("No login fields found on this page", "error");
    }
  } catch (err) {
    showToast("Cannot autofill here", "error");
  } finally {
    button.disabled = false;
  }
}

// ---- Init ------------------------------------------------------------------

function setSiteLabel() {
  if (state.hostname) {
    els.siteLabel.textContent = state.hostname;
  } else {
    els.siteLabel.textContent = "No active site";
  }

  const anyMatch = state.items.some((item) => item.isMatch);
  if (anyMatch) {
    els.banner.hidden = false;
    els.bannerText.textContent = "Vault has a login for " + (baseDomain(state.hostname) || state.hostname);
  } else if (state.hasPasswordField) {
    els.banner.hidden = false;
    els.bannerText.textContent = "Login form detected — pick an item to fill";
  } else {
    els.banner.hidden = true;
  }
}

function setBridgeBanner() {
  if (state.source === "disconnected") {
    els.bridgeBanner.hidden = false;
    els.bridgeBannerText.textContent =
      "Passbook bridge not connected — install the bridge and unlock Passbook to see your vault.";
  } else {
    els.bridgeBanner.hidden = true;
  }
}

// Ask the content script whether a login form is present (best-effort, for the
// "login form detected" hint). Uses the existing relay path.
async function probePage() {
  try {
    const result = await sendMessage({ type: "relay", payload: { type: "probe" } });
    if (result && result.ok && result.response) {
      state.hasPasswordField = !!result.response.hasPasswordField;
      if (!state.hostname && result.response.hostname) {
        state.hostname = result.response.hostname;
      }
    }
  } catch (_) {
    // Ignore — probe is only used for the hint banner.
  }
}

// Load vault items from the live bridge. If the bridge is unavailable there is
// NO fallback data — the list stays empty and the disconnected banner explains why.
async function loadItems() {
  try {
    const scope = state.origin || state.url;
    const result = await sendMessage({ type: "native", payload: { type: "list", origin: scope } });
    if (result && result.ok && result.response && Array.isArray(result.response.items)) {
      state.source = "live";
      state.items = result.response.items.map(normalizeLiveItem);
      return;
    }
    // Bridge responded but not with a usable list — treat as unavailable.
    throw new Error((result && result.error) || "Malformed list response");
  } catch (_) {
    // Bridge unavailable (not installed, host error, …). Show nothing — never fake data.
    state.source = "disconnected";
    state.items = [];
  }
}

async function init() {
  try {
    const tab = await getActiveTab();
    state.url = tab.url || "";
    state.hostname = hostFromUrl(state.url);
    try {
      state.origin = state.url ? new URL(state.url).origin : "";
    } catch (_) {
      state.origin = "";
    }
  } catch (_) {
    // No active tab / restricted page — leave defaults; the bridge still drives the list.
  }

  await loadItems();
  await probePage();

  setBridgeBanner();
  setSiteLabel();
  render();
}

els.search.addEventListener("input", (event) => {
  state.query = event.target.value;
  render();
});

init();
