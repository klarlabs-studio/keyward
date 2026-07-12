// Proctor Passbook — popup logic
//
// PROTOTYPE ONLY. These credentials are hardcoded demo data so the autofill flow
// can be demonstrated end to end. A real Passbook build would request a decrypted
// secret from the local vault bridge (native messaging / proctor-mcp) at fill time
// and would never ship passwords inside the extension.

"use strict";

const DEMO_VAULT = [
  {
    id: "github",
    title: "GitHub",
    username: "octo.dev@example.com",
    password: "demo-gh-P@ssw0rd!",
    domains: ["github.com", "gist.github.com"],
    color: "#24292f",
    initials: "GH"
  },
  {
    id: "netflix",
    title: "Netflix",
    username: "movie.night@example.com",
    password: "demo-nflx-Str3am#",
    domains: ["netflix.com"],
    color: "#e50914",
    initials: "NF"
  },
  {
    id: "chase",
    title: "Chase Bank",
    username: "j.saver",
    password: "demo-chase-B@nk2024",
    domains: ["chase.com", "secure.chase.com"],
    color: "#117aca",
    initials: "CH"
  },
  {
    id: "google",
    title: "Google",
    username: "you@gmail.com",
    password: "demo-goog-Acc0unt!",
    domains: ["google.com", "accounts.google.com", "mail.google.com"],
    color: "#4285f4",
    initials: "G"
  },
  {
    id: "amazon",
    title: "Amazon",
    username: "prime.shopper@example.com",
    password: "demo-amzn-Sh0p$",
    domains: ["amazon.com", "amazon.co.uk"],
    color: "#ff9900",
    initials: "AZ"
  }
];

const state = {
  hostname: "",
  origin: "",
  query: "",
  hasPasswordField: false
};

const els = {
  list: document.getElementById("vault-list"),
  search: document.getElementById("search"),
  empty: document.getElementById("empty-state"),
  siteLabel: document.getElementById("site-label"),
  banner: document.getElementById("site-banner"),
  bannerText: document.getElementById("site-banner-text"),
  toast: document.getElementById("toast")
};

// ---- Helpers ---------------------------------------------------------------

function baseDomain(hostname) {
  if (!hostname) return "";
  const parts = hostname.replace(/^www\./, "").split(".");
  if (parts.length <= 2) return parts.join(".");
  return parts.slice(-2).join(".");
}

function itemMatchesSite(item, hostname) {
  if (!hostname) return false;
  const host = hostname.replace(/^www\./, "");
  const base = baseDomain(hostname);
  return item.domains.some((domain) => host === domain || host.endsWith("." + domain) || base === domain);
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
  let items = DEMO_VAULT.slice();

  if (query) {
    items = items.filter(
      (item) =>
        item.title.toLowerCase().includes(query) ||
        item.username.toLowerCase().includes(query) ||
        item.domains.some((d) => d.includes(query))
    );
  }

  // Site matches first, then alphabetical.
  items.sort((a, b) => {
    const am = itemMatchesSite(a, state.hostname) ? 0 : 1;
    const bm = itemMatchesSite(b, state.hostname) ? 0 : 1;
    if (am !== bm) return am - bm;
    return a.title.localeCompare(b.title);
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
  const isMatch = itemMatchesSite(item, state.hostname);

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

async function onFill(item, button) {
  button.disabled = true;
  try {
    const result = await sendMessage({
      type: "relay",
      payload: { type: "fill", username: item.username, password: item.password }
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

  const anyMatch = DEMO_VAULT.some((item) => itemMatchesSite(item, state.hostname));
  if (anyMatch) {
    els.banner.hidden = false;
    els.bannerText.textContent = "Vault has a login for " + baseDomain(state.hostname);
  } else if (state.hasPasswordField) {
    els.banner.hidden = false;
    els.bannerText.textContent = "Login form detected — pick an item to fill";
  } else {
    els.banner.hidden = true;
  }
}

async function probeActiveTab() {
  try {
    const result = await sendMessage({ type: "relay", payload: { type: "probe" } });
    if (result && result.ok && result.response) {
      state.origin = result.response.origin || "";
      state.hostname = result.response.hostname || "";
      state.hasPasswordField = !!result.response.hasPasswordField;
    } else if (result && result.tab && result.tab.url) {
      // Fall back to the tab URL if the content script could not answer
      // (e.g. restricted page).
      try {
        state.hostname = new URL(result.tab.url).hostname;
      } catch (_) {
        /* ignore */
      }
    }
  } catch (_) {
    // Leave defaults; the popup still shows the full demo vault.
  }
  setSiteLabel();
  render();
}

els.search.addEventListener("input", (event) => {
  state.query = event.target.value;
  render();
});

render();
probeActiveTab();
