// Proctor Passbook — background service worker (MV3)
// Two responsibilities:
//   1. Relay fill/probe messages between the popup and the active tab's content
//      script. The popup cannot reliably talk to a content script directly
//      across all page states, so it asks the worker, which resolves the active
//      tab and forwards.
//   2. Proxy vault queries (`list`/`get`) to the local native-messaging host
//      (`com.klarlabs.proctor.passbook`) so the popup can read real vault items
//      without embedding secrets in the extension.
//
// SECURITY: the native host only returns secrets for a `get` at fill time. This
// worker forwards a `get` response straight back to the popup and never logs it
// (no console.log of passwords/totp) and never persists it.

"use strict";

const NATIVE_HOST = "com.klarlabs.proctor.passbook";

// One-shot native-messaging request. Chrome spawns the host, delivers `msg`,
// reads one reply, then tears the host down. `chrome.runtime.lastError` is set
// when the host is not installed / not registered / crashed.
function sendNative(msg) {
  return new Promise((resolve, reject) => {
    try {
      chrome.runtime.sendNativeMessage(NATIVE_HOST, msg, (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message || "Native host unavailable"));
          return;
        }
        if (response == null) {
          reject(new Error("Empty response from native host"));
          return;
        }
        resolve(response);
      });
    } catch (err) {
      reject(new Error(err && err.message ? err.message : String(err)));
    }
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
      if (!tab || tab.id == null) {
        reject(new Error("No active tab."));
        return;
      }
      resolve(tab);
    });
  });
}

// Ensure the content script is present. On pages loaded before the extension
// was installed/reloaded, the declared content script may not be running yet,
// so we inject it on demand. Harmless if it is already there.
async function ensureContentScript(tabId) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ["content.js"]
    });
  } catch (err) {
    // Injection can fail on restricted pages (chrome://, Web Store). The caller
    // handles the downstream messaging error.
  }
}

function sendToTab(tabId, message) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      resolve(response);
    });
  });
}

async function relay(message) {
  const tab = await getActiveTab();
  await ensureContentScript(tab.id);
  const response = await sendToTab(tab.id, message);
  return { tab: { id: tab.id, url: tab.url }, response };
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || typeof message.type !== "string") return;

  if (message.type === "relay") {
    relay(message.payload)
      .then((result) => sendResponse({ ok: true, ...result }))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true; // keep the message channel open for the async response
  }

  // Vault query proxied to the native host. The popup asks; we call the host and
  // relay the reply verbatim. `list` carries no secrets; `get` carries secrets
  // only at fill time — neither is logged here.
  if (message.type === "native") {
    sendNative(message.payload)
      .then((response) => sendResponse({ ok: true, response }))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true; // keep the message channel open for the async response
  }

  return undefined;
});
