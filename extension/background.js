// Proctor Passbook — background service worker (MV3)
// Relays messages between the popup and the active tab's content script.
// The popup cannot reliably talk to a content script directly across all page
// states, so it asks the worker, which resolves the active tab and forwards.

"use strict";

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

  return undefined;
});
