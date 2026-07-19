// Keyward Passbook — content script
// Runs in the page. Detects login fields and fills them on request from the popup
// (relayed through the background service worker).
//
// PROTOTYPE: this fills whatever credentials the popup sends. A production build
// would only ever receive a decrypted secret from the local Passbook bridge after
// an explicit user action, and would never keep secrets in the extension itself.

(function () {
  "use strict";

  // Guard against double registration: this file is declared as a content
  // script AND may be re-injected by the background worker via chrome.scripting.
  // Without this, two onMessage listeners would both try to sendResponse.
  if (window.__keywardPassbookLoaded) return;
  window.__keywardPassbookLoaded = true;

  // ---- Field detection -----------------------------------------------------

  const USERNAME_SELECTORS = [
    'input[autocomplete="username"]',
    'input[autocomplete="email"]',
    'input[type="email"]',
    'input[name*="user" i]',
    'input[name*="email" i]',
    'input[name*="login" i]',
    'input[id*="user" i]',
    'input[id*="email" i]',
    'input[id*="login" i]',
    'input[type="text"]',
    'input[type="tel"]',
    'input:not([type])'
  ];

  const PASSWORD_SELECTORS = [
    'input[type="password"]',
    'input[autocomplete="current-password"]'
  ];

  function isVisible(el) {
    if (!el) return false;
    if (el.disabled || el.readOnly) return false;
    const style = window.getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden" || style.opacity === "0") {
      return false;
    }
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }

  function firstVisible(selectors) {
    for (const selector of selectors) {
      const nodes = document.querySelectorAll(selector);
      for (const node of nodes) {
        if (isVisible(node)) return node;
      }
    }
    return null;
  }

  // Prefer a username field that sits in the same form as a password field.
  function findFields() {
    const passwordField = firstVisible(PASSWORD_SELECTORS);
    let usernameField = null;

    if (passwordField && passwordField.form) {
      for (const selector of USERNAME_SELECTORS) {
        const candidate = passwordField.form.querySelector(selector);
        if (candidate && isVisible(candidate) && candidate.type !== "password") {
          usernameField = candidate;
          break;
        }
      }
    }

    if (!usernameField) {
      usernameField = firstVisible(USERNAME_SELECTORS);
    }

    return { usernameField, passwordField };
  }

  // ---- Filling -------------------------------------------------------------

  // Set a value the way a real user would, so frameworks (React/Vue/etc.) notice.
  function setNativeValue(element, value) {
    const proto = Object.getPrototypeOf(element);
    const descriptor = Object.getOwnPropertyDescriptor(proto, "value");
    if (descriptor && descriptor.set) {
      descriptor.set.call(element, value);
    } else {
      element.value = value;
    }
  }

  function fillField(element, value) {
    if (!element || value == null) return false;
    element.focus();
    setNativeValue(element, value);
    element.dispatchEvent(new Event("keydown", { bubbles: true }));
    element.dispatchEvent(new Event("keyup", { bubbles: true }));
    element.dispatchEvent(new Event("input", { bubbles: true }));
    element.dispatchEvent(new Event("change", { bubbles: true }));
    element.blur();
    return true;
  }

  function handleFill(message) {
    const { usernameField, passwordField } = findFields();
    let filledUser = false;
    let filledPass = false;

    if (usernameField && typeof message.username === "string") {
      filledUser = fillField(usernameField, message.username);
    }
    if (passwordField && typeof message.password === "string") {
      filledPass = fillField(passwordField, message.password);
    }

    return {
      ok: filledUser || filledPass,
      filledUsername: filledUser,
      filledPassword: filledPass,
      origin: window.location.origin
    };
  }

  // ---- Messaging -----------------------------------------------------------

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (!message || typeof message.type !== "string") return;

    switch (message.type) {
      case "fill":
        sendResponse(handleFill(message));
        break;
      case "probe": {
        const { usernameField, passwordField } = findFields();
        sendResponse({
          origin: window.location.origin,
          hostname: window.location.hostname,
          hasUsernameField: !!usernameField,
          hasPasswordField: !!passwordField
        });
        break;
      }
      default:
        break;
    }
    // Responses are synchronous; no need to return true.
  });
})();
