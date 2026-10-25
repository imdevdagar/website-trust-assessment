"use strict";

const ACTION_LABELS = {
  browse: "Just browsing",
  signup: "Creating an account",
  purchase: "Making a purchase",
};

const LEVEL_LABELS = {
  low: "Low risk",
  medium: "Medium risk",
  high: "High risk",
  critical: "Critical risk",
  unknown: "Limited evidence",
};

const ICONS = {
  search:
    '<circle cx="10.5" cy="10.5" r="5.6" fill="none" stroke="currentColor" stroke-width="1.9"></circle>' +
    '<path d="M14.8 14.8 19.2 19.2" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"></path>',
  alert:
    '<path d="M12 3.8 21 19.4H3L12 3.8Z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"></path>' +
    '<path d="M12 9.4v4.3" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"></path>' +
    '<circle cx="12" cy="16.5" r="1" fill="currentColor"></circle>',
  block:
    '<circle cx="12" cy="12" r="8.2" fill="none" stroke="currentColor" stroke-width="1.8"></circle>' +
    '<path d="M6.3 17.7 17.7 6.3" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"></path>',
};

const dom = {
  localPill: document.getElementById("local-pill"),
  siteAvatar: document.getElementById("site-avatar"),
  siteDomain: document.getElementById("site-domain"),
  siteUrl: document.getElementById("site-url"),
  cacheChip: document.getElementById("cache-chip"),
  stateRegion: document.getElementById("state-region"),
  actionBlock: document.getElementById("action-block"),
  actionSelect: document.getElementById("action-select"),
  scanButton: document.getElementById("scan-button"),
  scanLabel: document.querySelector("#scan-button .button-label"),
  actionError: document.getElementById("action-error"),
  settings: document.getElementById("settings"),
  settingsHint: document.getElementById("settings-hint"),
  autoProtect: document.getElementById("auto-protect"),
  showOverlay: document.getElementById("show-overlay"),
  serverUrl: document.getElementById("server-url"),
  saveServer: document.getElementById("save-server"),
  settingsNote: document.getElementById("settings-note"),
  openDashboard: document.getElementById("open-dashboard"),
};

const state = {
  tabId: null,
  action: "browse",
  status: "loading",
  settings: null,
  result: null,
  cached: false,
  busy: false,
  scanning: false,
  pollTimer: null,
  pollDeadline: 0,
  requestSeq: 0,
  noteTimer: null,
};

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function safeAction(value) {
  return Object.prototype.hasOwnProperty.call(ACTION_LABELS, value) ? value : "browse";
}

function safeLevel(value) {
  return Object.prototype.hasOwnProperty.call(LEVEL_LABELS, value) ? value : "unknown";
}

function normalizeServer(raw) {
  const value = String(raw || "").trim();
  if (!value) throw new Error("Enter the local server address.");
  const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(value) ? value : `http://${value}`;
  let parsed;
  try {
    parsed = new URL(withScheme);
  } catch (error) {
    throw new Error("That is not a valid server address.");
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("The server address must use http:// or https://.");
  }
  if (!["127.0.0.1", "localhost"].includes(parsed.hostname)) {
    throw new Error("For privacy, Website Trust Assessment Guard only connects to localhost.");
  }
  return parsed.origin;
}

function sendRaw(message) {
  return new Promise((resolve, reject) => {
    try {
      chrome.runtime.sendMessage(message, (response) => {
        const error = chrome.runtime.lastError;
        if (error) {
          reject(new Error(error.message || "The guard service is unavailable."));
          return;
        }
        resolve(response);
      });
    } catch (error) {
      reject(new Error(error && error.message ? error.message : "The guard service is unavailable."));
    }
  });
}

function displayUrl(raw) {
  const value = String(raw || "");
  try {
    const url = new URL(value);
    const path = url.pathname === "/" ? "" : url.pathname;
    const query = url.search ? `${url.search.slice(0, 40)}${url.search.length > 40 ? "…" : ""}` : "";
    return `${url.hostname}${path}${query}`;
  } catch (error) {
    return value || "No address available";
  }
}

function relativeTime(value) {
  const stamp = Date.parse(String(value || ""));
  if (!Number.isFinite(stamp)) return "just now";
  const seconds = Math.max(0, Math.round((Date.now() - stamp) / 1000));
  if (seconds < 45) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hr ago`;
  return `${Math.floor(seconds / 86400)} d ago`;
}

function stateIcon(name, tone) {
  const span = el("span", `state-icon${tone ? ` ${tone}` : ""}`);
  span.setAttribute("aria-hidden", "true");
  span.innerHTML = `<svg viewBox="0 0 24 24" focusable="false">${ICONS[name]}</svg>`;
  return span;
}

function setStateContent(node) {
  dom.stateRegion.replaceChildren(node);
}

function renderSite(tab) {
  const info = tab || {};
  const domain = String(info.domain || "").trim();
  const rawUrl = String(info.url || "").trim();
  const label = domain || (rawUrl ? "Browser page" : "No page detected");
  const pageTitle = String(info.title || "").trim();
  const subtitle =
    pageTitle && pageTitle.toLowerCase() !== label.toLowerCase()
      ? pageTitle
      : rawUrl
        ? displayUrl(rawUrl)
        : "This tab cannot be assessed";
  dom.siteDomain.textContent = label;
  dom.siteDomain.title = label;
  dom.siteAvatar.textContent = (domain.replace(/^www\./, "").charAt(0) || "?").toUpperCase();
  dom.siteUrl.textContent = subtitle;
  dom.siteUrl.title = rawUrl || pageTitle;
  dom.cacheChip.hidden = !state.cached || !state.result ? true : false;
}

function renderIdle() {
  const card = el("div", "state-card");
  const copy = el("div", "state-copy");
  copy.append(
    el("h2", "", "Not assessed yet"),
    el(
      "p",
      "",
      "Run a local check before you share credentials, create an account, or make a payment."
    )
  );
  if (state.settings && state.settings.autoProtect) {
    copy.append(el("p", "state-note", "Auto-protect will also assess pages as they finish loading."));
  }
  card.append(stateIcon("search", "teal"), copy);
  setStateContent(card);
}

function renderScanning(title, message) {
  const card = el("div", "state-card scanning-card");
  const head = el("div", "scanning-head");
  const copy = el("div", "state-copy");
  copy.append(
    el("h2", "", title || "Assessing this page"),
    el(
      "p",
      "",
      message ||
        "Reading visible content, domain infrastructure, policy language, and pressure cues."
    )
  );
  head.append(el("span", "scan-spinner"), copy);
  const track = el("div", "progress-track");
  track.append(el("span"));
  track.setAttribute("aria-hidden", "true");
  card.append(head, track);
  setStateContent(card);
}

function renderUnsupported() {
  const card = el("div", "state-card");
  const copy = el("div", "state-copy");
  copy.append(
    el("h2", "", "This page is out of scope"),
    el(
      "p",
      "",
      "Browser pages, local files, extension URLs, and private network addresses are not sent for assessment."
    )
  );
  card.append(stateIcon("block"), copy);
  setStateContent(card);
}

function renderError(message) {
  const card = el("div", "state-card");
  const copy = el("div", "state-copy");
  copy.append(
    el("h2", "", "Assessment unavailable"),
    el("p", "", String(message || "The local guard could not complete the assessment."))
  );
  card.append(stateIcon("alert", "red"), copy);
  setStateContent(card);
}

function renderResult(result) {
  if (!result) {
    renderIdle();
    return;
  }
  const level = safeLevel(result.overall_level);
  const verdict = ["allow", "warn", "block"].includes(result.verdict) ? result.verdict : "warn";
  const risk = Math.max(0, Math.min(100, Math.round(Number(result.overall_risk) || 0)));
  const confidence = Math.max(0, Math.min(100, Math.round((Number(result.confidence) || 0) * 100)));

  const card = el("section", "result-card");
  card.dataset.verdict = verdict;

  const head = el("div", "result-head");
  const ring = el("div", "risk-ring");
  ring.dataset.level = level;
  ring.style.setProperty("--score", String(risk));
  ring.setAttribute("role", "img");
  ring.setAttribute("aria-label", `Risk score ${risk} out of 100`);
  const ringInner = el("div", "risk-ring-inner");
  ringInner.append(el("strong", "", String(risk)), el("span", "", "/100"));
  ring.append(ringInner);

  const summary = el("div", "result-summary");
  const tags = el("div", "result-tags");
  tags.append(el("span", `level-badge ${level}`, LEVEL_LABELS[level]));
  tags.append(el("span", "confidence", `${confidence}% confidence`));

  const headline = el("h2", "", String(result.headline || "Assessment complete"));
  headline.title = String(result.headline || "");
  const meta = el(
    "p",
    "result-meta",
    `${ACTION_LABELS[safeAction(state.action)]} · ${relativeTime(result.assessed_at)}`
  );
  summary.append(tags, headline, meta);
  head.append(ring, summary);

  const reasonsBlock = el("div", "reasons-block");
  reasonsBlock.append(el("p", "reasons-label", verdict === "allow" ? "Evidence reviewed" : "What we observed"));
  const list = el("ul", "reasons");
  const reasons = Array.isArray(result.reasons)
    ? result.reasons.filter((item) => typeof item === "string" && item.trim()).slice(0, 4)
    : [];
  if (reasons.length) {
    for (const reason of reasons) {
      list.append(el("li", "", reason));
    }
  } else {
    list.append(el("li", "", "No additional detail was recorded for this result."));
  }
  reasonsBlock.append(list);

  const advisory = el(
    "p",
    "advisory",
    "Advisory only. Automated signals can miss threats or flag legitimate sites; verify important decisions independently."
  );

  card.append(head, reasonsBlock, advisory);
  setStateContent(card);
}

function startPolling() {
  if (state.pollTimer) return;
  if (!state.pollDeadline) state.pollDeadline = Date.now() + 100000;
  state.pollTimer = window.setTimeout(pollStatus, 1200);
}

function stopPolling() {
  if (state.pollTimer) {
    window.clearTimeout(state.pollTimer);
    state.pollTimer = null;
  }
  state.pollDeadline = 0;
}

async function pollStatus() {
  state.pollTimer = null;
  if (!state.busy) return;
  if (Date.now() > state.pollDeadline) {
    state.busy = false;
    state.scanning = false;
    state.status = "error";
    renderError("The assessment is taking too long. Check the local engine and try again.");
    updateControls();
    return;
  }
  await refresh();
  if (state.busy) startPolling();
}

function updateControls() {
  const unsupported = state.status === "unsupported" || !state.tabId;
  const busy = state.busy || state.status === "scanning";

  dom.actionBlock.hidden = unsupported;
  dom.actionSelect.disabled = unsupported || busy;
  dom.actionSelect.value = state.action;

  dom.scanButton.disabled = unsupported || busy;
  dom.scanButton.classList.toggle("is-busy", busy && !unsupported);

  if (unsupported) {
    dom.scanLabel.textContent = "Unavailable";
  } else if (busy) {
    dom.scanLabel.textContent = "Assessing…";
  } else if (state.status === "ready") {
    dom.scanLabel.textContent = "Reassess this page";
  } else if (state.status === "error") {
    dom.scanLabel.textContent = "Try again";
  } else {
    dom.scanLabel.textContent = "Assess this page";
  }
}

function syncSettings() {
  const settings = state.settings;
  if (!settings) return;
  dom.autoProtect.checked = Boolean(settings.autoProtect);
  dom.showOverlay.checked = Boolean(settings.showOverlay);
  if (document.activeElement !== dom.serverUrl) {
    dom.serverUrl.value = settings.serverUrl;
  }
  dom.settingsHint.textContent = settings.autoProtect ? "Auto-protect on" : "Auto-protect off";
  dom.localPill.title = `Local engine: ${settings.serverUrl}`;
}

function applyResponse(response) {
  state.settings = response.settings || state.settings;
  if (response.tab) renderSite(response.tab);
  state.action = safeAction(response.action || state.action);
  state.cached = Boolean(response.cached);
  syncSettings();

  const status = ["ready", "scanning", "idle", "error", "unsupported"].includes(response.status)
    ? response.status
    : "error";
  state.status = status;
  state.result = response.result || null;

  if (status === "scanning" || (status === "idle" && state.scanning)) {
    state.busy = true;
    renderScanning();
    startPolling();
  } else {
    state.busy = false;
    state.scanning = false;
    stopPolling();
    if (status === "ready" && state.result) {
      renderResult(state.result);
    } else if (status === "unsupported") {
      renderUnsupported();
    } else if (status === "error") {
      renderError(response.error || "The local guard could not complete the assessment.");
    } else {
      renderIdle();
    }
  }

  dom.cacheChip.hidden = !(state.cached && Boolean(state.result));
  updateControls();
}

function showActionError(message) {
  dom.actionError.textContent = String(message || "");
  dom.actionError.hidden = !message;
}

async function refresh() {
  if (!state.tabId) return;
  const seq = ++state.requestSeq;
  try {
    const response = await sendRaw({
      type: "getStatus",
      tabId: state.tabId,
      action: state.action,
    });
    if (seq !== state.requestSeq) return;
    if (!response || typeof response !== "object") {
      throw new Error("The guard service returned no status.");
    }
    if (!response.status) {
      throw new Error(response.error || "The guard service returned no status.");
    }
    applyResponse(response);
  } catch (error) {
    if (seq !== state.requestSeq) return;
    stopPolling();
    state.busy = false;
    state.scanning = false;
    state.status = "error";
    renderError(error && error.message ? error.message : "The guard service is unavailable.");
    updateControls();
  }
}

async function handleScan() {
  if (!state.tabId || state.busy || state.status === "unsupported") return;
  showActionError("");
  state.scanning = true;
  state.busy = true;
  state.result = null;
  state.cached = false;
  state.status = "scanning";
  renderScanning();
  updateControls();
  startPolling();

  try {
    const response = await sendRaw({
      type: "scanTab",
      tabId: state.tabId,
      action: state.action,
    });
    if (!response) throw new Error("The guard service did not return a result.");
    if (response.pending) {
      return;
    }
    if (response.ok === false) {
      throw new Error(response.error || "The assessment failed.");
    }
    state.scanning = false;
    state.busy = false;
    stopPolling();
    await refresh();
    if (response.stale) {
      showActionError("The page changed while it was being assessed, so that result was discarded.");
    }
  } catch (error) {
    state.scanning = false;
    state.busy = false;
    stopPolling();
    state.status = "error";
    renderError(error && error.message ? error.message : "The assessment failed.");
    updateControls();
  }
}

function setSettingsNote(message, isError, clearAfter) {
  if (state.noteTimer) {
    window.clearTimeout(state.noteTimer);
    state.noteTimer = null;
  }
  dom.settingsNote.textContent = String(message || "");
  dom.settingsNote.classList.toggle("is-error", Boolean(isError));
  if (message && clearAfter) {
    state.noteTimer = window.setTimeout(() => {
      dom.settingsNote.textContent = "";
      dom.settingsNote.classList.remove("is-error");
      state.noteTimer = null;
    }, clearAfter);
  }
}

async function updateToggle(key, input) {
  const previous = state.settings ? state.settings[key] : !input.checked;
  input.disabled = true;
  try {
    const response = await sendRaw({ type: "saveSettings", settings: { [key]: input.checked } });
    if (!response || response.error) {
      throw new Error((response && response.error) || "Could not save the setting.");
    }
    state.settings = response.settings || state.settings;
    syncSettings();
    const label = key === "autoProtect" ? "Auto-protect" : "Warning overlay";
    setSettingsNote(`${label} ${input.checked ? "enabled" : "disabled"}.`, false, 2600);
  } catch (error) {
    input.checked = Boolean(previous);
    setSettingsNote(error.message, true);
  } finally {
    input.disabled = false;
  }
}

async function saveServer() {
  dom.saveServer.disabled = true;
  try {
    const serverUrl = normalizeServer(dom.serverUrl.value);
    const response = await sendRaw({ type: "saveSettings", settings: { serverUrl } });
    if (!response || response.error) {
      throw new Error((response && response.error) || "Could not save the server address.");
    }
    state.settings = response.settings || state.settings;
    syncSettings();
    dom.serverUrl.value = state.settings ? state.settings.serverUrl : serverUrl;
    setSettingsNote("Saved. Guard will use this local engine.", false, 3500);
  } catch (error) {
    setSettingsNote(error.message, true);
  } finally {
    dom.saveServer.disabled = false;
  }
}

function openDashboard() {
  const serverUrl = (state.settings && state.settings.serverUrl) || "http://127.0.0.1:8000";
  let target = `${serverUrl}/dashboard`;
  const pageUrl = state.tabId ? dom.siteUrl.title : "";
  if (/^https?:\/\//i.test(pageUrl)) {
    target += `?url=${encodeURIComponent(pageUrl)}`;
  }
  try {
    chrome.tabs.create({ url: target });
  } catch (error) {
    setSettingsNote("Could not open a new tab.", true);
  }
}

async function loadPreferredAction() {
  try {
    const stored = await chrome.storage.local.get("wtas_popup_action");
    return safeAction(stored.wtas_popup_action);
  } catch (error) {
    return "browse";
  }
}

async function findActiveTab() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    return tabs && tabs.length ? tabs[0] : null;
  } catch (error) {
    return null;
  }
}

async function init() {
  dom.scanButton.disabled = true;
  dom.actionSelect.disabled = true;
  renderScanning("Connecting to the local guard", "Reading the active tab and guard settings.");
  state.action = await loadPreferredAction();
  dom.actionSelect.value = state.action;

  const tab = await findActiveTab();
  if (!tab || typeof tab.id !== "number") {
    state.status = "unsupported";
    renderUnsupported();
    updateControls();
    return;
  }

  state.tabId = tab.id;
  renderSite({ url: tab.url || "", title: tab.title || "", domain: "" });
  await refresh();
}

dom.actionSelect.addEventListener("change", () => {
  if (state.busy) return;
  state.action = safeAction(dom.actionSelect.value);
  state.result = null;
  state.cached = false;
  state.status = "loading";
  state.busy = true;
  showActionError("");
  updateControls();
  try {
    chrome.storage.local.set({ wtas_popup_action: state.action });
  } catch (error) {
    /* preference persistence is optional */
  }
  renderScanning("Checking this page", "Looking for an existing assessment with the selected action.");
  refresh();
});

dom.scanButton.addEventListener("click", handleScan);

dom.autoProtect.addEventListener("change", () => {
  updateToggle("autoProtect", dom.autoProtect);
});

dom.showOverlay.addEventListener("change", () => {
  updateToggle("showOverlay", dom.showOverlay);
});

dom.saveServer.addEventListener("click", saveServer);

dom.serverUrl.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    saveServer();
  }
});

dom.openDashboard.addEventListener("click", openDashboard);

init();
