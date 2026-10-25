"use strict";

(() => {
  const DIMENSION_ORDER = ["security", "identity", "privacy", "manipulation"];
  const DIMENSION_LABELS = {
    security: "Security & Fraud",
    identity: "Identity & Legitimacy",
    privacy: "Privacy & Data",
    manipulation: "Manipulation & Deception",
  };
  const LEVEL_LABELS = {
    low: "Low risk",
    medium: "Medium risk",
    high: "High risk",
    critical: "Critical risk",
    unknown: "Insufficient evidence",
  };
  const ACTION_LABELS = {
    browse: "Browsing",
    signup: "Account signup",
    purchase: "Purchase",
  };
  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

  const state = {
    assessment: null,
    filters: { dimension: "all", severity: "all", positiveOnly: false },
    loading: false,
    history: [],
    feedbackVerdict: "",
    statusTimer: null,
  };

  const dom = {
    form: document.getElementById("scan-form"),
    url: document.getElementById("url-input"),
    action: document.getElementById("action-select"),
    force: document.getElementById("force-refresh"),
    scanButton: document.getElementById("scan-button"),
    scanLabel: document.querySelector("#scan-button .button-label"),
    results: document.getElementById("results"),
    error: document.getElementById("scan-error"),
    apiStatus: document.getElementById("api-status"),
    apiStatusText: document.getElementById("api-status-text"),
    history: document.getElementById("history-list"),
    refreshSidebar: document.getElementById("refresh-sidebar"),
    statsNote: document.getElementById("stats-note"),
    footerVersion: document.getElementById("footer-version"),
    stats: {
      total: document.getElementById("stat-total"),
      last24h: document.getElementById("stat-24h"),
      average: document.getElementById("stat-avg"),
      feedback: document.getElementById("stat-feedback"),
      labels: document.getElementById("stat-labels"),
      malicious: document.getElementById("stat-malicious"),
    },
  };

  const initialEmptyMarkup = dom.results.innerHTML;

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function append(parent, ...children) {
    for (const child of children) {
      if (child !== null && child !== undefined) parent.append(child);
    }
    return parent;
  }

  function safeToken(value, allowed, fallback) {
    const lowered = String(value || "").toLowerCase();
    return allowed.includes(lowered) ? lowered : fallback;
  }

  function safeLevel(value) {
    return safeToken(value, ["low", "medium", "high", "critical", "unknown"], "unknown");
  }

  function safeSeverity(value) {
    return safeToken(value, SEVERITIES, "info");
  }

  function safeDimension(value) {
    return safeToken(value, DIMENSION_ORDER, "security");
  }

  function safeAction(value) {
    return safeToken(value, ["browse", "signup", "purchase"], "browse");
  }

  function levelLabel(value) {
    return LEVEL_LABELS[safeLevel(value)];
  }

  function dimensionLabel(value, fallback) {
    return DIMENSION_LABELS[value] || fallback || "Dimension";
  }

  function actionLabel(value) {
    return ACTION_LABELS[safeAction(value)];
  }

  function severityLabel(value) {
    return safeSeverity(value);
  }

  function scoreText(value) {
    return Number.isFinite(Number(value)) ? String(Math.round(Number(value))) : "—";
  }

  function percent(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) return "—";
    return `${Math.round(Math.max(0, Math.min(1, number)) * 100)}%`;
  }

  function clampScore(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) return 0;
    return Math.max(0, Math.min(100, number));
  }

  function formatTimestamp(value) {
    if (!value) return "Unknown time";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "Unknown time";
    try {
      return new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(date);
    } catch (error) {
      return date.toLocaleString();
    }
  }

  function relativeTime(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "unknown time";
    const seconds = Math.round((date.getTime() - Date.now()) / 1000);
    const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
    const units = [
      ["year", 31536000],
      ["month", 2592000],
      ["day", 86400],
      ["hour", 3600],
      ["minute", 60],
    ];
    for (const [unit, size] of units) {
      if (Math.abs(seconds) >= size) {
        return formatter.format(Math.round(seconds / size), unit);
      }
    }
    return formatter.format(seconds, "second");
  }

  function formatDuration(milliseconds) {
    const ms = Number(milliseconds);
    if (!Number.isFinite(ms) || ms <= 0) return "";
    if (ms < 1000) return `${Math.round(ms)} ms`;
    return `${(ms / 1000).toFixed(ms < 10000 ? 1 : 0)} s`;
  }

  function shortId(value) {
    return String(value || "").slice(0, 8);
  }

  function clearError() {
    dom.error.hidden = true;
    dom.error.textContent = "";
  }

  function showError(message) {
    dom.error.textContent = message;
    dom.error.hidden = false;
  }

  async function request(path, options) {
    let response;
    const { headers, ...rest } = options || {};
    try {
      response = await fetch(path, {
        cache: "no-store",
        ...rest,
        headers: { Accept: "application/json", ...(headers || {}) },
      });
    } catch (error) {
      throw new Error("Could not reach the local TrustLens engine. Is the server running?");
    }
    const type = response.headers.get("content-type") || "";
    let payload;
    if (type.includes("application/json")) {
      try {
        payload = await response.json();
      } catch (error) {
        payload = null;
      }
    } else {
      payload = await response.text();
    }
    if (!response.ok) {
      let detail = "";
      if (payload && typeof payload.detail === "string") {
        detail = payload.detail;
      } else if (payload && Array.isArray(payload.detail)) {
        detail = payload.detail.map((item) => item.msg || "").filter(Boolean).join("; ");
      } else if (typeof payload === "string" && payload.trim()) {
        detail = payload.trim().slice(0, 300);
      }
      throw new Error(detail || `Request failed with status ${response.status}`);
    }
    return payload;
  }

  function setStatus(online, label) {
    dom.apiStatus.classList.toggle("online", Boolean(online));
    dom.apiStatus.classList.toggle("offline", !online);
    dom.apiStatusText.textContent = label || (online ? "Local engine online" : "Local engine offline");
  }

  async function checkHealth() {
    try {
      const health = await request("/health");
      setStatus(true, "Local engine online");
      dom.apiStatus.title = `TrustLens engine ${health.version} is running on this machine`;
      dom.footerVersion.textContent = `v${health.version}`;
    } catch (error) {
      setStatus(false, "Local engine offline");
      dom.apiStatus.title = "The local TrustLens engine is not reachable";
    }
  }

  function normalizeInput(value) {
    let raw = String(value || "").trim();
    if (!raw) throw new Error("Enter a website address to scan.");
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw)) raw = `https://${raw}`;
    let parsed;
    try {
      parsed = new URL(raw);
    } catch (error) {
      throw new Error("That does not look like a valid web address.");
    }
    if (!["http:", "https:"].includes(parsed.protocol)) {
      throw new Error("Only http:// and https:// addresses can be assessed.");
    }
    const hostname = parsed.hostname.toLowerCase();
    if (!hostname) throw new Error("The address has no hostname.");
    if (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "[::1]" ||
      hostname.endsWith(".local") ||
      hostname.endsWith(".internal")
    ) {
      throw new Error("Local and private addresses are not assessed by TrustLens.");
    }
    if (!hostname.includes(".") && !hostname.startsWith("[")) {
      throw new Error("Enter a full domain name, for example example.com.");
    }
    return parsed.href;
  }

  function setLoading(loading) {
    state.loading = loading;
    dom.scanButton.disabled = loading;
    dom.scanButton.classList.toggle("loading", loading);
    dom.scanLabel.textContent = loading ? "Scanning…" : "Scan site";
    dom.results.setAttribute("aria-busy", loading ? "true" : "false");
  }

  function renderScanning(url) {
    const wrapper = el("div", "scanning");
    const text = el("p", "scanning-text");
    let hostname = url;
    try {
      hostname = new URL(url).hostname;
    } catch (error) {
      /* keep raw */
    }
    text.textContent = `Collecting and scoring evidence for ${hostname}…`;
    wrapper.append(text);
    for (const className of ["tall", "w-90", "w-70", "w-45"]) {
      wrapper.append(el("div", `scanning-bar ${className}`));
    }
    dom.results.replaceChildren(wrapper);
  }

  function renderEmpty() {
    dom.results.innerHTML = initialEmptyMarkup;
  }

  function performScan(options) {
    const target = options || {};
    if (state.loading) return;
    clearError();
    let url;
    try {
      url = normalizeInput(target.url !== undefined ? target.url : dom.url.value);
    } catch (error) {
      showError(error.message);
      dom.url.focus();
      return;
    }
    const action = safeAction(target.action !== undefined ? target.action : dom.action.value);
    const force = Boolean(target.force);
    dom.url.value = url;
    dom.action.value = action;
    dom.force.checked = force;
    try {
      localStorage.setItem("trustlens.action", action);
    } catch (error) {
      /* storage can be unavailable */
    }
    setLoading(true);
    renderScanning(url);
    request("/v1/assess", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, action, force_refresh: force }),
    })
      .then((data) => {
        clearError();
        renderAssessment(data);
        document.title = `${data.domain} — TrustLens`;
        refreshSidebar();
      })
      .catch((error) => {
        if (state.assessment) {
          renderAssessment(state.assessment);
        } else {
          renderEmpty();
        }
        showError(error.message);
      })
      .finally(() => {
        setLoading(false);
      });
  }

  function buildToolbar(data) {
    const toolbar = el("div", "assessment-toolbar");
    const left = el("div", "toolbar-left");
    left.append(el("span", "audit-id", `Assessment ${shortId(data.id)}`));
    if (data.cached) left.append(el("span", "chip chip-cached", "Cached"));
    const right = el("div", "toolbar-right");

    const rescan = el("button", "secondary-button", "Scan again");
    rescan.type = "button";
    rescan.addEventListener("click", () => {
      performScan({ url: data.final_url || data.url, action: data.action, force: true });
    });

    const exportButton = el("button", "secondary-button", "Export JSON");
    exportButton.type = "button";
    exportButton.addEventListener("click", () => exportAssessment(data));

    append(right, rescan, exportButton);
    append(toolbar, left, right);
    return toolbar;
  }

  function buildVerdict(data) {
    const level = safeLevel(data.overall_level);
    const card = el("article", "card verdict-card");

    const head = el("div", "assessment-head");
    const titleBlock = el("div");
    const siteTitle = el("div", "site-title");
    siteTitle.append(el("h2", "", data.domain || "Unknown site"));
    if (data.cached) siteTitle.append(el("span", "chip chip-cached", "Cached"));
    const meta = el("div", "meta-line");
    meta.append(el("span", "meta-item", data.final_url || data.url || ""));
    const separator = () => el("span", "meta-sep", "·");
    meta.append(separator(), el("span", "meta-item", actionLabel(data.action)));
    meta.append(separator(), el("span", "meta-item", formatTimestamp(data.created_at)));
    const duration = formatDuration(data.meta && data.meta.duration_ms);
    if (duration) meta.append(separator(), el("span", "meta-item", `Completed in ${duration}`));
    append(titleBlock, siteTitle, meta);
    append(head, titleBlock);

    const main = el("div", "verdict-main");
    const ring = el("div", "score-ring");
    ring.dataset.level = level;
    ring.style.setProperty("--score-angle", `${clampScore(data.overall_risk) * 3.6}deg`);
    const ringInner = el("div", "score-ring-inner");
    ringInner.append(el("span", "score-number", level === "unknown" ? "?" : scoreText(data.overall_risk)));
    ringInner.append(el("span", "score-denom", level === "unknown" ? "abstained" : "/ 100 risk"));
    ring.append(ringInner);

    const copy = el("div", "verdict-copy");
    copy.append(el("span", `level-badge level-${level}`, levelLabel(level)));
    copy.append(el("h3", "headline", data.headline || "Assessment complete"));
    copy.append(el("p", "recommendation", data.recommendation || ""));

    const confidence = el("div", "confidence-row");
    confidence.append(el("span", "confidence-label", "Confidence"));
    const meter = el("div", "meter");
    const fill = el("div", `meter-fill level-${level}`);
    fill.style.width = `${level === "unknown" ? 0 : Math.round((Number(data.confidence) || 0) * 100)}%`;
    meter.append(fill);
    confidence.append(meter, el("span", "confidence-value", percent(data.confidence)));
    copy.append(confidence);

    const chips = el("div", "badge-row");
    chips.append(el("span", "chip", actionLabel(data.action)));
    if (data.calibrated_probability !== null && data.calibrated_probability !== undefined) {
      const probability = Number(data.calibrated_probability);
      if (Number.isFinite(probability)) {
        chips.append(
          el("span", "chip", `${percent(probability)} calibrated negative-label probability`)
        );
      }
    }
    const floors = (data.meta && Array.isArray(data.meta.floors)) ? data.meta.floors : [];
    if (floors.length) {
      const floorChip = el("span", "chip", "Reputation floor applied");
      floorChip.title = floors.join(", ");
      chips.append(floorChip);
    }
    if (Array.isArray(data.evidence)) {
      chips.append(el("span", "chip", `${data.evidence.length} evidence item${data.evidence.length === 1 ? "" : "s"}`));
    }
    copy.append(chips);

    if (data.rationale) {
      const rationale = el("details", "rationale");
      rationale.append(el("summary", "", "Why this assessment?"));
      rationale.append(el("p", "", data.rationale));
      copy.append(rationale);
    }

    append(main, ring, copy);
    append(card, head, main);
    return card;
  }

  function buildDimensions(data) {
    const section = el("section", "card section");
    const head = el("div", "section-head");
    head.append(el("h3", "section-title", "Dimension profile"));
    head.append(el("span", "section-hint", "Scores are independent; action weighting is applied only to the overall result."));
    section.append(head);

    const grid = el("div", "dimension-grid");
    const dimensions = data.dimensions || {};
    const keys = [
      ...DIMENSION_ORDER.filter((key) => dimensions[key]),
      ...Object.keys(dimensions).filter((key) => !DIMENSION_ORDER.includes(key)),
    ];
    const evidence = Array.isArray(data.evidence) ? data.evidence : [];

    for (const key of keys) {
      const dimension = dimensions[key];
      const level = safeLevel(dimension.risk_level);
      const card = el("article", `dimension-card level-${level}`);
      const top = el("div", "dimension-top");
      top.append(el("span", "dimension-label", dimension.label || dimensionLabel(key)));
      const score = el("span", "dimension-score", dimension.abstained ? "—" : scoreText(dimension.risk_score));
      score.append(el("span", "", " /100"));
      top.append(score);
      card.append(top);

      const meter = el("div", "meter dimension-meter");
      const fill = el("div", `meter-fill level-${level}`);
      fill.style.width = `${dimension.abstained ? 0 : clampScore(dimension.risk_score)}%`;
      meter.append(fill);
      card.append(meter);
      card.append(el("p", "dimension-summary", dimension.summary || ""));

      const count = evidence.filter((item) => item.dimension === key).length;
      const foot = el("div", "dimension-foot");
      foot.append(el("span", "", `Confidence ${percent(dimension.confidence)}`));
      foot.append(el("span", "", `Coverage ${percent(dimension.coverage)}`));
      foot.append(el("span", "", `${count} evidence item${count === 1 ? "" : "s"}`));
      if (dimension.abstained) foot.append(el("span", "", "Abstained"));
      card.append(foot);
      grid.append(card);
    }
    section.append(grid);
    return section;
  }

  function buildEvidenceSection(data) {
    const section = el("section", "card section");
    const head = el("div", "section-head");
    head.append(el("h3", "section-title", "Evidence"));
    const hint = el("span", "section-hint", "");
    head.append(hint);
    section.append(head);

    const controls = el("div", "evidence-controls");
    const dimensionSelect = el("select", "select-control");
    dimensionSelect.setAttribute("aria-label", "Filter evidence by dimension");
    dimensionSelect.append(new Option("All dimensions", "all"));
    for (const key of DIMENSION_ORDER) {
      dimensionSelect.append(new Option(DIMENSION_LABELS[key], key));
    }

    const severitySelect = el("select", "select-control");
    severitySelect.setAttribute("aria-label", "Filter evidence by severity");
    severitySelect.append(new Option("All severities", "all"));
    for (const severity of SEVERITIES) {
      severitySelect.append(new Option(severity[0].toUpperCase() + severity.slice(1), severity));
    }

    const positiveLabel = el("label", "checkbox-control");
    const positiveInput = el("input");
    positiveInput.type = "checkbox";
    positiveLabel.append(positiveInput, el("span", "", "Positive signals only"));

    append(controls, dimensionSelect, severitySelect, positiveLabel);
    section.append(controls);

    const list = el("div", "evidence-list");
    section.append(list);

    const refresh = () => {
      state.filters.dimension = dimensionSelect.value;
      state.filters.severity = severitySelect.value;
      state.filters.positiveOnly = positiveInput.checked;
      const visible = renderEvidenceList(list, data);
      const total = Array.isArray(data.evidence) ? data.evidence.length : 0;
      hint.textContent = `${visible} of ${total} item${total === 1 ? "" : "s"} shown`;
    };
    dimensionSelect.addEventListener("change", refresh);
    severitySelect.addEventListener("change", refresh);
    positiveInput.addEventListener("change", refresh);
    refresh();
    return section;
  }

  function renderEvidenceList(container, data) {
    const evidence = Array.isArray(data.evidence) ? data.evidence.slice() : [];
    evidence.sort((a, b) => {
      const riskA = (Number(a.risk_points) || 0) * (Number(a.confidence) || 0);
      const riskB = (Number(b.risk_points) || 0) * (Number(b.confidence) || 0);
      if (riskB !== riskA) return riskB - riskA;
      const trustA = (Number(a.trust_points) || 0) * (Number(a.confidence) || 0);
      const trustB = (Number(b.trust_points) || 0) * (Number(b.confidence) || 0);
      if (trustB !== trustA) return trustB - trustA;
      const dimensionA = DIMENSION_ORDER.indexOf(a.dimension);
      const dimensionB = DIMENSION_ORDER.indexOf(b.dimension);
      return dimensionA - dimensionB;
    });

    const filtered = evidence.filter((item) => {
      if (state.filters.dimension !== "all" && item.dimension !== state.filters.dimension) return false;
      if (state.filters.severity !== "all" && item.severity !== state.filters.severity) return false;
      if (state.filters.positiveOnly && !(Number(item.trust_points) > 0)) return false;
      return true;
    });

    container.replaceChildren();
    if (!filtered.length) {
      container.append(el("div", "evidence-empty", "No evidence matches these filters."));
      return 0;
    }

    const fragment = document.createDocumentFragment();
    for (const item of filtered) {
      fragment.append(buildEvidenceCard(item));
    }
    container.append(fragment);
    return filtered.length;
  }

  function buildEvidenceCard(item) {
    const severity = safeSeverity(item.severity);
    const dimension = safeDimension(item.dimension);
    const card = el("article", `evidence-card severity-${severity}`);

    const head = el("div", "evidence-head");
    head.append(el("span", `severity-chip severity-${severity}`, severityLabel(severity)));
    head.append(el("span", "dimension-chip", DIMENSION_LABELS[dimension] || dimension));
    head.append(el("h4", "evidence-title", item.title || item.code || "Observation"));
    const risk = Number(item.risk_points) || 0;
    const trust = Number(item.trust_points) || 0;
    if (risk > 0) {
      head.append(el("span", "evidence-points risk-points", `+${scoreText(risk)} risk`));
    }
    if (trust > 0) {
      head.append(el("span", "evidence-points trust-points", `+${scoreText(trust)} trust`));
    }
    card.append(head);

    if (item.detail) card.append(el("p", "evidence-detail", item.detail));

    const meta = el("div", "evidence-meta");
    if (item.source) meta.append(el("span", "", `Source: ${item.source}`));
    meta.append(el("span", "", `Confidence ${percent(item.confidence)}`));
    if (item.observed_at) meta.append(el("span", "", formatTimestamp(item.observed_at)));
    const tags = Array.isArray(item.tags) ? item.tags : [];
    for (const tag of tags.slice(0, 7)) {
      meta.append(el("span", "tag", String(tag)));
    }
    card.append(meta);

    const provenance = item.provenance;
    if (provenance && typeof provenance === "object" && Object.keys(provenance).length) {
      const details = el("details", "provenance");
      details.append(el("summary", "", "Provenance"));
      const pre = el("pre", "");
      try {
        pre.textContent = JSON.stringify(provenance, null, 2);
      } catch (error) {
        pre.textContent = "Unavailable";
      }
      details.append(pre);
      card.append(details);
    }
    return card;
  }

  function buildMissingPanel(data) {
    const missing = Array.isArray(data.missing_evidence) ? data.missing_evidence : [];
    if (!missing.length) return null;
    const panel = el("section", "missing-panel");
    panel.append(el("h3", "", "Evidence gaps lower confidence"));
    panel.append(el("p", "", "The following checks could not be completed or did not apply:"));
    const list = el("ul", "missing-list");
    for (const message of missing) list.append(el("li", "", String(message)));
    panel.append(list);
    return panel;
  }

  function buildScreenshot(data) {
    const path = String(data.screenshot_url || "");
    if (!/^\/screenshots\/[A-Za-z0-9_.-]+$/.test(path)) return null;
    const section = el("section", "card section");
    const head = el("div", "section-head");
    head.append(el("h3", "section-title", "Rendered page screenshot"));
    head.append(el("span", "section-hint", "Captured by the local browser sandbox. OCR output is not stored."));
    section.append(head);
    const frame = el("div", "screenshot-frame");
    const image = el("img");
    image.src = path;
    image.alt = `Screenshot of ${data.domain || "the assessed page"}`;
    image.loading = "lazy";
    image.addEventListener("error", () => {
      image.remove();
      frame.append(el("div", "screenshot-fallback", "The screenshot could not be displayed."));
    });
    frame.append(image);
    section.append(frame);
    return section;
  }

  function buildAudit(data) {
    const meta = data.meta || {};
    const strip = el("div", "audit-details");
    if (meta.engine_version) {
      const item = el("span");
      item.append(el("strong", "", "Engine "), document.createTextNode(String(meta.engine_version)));
      strip.append(item);
    }
    if (meta.crawl_engine) {
      const item = el("span");
      item.append(el("strong", "", "Crawler "), document.createTextNode(String(meta.crawl_engine)));
      strip.append(item);
    }
    if (meta.http_status) {
      const item = el("span");
      item.append(el("strong", "", "HTTP "), document.createTextNode(String(meta.http_status)));
      strip.append(item);
    }
    const weights = meta.action_weights;
    if (weights && typeof weights === "object") {
      const parts = DIMENSION_ORDER
        .filter((key) => Number.isFinite(Number(weights[key])))
        .map((key) => `${DIMENSION_LABELS[key].split(" ")[0]} ${percent(weights[key])}`);
      if (parts.length) {
        const item = el("span");
        item.append(el("strong", "", "Action weights "), document.createTextNode(parts.join(" · ")));
        strip.append(item);
      }
    }
    if (data.coverage && typeof data.coverage === "object") {
      const average = Object.values(data.coverage).reduce((sum, value) => sum + (Number(value) || 0), 0) / Math.max(1, Object.keys(data.coverage).length);
      const item = el("span");
      item.append(el("strong", "", "Mean coverage "), document.createTextNode(percent(average)));
      strip.append(item);
    }
    const errors = meta.errors && typeof meta.errors === "object" ? Object.entries(meta.errors) : [];
    if (errors.length) {
      const item = el("span");
      item.append(el("strong", "", "Warnings "), document.createTextNode(String(errors.length)));
      item.title = errors.map(([name, message]) => `${name}: ${message}`).join("\n");
      strip.append(item);
    }
    return strip;
  }

  function buildFeedback(data) {
    const panel = el("section", "feedback-panel");
    panel.append(el("h3", "", "Was this assessment useful?"));
    panel.append(el("p", "", "Feedback is stored locally and will inform later calibration research. It does not change this score."));
    const actions = el("div", "feedback-actions");
    const buttons = [];
    for (const [value, label] of [["agree", "I agree"], ["disagree", "I disagree"], ["unsure", "Not sure"]]) {
      const button = el("button", "feedback-button", label);
      button.type = "button";
      button.dataset.verdict = value;
      button.addEventListener("click", () => {
        state.feedbackVerdict = value;
        for (const other of buttons) other.classList.toggle("selected", other === button);
      });
      buttons.push(button);
      actions.append(button);
    }
    panel.append(actions);

    const note = el("textarea", "feedback-note");
    note.maxLength = 1000;
    note.placeholder = "Optional note: what did TrustLens get right or wrong?";
    note.setAttribute("aria-label", "Optional feedback note");
    panel.append(note);

    const foot = el("div", "feedback-foot");
    const submit = el("button", "primary-button", "Submit feedback");
    submit.type = "button";
    const status = el("span", "feedback-status", "");
    foot.append(submit, status);
    panel.append(foot);

    submit.addEventListener("click", () => {
      if (!state.feedbackVerdict) {
        status.textContent = "Choose agree, disagree, or not sure first.";
        return;
      }
      submit.disabled = true;
      submit.classList.add("loading");
      status.textContent = "Submitting…";
      request("/v1/feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          assessment_id: data.id,
          verdict: state.feedbackVerdict,
          note: note.value.trim(),
        }),
      })
        .then(() => {
          status.textContent = "Thank you — feedback is stored locally.";
          note.disabled = true;
          for (const button of buttons) button.disabled = true;
          submit.classList.remove("loading");
          refreshSidebar();
        })
        .catch((error) => {
          submit.disabled = false;
          submit.classList.remove("loading");
          status.textContent = error.message;
        });
    });
    return panel;
  }

  function renderAssessment(data) {
    state.assessment = data;
    state.filters = { dimension: "all", severity: "all", positiveOnly: false };
    state.feedbackVerdict = "";
    const fragment = document.createDocumentFragment();
    fragment.append(buildToolbar(data));
    fragment.append(buildVerdict(data));
    fragment.append(buildDimensions(data));
    fragment.append(buildEvidenceSection(data));
    const missing = buildMissingPanel(data);
    if (missing) fragment.append(missing);
    const screenshot = buildScreenshot(data);
    if (screenshot) fragment.append(screenshot);
    fragment.append(buildAudit(data));
    fragment.append(buildFeedback(data));
    dom.results.replaceChildren(fragment);
    dom.results.setAttribute("aria-busy", "false");
    markHistoryActive(data.id);
  }

  function exportAssessment(data) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `trustlens-${data.domain || "assessment"}-${shortId(data.id)}.json`;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function renderStats(stats) {
    dom.stats.total.textContent = stats.total_assessments ?? 0;
    dom.stats.last24h.textContent = stats.assessments_24h ?? 0;
    dom.stats.average.textContent = Number.isFinite(Number(stats.average_risk)) ? Number(stats.average_risk).toFixed(1) : "—";
    dom.stats.feedback.textContent = stats.feedback_count ?? 0;
    dom.stats.labels.textContent = stats.labeled_domains ?? 0;
    dom.stats.malicious.textContent = stats.malicious_domains ?? 0;
    dom.statsNote.textContent = stats.average_duration_ms
      ? `Mean assessment time: ${formatDuration(stats.average_duration_ms)}. Statistics come from the local SQLite database.`
      : "Statistics come from the local SQLite database.";
  }

  function renderHistory(rows) {
    state.history = Array.isArray(rows) ? rows : [];
    dom.history.replaceChildren();
    if (!state.history.length) {
      dom.history.append(el("p", "panel-note", "No assessments recorded yet."));
      return;
    }
    for (const row of state.history) {
      const level = safeLevel(row.overall_level);
      const button = el("button", "history-item");
      button.type = "button";
      if (state.assessment && state.assessment.id === row.id) button.classList.add("active");
      button.dataset.id = row.id;
      button.append(el("span", `history-dot level-${level}`));
      const main = el("span", "history-main");
      main.append(el("span", "history-domain", row.domain || row.url || "Unknown"));
      main.append(el("span", "history-meta", `${actionLabel(row.action)} · ${relativeTime(row.created_at)}`));
      button.append(main);
      button.append(el("span", "history-score", level === "unknown" ? "?" : scoreText(row.overall_risk)));
      button.addEventListener("click", () => loadAssessment(row.id));
      dom.history.append(button);
    }
  }

  function markHistoryActive(id) {
    for (const item of dom.history.querySelectorAll(".history-item")) {
      item.classList.toggle("active", item.dataset.id === id);
    }
  }

  async function refreshSidebar() {
    try {
      const [stats, history] = await Promise.all([
        request("/v1/stats"),
        request("/v1/assessments?limit=12"),
      ]);
      renderStats(stats);
      renderHistory(history);
    } catch (error) {
      dom.statsNote.textContent = `Could not load local statistics: ${error.message}`;
    }
  }

  async function loadAssessment(id) {
    try {
      const data = await request(`/v1/assessments/${encodeURIComponent(id)}`);
      renderAssessment(data);
      document.title = `${data.domain} — TrustLens`;
      try {
        document.getElementById("results").scrollIntoView({ behavior: "smooth", block: "start" });
      } catch (error) {
        /* older browsers */
      }
    } catch (error) {
      showError(`Could not load that assessment: ${error.message}`);
    }
  }

  dom.form.addEventListener("submit", (event) => {
    event.preventDefault();
    performScan({ url: dom.url.value, action: dom.action.value, force: dom.force.checked });
  });

  dom.refreshSidebar.addEventListener("click", () => refreshSidebar());

  try {
    const savedAction = localStorage.getItem("trustlens.action");
    if (savedAction && ACTION_LABELS[savedAction]) dom.action.value = savedAction;
  } catch (error) {
    /* storage can be unavailable */
  }

  const params = new URLSearchParams(window.location.search);
  const prefill = params.get("url");
  if (prefill) dom.url.value = prefill;

  checkHealth();
  refreshSidebar();
  state.statusTimer = window.setInterval(checkHealth, 30000);
})();
