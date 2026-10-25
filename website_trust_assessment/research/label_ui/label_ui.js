(() => {
  "use strict";

  const tokenMeta = document.querySelector('meta[name="annotation-token"]');
  const TOKEN = tokenMeta ? tokenMeta.content : "";
  const LABELS = ["benign", "suspicious", "malicious"];
  const CONFIDENCE_KEY = "wtas-labeling-confidence";

  const state = {
    meta: null,
    sites: [],
    index: 0,
    form: { label: "", confidence: 0.9, notes: "" },
    dirty: false,
    frozen: false,
    saving: false,
  };

  const els = {
    labeledCount: document.getElementById("labeled-count"),
    totalCount: document.getElementById("total-count"),
    progressBar: document.getElementById("progress-bar"),
    progressFill: document.getElementById("progress-fill"),
    metaRole: document.getElementById("meta-role"),
    metaRound: document.getElementById("meta-round"),
    metaSheet: document.getElementById("meta-sheet"),
    filterText: document.getElementById("filter-text"),
    filterStatus: document.getElementById("filter-status"),
    siteList: document.getElementById("site-list"),
    emptyList: document.getElementById("empty-list"),
    review: document.getElementById("review"),
    sitePosition: document.getElementById("site-position"),
    siteDomain: document.getElementById("site-domain"),
    siteUrl: document.getElementById("site-url"),
    siteAction: document.getElementById("site-action"),
    openSite: document.getElementById("open-site"),
    labelButtons: Array.from(document.querySelectorAll(".label-button")),
    confidence: document.getElementById("confidence"),
    confidenceValue: document.getElementById("confidence-value"),
    notes: document.getElementById("notes"),
    notesRequired: document.getElementById("notes-required"),
    notesCount: document.getElementById("notes-count"),
    save: document.getElementById("save"),
    prev: document.getElementById("prev"),
    saveState: document.getElementById("save-state"),
    snapshotBlock: document.getElementById("snapshot-block"),
    snapshotState: document.getElementById("snapshot-state"),
    snapshotMeta: document.getElementById("snapshot-meta"),
    snapshotImg: document.getElementById("snapshot-img"),
    snapshotZoom: document.getElementById("snapshot-zoom"),
    snapshotHint: document.getElementById("snapshot-hint"),
    metaSnapshots: document.getElementById("meta-snapshots"),
    filterNoSnapshot: document.getElementById("filter-no-snapshot"),
    frozenBanner: document.getElementById("frozen-banner"),
    errorBanner: document.getElementById("error-banner"),
    doneBanner: document.getElementById("done-banner"),
    helpToggle: document.getElementById("help-toggle"),
    helpDialog: document.getElementById("help-dialog"),
    helpClose: document.getElementById("help-close"),
  };

  function showError(message) {
    els.errorBanner.textContent = message;
    els.errorBanner.classList.remove("hidden");
  }

  function clearError() {
    els.errorBanner.classList.add("hidden");
  }

  function setSaveState(message, kind) {
    els.saveState.textContent = message || "";
    els.saveState.className = "save-state" + (kind ? " " + kind : "");
  }

  function currentSite() {
    return state.sites[state.index] || null;
  }

  function draftKey(site) {
    return `wtas-draft:${state.meta ? state.meta.sheet : "sheet"}:${site.sample_id}`;
  }

  function readDraft(site) {
    try {
      const raw = localStorage.getItem(draftKey(site));
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== "object") return null;
      return {
        label: LABELS.includes(parsed.label) ? parsed.label : "",
        confidence: Number.isFinite(Number(parsed.confidence))
          ? Math.min(1, Math.max(0, Number(parsed.confidence)))
          : null,
        notes: typeof parsed.notes === "string" ? parsed.notes.slice(0, 1000) : "",
      };
    } catch {
      return null;
    }
  }

  function writeDraft() {
    const site = currentSite();
    if (!site) return;
    const empty = !state.form.label && !state.form.notes.trim();
    try {
      if (empty) {
        localStorage.removeItem(draftKey(site));
      } else {
        localStorage.setItem(draftKey(site), JSON.stringify(state.form));
      }
    } catch {
      // Drafts are a convenience; storage failures must not block labeling.
    }
  }

  function clearDraft(site) {
    try {
      localStorage.removeItem(draftKey(site));
    } catch {
      // ignore
    }
  }

  function defaultConfidence() {
    try {
      const raw = localStorage.getItem(CONFIDENCE_KEY);
      if (raw !== null && raw !== "") {
        const stored = Number(raw);
        if (Number.isFinite(stored) && stored >= 0 && stored <= 1) return stored;
      }
    } catch {
      // ignore
    }
    return 0.9;
  }

  function rememberConfidence(value) {
    try {
      localStorage.setItem(CONFIDENCE_KEY, String(value));
    } catch {
      // ignore
    }
  }

  function progress() {
    const counts = { benign: 0, suspicious: 0, malicious: 0 };
    for (const site of state.sites) {
      if (LABELS.includes(site.label)) counts[site.label] += 1;
    }
    const labeled = counts.benign + counts.suspicious + counts.malicious;
    return { labeled, total: state.sites.length, counts, complete: state.sites.length > 0 && labeled === state.sites.length };
  }

  function renderProgress() {
    const p = progress();
    els.labeledCount.textContent = String(p.labeled);
    els.totalCount.textContent = String(p.total);
    const pct = p.total ? Math.round((p.labeled / p.total) * 100) : 0;
    els.progressFill.style.width = pct + "%";
    els.progressBar.setAttribute("aria-valuenow", String(pct));
    els.doneBanner.classList.toggle("hidden", !p.complete || state.frozen);
  }

  function renderMeta() {
    if (!state.meta) return;
    els.metaRole.textContent = state.meta.role ? `Annotator ${state.meta.role}` : "Annotator";
    els.metaRound.textContent = state.meta.round || "Round";
    els.metaSheet.textContent = state.meta.sheet || "";
    document.title = `Website Trust Assessment | ${state.meta.round || "annotation"} | annotator ${state.meta.role || ""}`;
    const snap = state.meta.snapshots;
    const hasCaptures = Boolean(snap && snap.sites && (snap.ok || snap.duplicate || snap.likely_blank));
    if (hasCaptures) {
      els.metaSnapshots.textContent =
        `${snap.usable_snapshots} of ${snap.sites} sites have a captured page` +
        (snap.suspect_snapshots ? ` · ${snap.suspect_snapshots} capture(s) look blank` : "");
      els.metaSnapshots.classList.remove("hidden");
      if (els.filterNoSnapshot && !els.filterNoSnapshot.parentNode) {
        els.filterStatus.appendChild(els.filterNoSnapshot);
      }
    } else {
      els.metaSnapshots.textContent = "";
      els.metaSnapshots.classList.add("hidden");
      if (els.filterNoSnapshot && els.filterStatus.value === "no-snapshot") {
        els.filterStatus.value = "all";
      }
      if (els.filterNoSnapshot) els.filterNoSnapshot.remove();
    }
    if (state.frozen) {
      const when = state.meta.frozen_at ? ` (${state.meta.frozen_at})` : "";
      els.frozenBanner.textContent =
        `This sheet is frozen${when}. Corrections must be recorded as a protocol amendment, not a silent edit.`;
      els.frozenBanner.classList.remove("hidden");
    }
  }

  const SNAPSHOT_TITLES = {
    ok: "Captured page",
    duplicate: "Capture shared with other sites",
    likely_blank: "Capture looks blank",
  };
  let loadedSnapshot = "";
  let failedSnapshot = "";

  function renderSnapshot(site) {
    const snap = site && site.snapshot ? site.snapshot : null;
    const params = new URLSearchParams({ sample_id: site ? site.sample_id : "", token: TOKEN });
    const src = `/api/snapshot?${params.toString()}`;
    const show = Boolean(snap && snap.available && SNAPSHOT_TITLES[snap.state]) && src !== failedSnapshot;
    if (!show) {
      els.snapshotBlock.classList.add("hidden");
      els.snapshotImg.removeAttribute("src");
      els.snapshotZoom.removeAttribute("href");
      loadedSnapshot = "";
      return;
    }
    if (loadedSnapshot !== src) {
      els.snapshotImg.classList.add("loading");
      els.snapshotImg.onload = () => els.snapshotImg.classList.remove("loading");
      els.snapshotImg.onerror = () => {
        els.snapshotImg.classList.remove("loading");
        failedSnapshot = src;
        renderSnapshot(currentSite());
      };
      els.snapshotImg.src = src;
      loadedSnapshot = src;
    }
    els.snapshotZoom.href = src;
    els.snapshotState.textContent = SNAPSHOT_TITLES[snap.state];
    els.snapshotState.dataset.state = snap.state;
    const kilo = snap.bytes ? Math.round(snap.bytes / 1024) : 0;
    els.snapshotMeta.textContent = kilo ? `PNG · about ${kilo} KB` : "";
    els.snapshotHint.textContent =
      snap.state === "ok"
        ? "This is the page the crawler recorded for this URL. Click it to view full size; open the live site if anything is unclear."
        : snap.state === "likely_blank"
          ? "A capture this small is almost always an empty or blocked render, not the page. Open the site live, or record a failed load in the notes."
          : `This capture is byte-identical to ${snap.identical_captures} others, so it is probably a shared error or parking page rather than the site itself. Open the live site before labelling.`;
    els.snapshotBlock.classList.remove("hidden");
  }

  function renderList() {
    const query = els.filterText.value.trim().toLowerCase();
    const status = els.filterStatus.value;
    const fragment = document.createDocumentFragment();
    let shown = 0;

    state.sites.forEach((site, index) => {
      const labeled = LABELS.includes(site.label);
      if (status === "unlabeled" && labeled) return;
      if (status === "labeled" && !labeled) return;
      if (status === "no-snapshot" && site.snapshot && site.snapshot.state === "ok") return;
      if (query && !(`${site.domain} ${site.url}`.toLowerCase().includes(query))) return;
      shown += 1;

      const li = document.createElement("li");
      const button = document.createElement("button");
      button.type = "button";
      button.className = "site-button";
      button.dataset.label = labeled ? site.label : "";
      button.setAttribute("aria-current", index === state.index ? "true" : "false");
      button.addEventListener("click", () => selectSite(index));

      const dot = document.createElement("span");
      dot.className = "dot";
      dot.dataset.label = labeled ? site.label : "";
      const domain = document.createElement("span");
      domain.className = "domain";
      domain.textContent = site.domain || site.url;
      const stateText = document.createElement("span");
      stateText.className = "status";
      stateText.textContent = labeled ? site.label : "unlabeled";

      button.append(dot, domain, stateText);
      li.append(button);
      fragment.append(li);
    });

    els.siteList.replaceChildren(fragment);
    els.emptyList.classList.toggle("hidden", shown > 0);
  }

  function setLabel(label) {
    if (state.frozen || !currentSite()) return;
    if (!LABELS.includes(label)) return;
    state.form.label = state.form.label === label ? "" : label;
    state.dirty = true;
    writeDraft();
    renderForm();
  }

  function renderForm() {
    const site = currentSite();
    if (!site) {
      els.siteDomain.textContent = "No site selected";
      els.siteUrl.textContent = "";
      els.sitePosition.textContent = "";
      els.siteAction.textContent = "";
      els.openSite.setAttribute("aria-disabled", "true");
      els.openSite.classList.add("is-disabled");
      els.save.disabled = true;
      els.prev.disabled = true;
      renderSnapshot(null);
      return;
    }

    els.sitePosition.textContent = `Site ${state.index + 1} of ${state.sites.length}`;
    els.siteDomain.textContent = site.domain || site.url;
    els.siteUrl.textContent = site.url;
    els.siteAction.textContent = site.action ? `Requested action: ${site.action}` : "";
    if (site.openable) {
      els.openSite.href = site.url;
      els.openSite.removeAttribute("aria-disabled");
      els.openSite.classList.remove("is-disabled");
      els.openSite.tabIndex = 0;
    } else {
      els.openSite.removeAttribute("href");
      els.openSite.setAttribute("aria-disabled", "true");
      els.openSite.classList.add("is-disabled");
      els.openSite.tabIndex = -1;
    }
    renderSnapshot(site);

    for (const button of els.labelButtons) {
      button.setAttribute("aria-pressed", button.dataset.label === state.form.label ? "true" : "false");
      button.disabled = state.frozen;
    }
    els.confidence.value = String(state.form.confidence);
    els.confidence.disabled = state.frozen;
    els.confidenceValue.textContent = Number(state.form.confidence).toFixed(2);
    els.notes.value = state.form.notes;
    els.notes.disabled = state.frozen;
    els.notesCount.textContent = `${state.form.notes.length} / 1000`;
    els.notes.classList.remove("invalid");
    els.notesRequired.classList.toggle("hidden", !["suspicious", "malicious"].includes(state.form.label));
    els.save.disabled = state.frozen || state.saving || !currentSite();
    els.prev.disabled = state.index <= 0;
  }

  function selectSite(index, options) {
    if (index < 0 || index >= state.sites.length) return;
    if (state.dirty) writeDraft();
    state.index = index;
    const site = currentSite();
    const draft = readDraft(site);
    if (draft) {
      state.form = {
        label: draft.label || site.label || "",
        confidence: draft.confidence === null ? (site.confidence ?? defaultConfidence()) : draft.confidence,
        notes: draft.notes || "",
      };
      state.dirty = true;
      setSaveState("Draft restored");
    } else {
      state.form = {
        label: site.label || "",
        confidence: site.confidence ?? defaultConfidence(),
        notes: site.notes || "",
      };
      state.dirty = false;
      setSaveState(site.label ? "Saved" : "");
    }
    renderList();
    renderForm();
    if (!options || !options.keepScroll) window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function nextUnlabeled(from) {
    for (let step = 1; step <= state.sites.length; step += 1) {
      const index = (from + step) % state.sites.length;
      if (!LABELS.includes(state.sites[index].label)) return index;
    }
    return -1;
  }

  function advance() {
    const next = nextUnlabeled(state.index);
    if (next !== -1) selectSite(next);
    renderList();
    renderForm();
  }

  async function api(path, options) {
    const response = await fetch(path, {
      ...options,
      headers: {
        "X-Annotation-Token": TOKEN,
        "Content-Type": "application/json",
        ...(options && options.headers ? options.headers : {}),
      },
    });
    let body = null;
    try {
      body = await response.json();
    } catch {
      body = null;
    }
    if (!response.ok) {
      const detail = body && body.detail ? body.detail : `request failed (${response.status})`;
      const error = new Error(detail);
      error.status = response.status;
      throw error;
    }
    return body;
  }

  async function save() {
    const site = currentSite();
    if (!site || state.frozen || state.saving) return;
    clearError();
    if (!state.form.label) {
      setSaveState("Choose a label first", "error");
      return;
    }
    if (["suspicious", "malicious"].includes(state.form.label) && !state.form.notes.trim()) {
      els.notes.classList.add("invalid");
      els.notes.focus();
      setSaveState("Notes are required for this label", "error");
      return;
    }

    state.saving = true;
    els.save.disabled = true;
    setSaveState("Saving…");
    try {
      const data = await api("/api/annotations", {
        method: "POST",
        body: JSON.stringify({
          sample_id: site.sample_id,
          label: state.form.label,
          confidence: Number(state.form.confidence),
          notes: state.form.notes,
        }),
      });
      state.sites[state.index] = data.site;
      clearDraft(site);
      state.dirty = false;
      rememberConfidence(Number(state.form.confidence));
      setSaveState("Saved", "success");
      renderProgress();
      renderList();
      renderForm();
      if (data.progress && data.progress.complete) {
        els.doneBanner.classList.remove("hidden");
      }
      advance();
      setSaveState("Saved", "success");
    } catch (error) {
      if (error.status === 409) {
        state.frozen = true;
        renderMeta();
        renderForm();
      }
      showError(error.message || "Could not save this label.");
      setSaveState("Not saved", "error");
    } finally {
      state.saving = false;
      if (!state.frozen) els.save.disabled = !currentSite();
    }
  }

  function openSite() {
    const site = currentSite();
    if (!site || !site.openable) return;
    window.open(site.url, "_blank", "noopener,noreferrer");
  }

  function bindEvents() {
    for (const button of els.labelButtons) {
      button.addEventListener("click", () => setLabel(button.dataset.label));
    }
    els.confidence.addEventListener("input", () => {
      state.form.confidence = Number(els.confidence.value);
      state.dirty = true;
      writeDraft();
      renderForm();
    });
    els.notes.addEventListener("input", () => {
      state.form.notes = els.notes.value.slice(0, 1000);
      state.dirty = true;
      writeDraft();
      els.notesCount.textContent = `${state.form.notes.length} / 1000`;
      els.notesRequired.classList.toggle("hidden", !["suspicious", "malicious"].includes(state.form.label));
      els.notes.classList.remove("invalid");
    });
    els.save.addEventListener("click", save);
    els.prev.addEventListener("click", () => selectSite(state.index - 1));
    els.filterText.addEventListener("input", renderList);
    els.filterStatus.addEventListener("change", renderList);
    els.openSite.addEventListener("click", (event) => {
      if (els.openSite.getAttribute("aria-disabled") === "true") event.preventDefault();
    });
    els.helpToggle.addEventListener("click", () => els.helpDialog.showModal());
    els.helpClose.addEventListener("click", () => els.helpDialog.close());

    document.addEventListener("keydown", (event) => {
      if (els.helpDialog.open) return;
      const key = event.key.toLowerCase();
      if (event.ctrlKey || event.metaKey) {
        if (event.key === "Enter") {
          event.preventDefault();
          save();
        }
        return;
      }
      const target = event.target;
      if (target instanceof HTMLElement && target.matches("input, textarea, select")) return;
      if (event.key === "?") {
        event.preventDefault();
        els.helpDialog.showModal();
      } else if (key === "1") {
        event.preventDefault();
        setLabel("benign");
      } else if (key === "2") {
        event.preventDefault();
        setLabel("suspicious");
      } else if (key === "3") {
        event.preventDefault();
        setLabel("malicious");
      } else if (key === "o") {
        event.preventDefault();
        openSite();
      } else if (key === "j" || event.key === "ArrowDown") {
        event.preventDefault();
        selectSite(state.index + 1);
      } else if (key === "k" || event.key === "ArrowUp") {
        event.preventDefault();
        selectSite(state.index - 1);
      }
    });

    window.addEventListener("beforeunload", (event) => {
      if (!state.dirty) return;
      event.preventDefault();
      event.returnValue = "";
    });
  }

  async function load() {
    if (!TOKEN || TOKEN.includes("__ANNOTATION_TOKEN__")) {
      showError("Missing annotation token. Reopen the tokenized URL printed in the terminal.");
      return;
    }
    try {
      const data = await api("/api/sites");
      state.meta = data;
      state.sites = data.sites || [];
      state.frozen = Boolean(data.frozen);
      renderMeta();
      renderProgress();
      bindEvents();
      const firstUnlabeled = state.sites.findIndex((site) => !LABELS.includes(site.label));
      state.index = firstUnlabeled === -1 ? 0 : firstUnlabeled;
      if (state.sites.length) {
        selectSite(state.index);
      } else {
        renderForm();
        showError("This sheet has no sites.");
      }
    } catch (error) {
      showError(error.message || "Could not load the annotation sheet.");
    }
  }

  load();
})();
