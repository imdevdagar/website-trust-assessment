# Website Trust Assessment System threat model

Version 1.0 — engineering and research threat model.

The system deliberately visits hostile web pages and turns their content into evidence. It must treat
the page, its subresources, its scripts, and its text as untrusted. This document lists the assets at
risk, the adversaries considered, the trust boundaries, the implemented controls, and the risks that
remain. It is a design document, not a certification.

---

## 1. Scope and assumptions

**In scope:**

- the local FastAPI service and SQLite database;
- the Playwright/Chromium collection path and static HTTP fallback;
- the browser extension;
- the dashboard served on localhost;
- the research annotation, dataset, and training workflow;
- the user's host machine and local network as reached by the crawler.

**Assumptions:**

- the operator controls the machine and runs the system for personal research or demonstration;
- the API is bound to `127.0.0.1` unless the operator explicitly changes it;
- the operator does not scan authenticated pages or enter real credentials;
- the browser and operating system receive security updates;
- the extension is installed from the local `extension/` directory by the operator.

**Out of scope:**

- a hostile machine administrator or root/kernel compromise;
- nation-state adversaries and browser zero-days;
- a public multi-tenant deployment;
- enterprise SSO, payment processing, or regulated data;
- guarantees that a scanned page is safe;
- legal compliance certification (GDPR, HIPAA, PCI, etc.).

---

## 2. Assets

| ID | Asset | Why it matters |
| --- | --- | --- |
| A1 | Current tab URL and browsing context | Reveals what the user is visiting; the extension sends the URL to localhost. |
| A2 | Assessment database and screenshots | May contain URLs, page text, cookies metadata, and visual content. |
| A3 | Integrity of scores and evidence | A manipulated assessment could wrongly reassure or alarm a user. |
| A4 | Host machine and local network | The crawler makes outbound requests and launches a browser. |
| A5 | Research dataset and labels | Determines the validity of the paper and contains human judgments. |
| A6 | Extension and its settings | A compromised extension could read tabs or redirect the local API. |
| A7 | Reputation labels and feedback | User-supplied data; can change runtime floors and research labels. |
| A8 | Model artifacts and manifests | Reproducibility claims depend on their integrity. |

---

## 3. Adversaries

| Adversary | Capability | Primary goal |
| --- | --- | --- |
| Malicious website operator | Controls page content, scripts, redirects, forms, TLS configuration, and subresources. | Evade detection, impersonate a brand, collect credentials, or influence the assessment. |
| Phishing kit / cloaking service | Serves different content to crawlers, data-centre IPs, or headless browsers. | Show benign content to the system while targeting the human visitor. |
| Prompt injector | Embeds instructions in visible or hidden page text, comments, metadata, or alt text. | Make an LLM or automated reviewer output a favourable verdict. |
| Third-party script/adversary | Controls a script or iframe included by an otherwise legitimate page. | Exfiltrate data, inject content, or alter the page. |
| Local unprivileged user | Can run processes and reach localhost on a shared machine. | Read the database, invoke the API, or tamper with labels. |
| Network attacker | Can observe or modify traffic between the host and the target site, or DNS. | Intercept, redirect, or block collection. |
| Dependency attacker | Compromises a Python or browser dependency. | Execute code in the assessment process or exfiltrate data. |
| Careless operator | Exposes the API, scans private pages, or uses real credentials. | Accidental data leakage or misuse. |

The design does not attempt to resist a malicious administrator or a compromised operating system.

---

## 4. Trust boundaries

```text
[ Browser tab ] --URL only--> [ Extension ] --localhost HTTP--> [ FastAPI ]
                                                                   |
                                                                   +--> [ SQLite / screenshots ]
                                                                   |
                                                                   +--> [ Playwright / Chromium ]
                                                                             |
                                                                             +--> [ Untrusted website ]
                                                                                       |
                                                                             page text, DOM, forms,
                                                                             network requests, OCR
                                                                                       |
                                                                             treated as data only
                                                                                       v
                                                                               [ Evidence extractors ]
                                                                                       |
                                                                               structured Evidence
                                                                                       v
                                                                               [ Scoring / explanation ]
```

Boundary notes:

1. **Extension → API.** The extension transmits the current URL and action, not page HTML. It accepts
   only localhost server origins. The API has no remote authentication because it is a single-user
   local service.
2. **API → target.** Every URL and browser subrequest is untrusted. Redirects and subresources must be
   revalidated; a check on the initial URL alone is insufficient.
3. **Page → extractors.** Page text is parsed as data. No page content is executed as an instruction,
   interpolated into a prompt, or used to construct shell/SQL commands.
4. **Evidence → scoring.** Extractors emit typed `Evidence` objects. Downstream code does not parse
   arbitrary HTML to decide a score.
5. **Research artifacts → training.** Known-label evidence and derived labels are removed before model
   fitting. The dataset hash is recorded in every artifact.
6. **Local filesystem.** SQLite, screenshots, labels, and models are readable by the local user. Disk
   encryption and access controls are the operator's responsibility.

---

## 5. Threat analysis and controls

### 5.1 Server-side request forgery and network access

**Threat.** A submitted URL or a page subresource causes the server to request a private address,
link-local metadata service, localhost service, or an internal hostname. Redirects can bypass a
one-time initial check.

**Implemented controls:**

- only `http` and `https`; standard ports 80/443;
- reject embedded credentials, whitespace/control characters, overlong URLs, invalid IDNA;
- resolve hostnames and reject non-public IPs, including loopback, private, link-local, multicast,
  reserved, and metadata names;
- validate every HTTP redirect hop (maximum 5);
- revalidate every Playwright subrequest through `check_request_url_sync`;
- block local/internal host suffixes (`.local`, `.internal`, `.lan`, `.home`, `.corp`, `.localhost`)
  and metadata hostnames;
- block media requests and abort unsafe requests before they leave the browser.

**Residual risk:** DNS rebinding. The validation resolves a hostname, but Chromium may resolve it again
at connection time. A determined attacker with a short-TTL record can return a different address after
the check. Mitigations such as a DNS-pinning proxy or network namespace isolation are not implemented.
The API should not be exposed to untrusted networks.

### 5.2 Browser compromise and malicious page behaviour

**Threat.** A page exploits Chromium, escapes the renderer, installs a service worker, triggers a
download, opens popups, or abuses dialogs to interfere with collection.

**Implemented controls:**

- headless Chromium in a fresh browser context per assessment;
- `accept_downloads=False`;
- service workers blocked;
- media requests blocked;
- popups and extra pages closed;
- dialogs dismissed automatically;
- no form submission and no credential/card entry by the automation;
- bounded page settle and crawl timeouts;
- no persistent profile reused across sites.

**Residual risk:** browser zero-days and sandbox escapes. Run the software on a patched machine, ideally in
a dedicated VM or non-privileged account when scanning untrusted links at scale. Do not scan pages while
logged into sensitive accounts.

### 5.3 Prompt injection and instruction-like content

**Threat.** A page contains text such as "ignore previous instructions", fake system prompts, or
instructions to mark the site safe. If that text reaches a language model, it can change the verdict.

**Implemented controls:**

- The system does not send page content to an LLM. Explanations are deterministic templates over typed
  evidence.
- Hidden text, comments, metadata, alt text, zero-width characters, and bidi controls are scanned for
  instruction-like patterns (`hidden_prompt_injection`, `zero_width_obfuscation`,
  `bidi_control_spoofing`, `encoded_instruction_blob`).
- Page content is never concatenated into a prompt, shell command, SQL statement, or file path.
- OCR text is sanitised and used only for pattern matching; it is not persisted as part of the
  assessment.

**Residual risk:** if optional LLM narration is added later, the LLM becomes a new trust boundary.
It must receive a narrow, structured evidence summary, never raw HTML or unquoted page text, and its
output must not directly control the score. The current repository reserves Ollama settings but does
not implement LLM narration; enabling those settings alone does not create an LLM path.

### 5.4 Assessment manipulation and cloaking

**Threat.** The site shows the crawler different content from what a human sees, hides adverse content,
or fabricates trust signals to lower its risk score.

**Implemented controls:**

- multiple independent evidence sources, not a single content check;
- inconsistency checks between the claimed identity, domain, certificate, contact information, and
  forms;
- evidence provenance and confidence;
- no positive score from "the page looks professional" alone;
- abstention when coverage is low.

**Residual risk:** cloaking is fundamentally hard to defeat from a single vantage point. A site can
serve benign content to a headless browser or a data-centre IP. The system reports what it observed and
does not claim to reconstruct the human view. Future work could compare multiple vantage points, but
that is outside version 1.0.

### 5.5 Credential and payment capture by the operator

**Threat.** The automation or a rushed annotator submits a form, enters a password, or completes a
payment while inspecting a malicious page.

**Implemented controls:**

- the automation never fills or submits forms;
- annotator protocol forbids login, signup, payment, OTP entry, seed phrases, and downloads;
- forms are inspected from the DOM only;
- remote-access and seed-phrase requests are surfaced as high-severity evidence;
- no password manager or stored profile is used by the automation.

**Residual risk:** human error. Use a dedicated browser profile with no saved credentials and follow
the stop conditions in [annotation-protocol.md](annotation-protocol.md).

### 5.6 Data disclosure at rest and in transit

**Threat.** Assessment URLs, screenshots, labels, or notes leak through the database, logs, backups, or
a public repository.

**Implemented controls:**

- localhost binding by default;
- no telemetry or cloud calls;
- extension localhost restriction;
- screenshots stored under `data/screenshots` and excluded from version control;
- annotation protocol forbids credentials and personal data in notes;
- dataset release planned as derived features and labels, not raw screenshots;
- no raw page HTML returned to the extension or dashboard.

**Residual risk:** SQLite and screenshots are unencrypted. A local attacker or stolen laptop can read
them. Use full-disk encryption, restrict file permissions, and delete data when no longer needed.
The database may contain sensitive URLs even if page credentials were never entered. Do not scan
personal account pages.

### 5.7 API abuse, CSRF, and local denial of service

**Threat.** A malicious local process or a web page tries to invoke `/v1/assess` or `/v1/guard`, causing
scans, resource exhaustion, or data disclosure.

**Implemented controls:**

- API bound to `127.0.0.1` by default;
- CORS disabled unless explicitly configured; `application/json` requests trigger preflight;
- per-client rate limit (default 30 requests/minute);
- assessment concurrency limit (default 2);
- timeouts, response-size limits, redirect limits, and a bounded number of links/forms;
- security headers and CSP on the dashboard.

**Residual risk:** there is no authentication. Any local process or user that can reach the port can
invoke the API and read stored assessments. This is acceptable for a single-user research prototype
but not for a shared machine or a network-exposed deployment. If binding to a non-loopback address,
put the service behind authentication and a reverse proxy; do not do this for a classroom demo
without understanding the risk.

### 5.8 Extension compromise

**Threat.** A malicious update, a compromised extension page, or an overly broad permission reads
sensitive tabs or sends URLs to a remote server.

**Implemented controls:**

- Manifest V3 with local files only; no remote code;
- server URL normalisation accepts only `127.0.0.1` and `localhost`;
- page URL is the only browsing data sent;
- verdict cache is local and bounded;
- no inline event handlers; extension pages use the packaged scripts;
- no content script injection of remote content.

**Residual risk:** broad host permissions are required to observe the active tab and show warnings.
A compromised browser or extension update can still read tabs. Review the code before installing and
do not install builds from untrusted sources. The server itself must be trusted because it receives the
URL.

### 5.9 Research integrity and label poisoning

**Threat.** Labels, assessments, or feedback are altered; test data influences model selection; known
reputation labels leak into features; a changed dataset is reported under an old result.

**Implemented controls:**

- separate annotation sheets and coordinator-only key;
- hashes for datasets and artifacts;
- known-label and label-derived features excluded;
- domain-grouped splits and overlap checks;
- validation-only calibration and threshold selection;
- test-set reuse prohibited by protocol;
- run manifests and reports generated automatically;
- feedback is stored but not automatically used for training.

**Residual risk:** a determined author can still misreport. The defense is the archived protocol,
frozen artifacts, hashes, and independent review. Do not use runtime labels to build training data
without rebuilding and re-reporting the dataset.

### 5.10 Supply chain and dependencies

**Threat.** A compromised Python package, Playwright browser build, or bundled knowledge file changes
behaviour or exfiltrates data.

**Implemented controls:**

- dependencies are declared with minimum versions; no runtime auto-update;
- no cloud SDK, telemetry package, or remote model download in the request path;
- tldextract uses the bundled public suffix snapshot with network updates disabled;
- knowledge files are local and reviewable.

**Residual risk:** `pyproject.toml` does not pin exact versions or hashes. Before a public release,
produce a lockfile, review dependency changes, and run a vulnerability scan. Treat browser updates as
security updates. A reproducible research environment should record the exact wheel versions.

---

## 6. Privacy analysis

| Data | Where it goes | Retention |
| --- | --- | --- |
| Current tab URL | Extension → localhost API | Cached up to 1 hour; assessment stored in local SQLite. |
| Page HTML/DOM | Crawler → extractors → typed features | Raw HTML is not persisted; derived features and a screenshot may be. |
| Screenshot | Local filesystem | Stored until the operator deletes it. |
| Form field names | Assessment evidence/meta | Stored as derived metadata; values are not collected. |
| Tracker/network URLs | Evidence features | Stored in assessment metadata. |
| Annotation notes | Local CSV | Stored until the dataset freeze; should contain no personal data. |
| Feedback | Local SQLite | Stored for research review; not auto-training. |

No data is sent to a cloud API by default. The optional Ollama settings are not wired into the request
path. A user who enables a future narration feature must treat the local LLM as a data processor and
review what is sent to it.

---

## 7. Risk register

| Risk | Likelihood | Impact | Status |
| --- | --- | --- | --- |
| DNS rebinding bypasses SSRF check | Low | High | Partially mitigated; documented residual. |
| Malicious page cloaks content from crawler | Medium | High | Not solvable from one vantage point; documented. |
| Browser zero-day during scan | Low | High | Use patched browser and dedicated environment. |
| Local user reads SQLite/screenshots | Medium | Medium | Disk encryption and access controls are operator duties. |
| API exposed to LAN | Low | High | Default localhost; warning in README and this document. |
| Prompt injection via page text | Medium | High if an LLM is added | Current path has no LLM; detection implemented. |
| Label leakage inflates results | Medium | High | Excluded features, leakage report, dataset hash. |
| Test-set reuse inflates results | Medium | High | Protocol freeze; evaluate once. |
| Small test set yields unstable claims | High | Medium | Report intervals and sample counts; avoid subgroup claims. |
| False positive harms a small site | Medium | Medium | Advisory wording, evidence cards, human review. |
| Dependency compromise | Low | High | Pin and audit before release. |

---

## 8. Responsible use

- The system is **advisory**. Do not use it as the sole reason to block a site, accuse an organization,
  or make a financial decision.
- A low score is not proof of safety. A high score is not proof of malice. Report confidence, coverage,
  and missing evidence alongside the verdict.
- Browser warnings should preserve user agency. The extension's block verdict is a warning layer, not
  a security boundary; the user can inspect the evidence.
- Do not scan pages while authenticated, and do not enter credentials into a page under assessment.
- Do not expose the API to the internet or a shared network without authentication and a review.
- Do not publish screenshots or assessment records containing personal data.
- If you find a real phishing site, report it to the relevant brand, hosting provider, or a public
  takedown service. The system is not a takedown service.
- Security issues in the project should be reported privately to the project maintainers before public
  disclosure.
