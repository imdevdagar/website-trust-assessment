# Demo and release runbook

This runbook covers the software demo: install, verify, run the local app, and show the extension.
Research claims live in the model card and manuscript; do not improvise them during a demo.

## 1. Pre-flight

Run these before the demo, not during it:

```bash
wtas doctor
```

Expected: `READY` on a source checkout. A `WARN` for Tesseract means OCR evidence is
unavailable; a `WARN` for the port means another server may already be running. A `FAIL` must be fixed.
Use `wtas doctor --json` if you need to log the result.

Then confirm:

- the machine can reach the public web (the demo scans `example.com`);
- Chromium is installed (`python -m playwright install chromium`);
- the browser extension is loaded and pinned;
- the API is running at `http://127.0.0.1:8000`;
- `data/dashboard-result.png`, `data/extension-popup-final.png`, and
  `data/extension-overlay-warn.png` exist as an offline fallback.

## 2. Fresh install

From the repository root:

```bash
python -m venv .venv
source .venv/Scripts/activate        # Git Bash on Windows
# .venv\Scripts\Activate.ps1         # PowerShell
# source .venv/bin/activate          # macOS/Linux
python -m pip install --upgrade pip
pip install -e ".[dev]"
python -m playwright install chromium
wtas doctor
wtas init
```

A wheel install exercises the packaged dashboard and knowledge files. Use a separate virtual
environment so the editable install is not replaced:

```bash
python -m pip wheel . --no-deps --no-build-isolation -w dist
python -m venv .venv-wheel
source .venv-wheel/Scripts/activate
python -m pip install dist/website_trust_assessment_system-0.1.1-py3-none-any.whl
wtas doctor
```

A non-editable install stores the database, screenshots, and models in the platform user-data
directory (`%LOCALAPPDATA%\WebsiteTrustAssessment` on Windows, `~/Library/Application Support/WebsiteTrustAssessment` on macOS,
`$XDG_DATA_HOME/website-trust-assessment` on Linux). Set `WTAS_HOME` to override it. The extension remains in the
source checkout's `extension/` directory.

## 3. Isolated demo state

Avoid writing demo scans into the research database. Start the server with a throw-away home:

```bash
WTAS_HOME=.demo-state wtas serve
```

PowerShell:

```powershell
$env:WTAS_HOME = ".demo-state"
wtas serve
```

On first start the API creates the database and directories under `.demo-state/`. To reset after the
demo, stop the server and delete only that directory. Do not delete `data/`.

## 4. Five-minute walkthrough

1. **Readiness (20 s).** Run `wtas doctor` in a second terminal. Point out that it checks
   dependencies, bundled assets, Chromium, database write access, OCR, and the port.
2. **Dashboard (2 min).** Open `http://127.0.0.1:8000/dashboard` and scan `https://example.com` with
   action **browse**. Walk through the four dimensions, the evidence cards with source and
   confidence, missing evidence, coverage, and the explicit low-risk wording. A low score means no
   evidence of harm was found; it is not a guarantee.
3. **Action awareness (30 s).** Scan the same URL with **purchase** and show how the action changes
   dimension weighting and the recommendation. The engine is deterministic for the same captured
   page; the live page itself can change, so treat a second scan as a fresh observation.
4. **CLI (30 s).** Run:
   ```bash
   wtas guard https://example.com
   wtas stats
   ```
5. **Extension (1 min).** Open `chrome://extensions`, enable Developer mode, choose **Load unpacked**,
   and select `extension/`. Pin Website Trust Assessment Guard, open `https://example.com`, and open the popup. Show
   the verdict, the evidence summary, and the localhost-only server setting.
6. **Evaluation evidence (30 s, optional).** Open `data/research/runs/feed_v3/report.md` and state one
   result only: over 5,129 feed-labelled domains the shipped rule engine is at chance against feed
   membership (AUROC 0.455 on the test split, 0.475 over all labelled rows), while the research hybrid
   models reach 0.987–0.993. Explain that the learned models are not shipped and the rule engine remains
   the decision policy.

## 5. Claims to keep straight

- The system is an advisory research prototype, not a commercial safety product.
- The evaluation sample is 5,129 feed-labelled samples over 5,129 domains; percentages are not web-wide
  prevalence.
- The benign class is *not reported by the feeds*, not verified clean.
- The 146 human labels are a one-annotator validity subset; no inter-rater reliability is claimed.
- The H3 user study was not run; do not claim that evidence cards improve user decisions.
- Learned models are evaluation artifacts; the API loads the rule engine only.
- Hidden-instruction isolation is measured on a controlled local corpus, not on in-the-wild pages.

## 6. Troubleshooting

| Symptom | Check |
| --- | --- |
| `/dashboard` returns 503 | `wtas doctor` dashboard check; use a source checkout or the built wheel. |
| Scan fails immediately | Network access, Playwright install, and whether the URL is public HTTP(S). Loopback and private addresses are blocked by design. |
| Scan times out | Retry once; some sites block headless browsers. Raise `WTAS_CRAWL_TIMEOUT_MS` for slow pages. |
| Extension says the server is offline | Start `wtas serve`; confirm the popup server address is `http://127.0.0.1:8000`; only localhost is accepted. |
| Extension cannot read the page | Reload the tab after loading the extension; confirm permissions were accepted. |
| OCR evidence missing | Install Tesseract and rerun `wtas doctor`; this is optional. |
| Port 8000 in use | `wtas serve --port 8001`, then update the extension server address. |
| Demo database polluted | Stop the server and remove the isolated `.demo-state/` directory. |
| `pytest` temp-directory error on Windows | Use `PYTHONPATH=. python -m pytest -q --basetemp=.pytest-tmp`. |

## 7. Safety during the demo

Do not scan authenticated pages, private addresses, or gated research candidates. Do not enter
credentials or submit forms. Do not run collection commands that visit malicious URLs. The crawler
never submits forms, accepts downloads, or interacts with account surfaces; keep it that way.
