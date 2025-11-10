## Purpose

Help an AI agent become productive in this repository: a small Python-based Nova Act security agent that drives a browser against WebGoat to test XSS and SQL injection payloads.

## Big picture (what to know fast)
- This is a single-purpose test agent: it uses Nova Act browser automation to visit WebGoat, inject payloads into login/inputs, and record results (see `README.md`).
- Primary flows: load environment (via `.env` / `NOVA_ACT_API_KEY`), start NovaAct, iterate payload list (XSS and SQL), submit forms, analyze responses, write `security_test_results.json` and console report.
- Key artefacts referenced in docs: `webgoat_security_test.py` (main runner per README) and `nova-act-sql-xss-injection.ipynb` (notebook examples showing `dotenv` usage and NovaAct snippet).

## Where to look first (files/places)
- `README.md` — authoritative high-level usage and full payload lists (XSS and SQL examples).
- `nova-act-sql-xss-injection.ipynb` — shows .env loading and example NovaAct usage (look at the first two cells for `dotenv` and `NovaAct` usage).
- `vunerable_website/` — self-contained vulnerable Flask app (SQL injection + XSS) for local testing without WebGoat.
  - `vunerable_website/app.py` — main Flask app with intentional vulnerabilities.
  - `vunerable_website/README.md` — how to run the vulnerable app and test payloads.
  - `vunerable_website/Dockerfile` — containerized vulnerable web app.
- Search for `NOVA_ACT_API_KEY` or `.env` in the repo to find environment-dependent behavior.

## Environment & run workflows (explicit)
- Install dependencies: `pip install -r requirements.txt` (README). If `requirements.txt` is missing, inspect the notebook for imports (`dotenv`, `nova_act`) and install those packages.
- **Install Playwright browser** (one-time setup):
  ```powershell
  pip install playwright
  python -m playwright install chromium
  ```
- **Start WebGoat** (required before running tests):
  ```powershell
  # Using Docker (recommended):
  docker run -p 8080:8080 -p 9090:9090 webgoat/webgoat
  
  # Or using standalone JAR:
  java -jar webgoat-2024.x.jar
  ```
  Wait for "WebGoat started on port 8080" before running tests.
- Set the API key (PowerShell example):
  - `$env:NOVA_ACT_API_KEY = "<your_key>"` or create a `.env` file with `NOVA_ACT_API_KEY=...` (the notebook uses `python-dotenv`).
- Run the main test runner (per README):
  - Visible browser: `python webgoat_security_test.py`
  - Headless: `python webgoat_security_test.py --headless`
  - Target URL override: `python webgoat_security_test.py --target_url http://localhost:8080/WebGoat/login`

## Patterns & conventions to follow
- Environment-first: sensitive keys come from environment or `.env` (see notebook cell that calls `load_dotenv()` and then `os.environ.get("NOVA_ACT_API_KEY")`).
- CLI flags are used to switch modes (`--headless`, `--xss_only`, `--sql_only`, `--target_url`) — follow the same pattern when adding new runner options.
- Output: the project emits a consolidated JSON (`security_test_results.json`) and human-readable console output; preserve that format when extending reporting.

## Integration points / external deps
- NovaAct (library) — core browser automation. Search imports for `from nova_act import NovaAct` to find usage sites.
- python-dotenv (`dotenv`) — config from `.env`.
- WebGoat (external target) — tests assume a running WebGoat instance; the runner accepts a `--target_url` to customize the target.
- **Vulnerable Flask app** (`vunerable_website/`) — alternative local target with SQL injection and XSS vulnerabilities. Run with Docker: `docker build -t vulnerable-webapp vunerable_website && docker run -p 5000:5000 vulnerable-webapp` or locally: `cd vunerable_website && python app.py`.

## Example snippets (copyable patterns)
- Read env and use NovaAct (from notebook):
  - `load_dotenv(); nova_api_key = os.environ.get("NOVA_ACT_API_KEY")`
  - `with NovaAct(starting_page=...) as nova: nova.act("click...", "return title")`
- Run only XSS tests: `python webgoat_security_test.py --xss_only`

## Known issues & workarounds
- **Jupyter/asyncio incompatibility**: NovaAct's sync API fails in Jupyter notebooks because notebooks run inside an asyncio event loop. The error is: `"It looks like you are using Playwright Sync API inside the asyncio loop. Please use the Async API instead."`
  - **Primary solution**: Install `nest_asyncio` (`pip install nest-asyncio`) and run `import nest_asyncio; nest_asyncio.apply()` before NovaAct code. See the notebook's cell 2 and cell 3 for the working example.
  - **Alternative**: Use standalone Python scripts (like `webgoat_security_test.py`) instead of running NovaAct in notebook cells.
  - Other options: Switch to NovaAct's async API or run automation via `subprocess`/`%run` magic.

- **Authentication errors**: If you see `AuthError: Authentication failed`, your `NOVA_ACT_API_KEY` is missing, invalid, or expired.
  - Get a valid key from https://nova.amazon.com/act
  - Update `.env` file: `NOVA_ACT_API_KEY=your-key-here`
  - Verify with `python -c "import os; from dotenv import load_dotenv; load_dotenv(); print('Key exists:', os.getenv('NOVA_ACT_API_KEY') is not None)"`

- **HTTP to HTTPS redirect**: NovaAct validates SSL certificates by default. For localhost HTTP URLs, add `ignore_https_errors=True`:
  ```python
  NovaAct(starting_page="http://localhost:8080/WebGoat", ignore_https_errors=True)
  ```

## Safe guardrails for edits
- Do not hardcode API keys or secrets. Use `.env` or environment variables.
- Keep payload lists in the same place they are consumed (README lists canonical payloads). If moving payloads into code, keep the same names and order to preserve report comparability.

## When adding features
- Add CLI flags consistent with existing ones. Update README with exact example commands.
- Ensure any new output is added to the JSON export; consumers expect `security_test_results.json`.

## Quick facts for PRs
- Focus changes on: `webgoat_security_test.py`, helper modules, or the notebook. Update README when usage or flags change.
- No test harness is present in the repo; prefer small smoke scripts or notebook examples to validate changes.

---
If anything in this file is unclear or you want a different focus (for example: more notebook-driven examples, or explicit JSON schema for `security_test_results.json`), tell me and I'll iterate.
