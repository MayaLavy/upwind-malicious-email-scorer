# Malicious Email Scorer

Gmail Workspace Add-on that analyzes the currently opened email and returns a **0–100 risk score**, a **verdict**, and **human-readable reasons**.

Open an email → click **Analyze Email** → the add-on extracts lightweight signals from the message, sends them to a Node.js backend, and displays the result in Gmail.

---

## Architecture

```text
Gmail message
  → Gmail Add-on (Apps Script / CardService)
  → extract signals (subject, from, bodyText, urls, replyTo,
                    Authentication-Results, bodyHtml)
  → POST /analyze
  → backend category analyzers
  → corroboration
  → final score (capped at 100) + verdict + reasons
  → result card in Gmail
```

The add-on never visits links. Scoring is deterministic heuristic analysis on the backend—no LLM and no external reputation APIs.

---

## Repository Structure

```text
upwind-malicious-email-scorer/
  apps/
    backend/                         # Node.js / Express API
      src/
        server.js                    # App entry point
        routes/
          health.js                  # GET /health
          analyze.js                 # POST /analyze
        services/
          analyzer.js                # Orchestrates scoring + verdict
          categories/                # Per-category scorers
          utils/                     # Domain / header / HTML helpers
      test/
        scoring.test.js              # Automated scoring + regression tests
      .env.example
    gmail-addon/                     # Google Apps Script add-on
      Code.js                        # UI + message extraction + backend call
      Config.js                      # BACKEND_URL
      appsscript.json                # Manifest + OAuth scopes
  README.md
```

---

## Scoring Model

Each primary detection category is scored independently. Corroboration is then evaluated across category results, and the combined score is capped at 100.

| Category | Signals | Cap |
|----------|---------|-----|
| **Authentication** | SPF fail **+10**, DKIM fail **+10**, DMARC fail **+20** (hard `fail` only) | **30** |
| **Impersonation** | Brand/display-name mismatch **+15**; sender lookalike domain **sets category score to 25** | **25** |
| **URL Risk** | ≥10 unique URLs **+5**; known shortener **+5**; IP URL **+10**; lookalike domain **+15**; displayed-link vs href mismatch **+20** | **25** |
| **Reply-To** | Sender / Reply-To domain-family mismatch **+5** | **5** |
| **Content** | Urgency **+5**; threat **+5**; credentials/sensitive-data request **+15**; unusual financial request **+15** | **20** |
| **Corroboration** | Cross-category bonus (see below) | **+10 max** |

### Corroboration

- **General +10** when all of the following are true:
  - at least **2** scoring categories are active (`score > 0`),
  - at least one active category is **strong** (`Authentication`, `Impersonation`, or `URL Risk`),
  - and either:
    - a) at least one active **non-strong** category (`Reply-To` or `Content`), or
    - b) at least **two** active strong categories.
- **BEC-specific +10:** unusual financial request **and** Reply-To domain mismatch, **only if** the general bonus was not already awarded.
- These bonuses **do not stack**. Corroboration contributes at most **10** points.

### Verdict thresholds

| Score | Verdict |
|------:|---------|
| 0–14 | Low Risk |
| 15–29 | Suspicious |
| 30–59 | High Risk |
| 60–100 | Likely Malicious |

---

## Backend

### Prerequisites

- Node.js **18+**

### Local setup

```bash
cd apps/backend
npm install
cp .env.example .env   # Windows: Copy-Item .env.example .env
npm run dev
```

Default URL: `http://localhost:3000`

`.env.example` includes `PORT` (defaults to `3000` if unset).

### Scripts

| Command | Purpose |
|---------|---------|
| `npm run dev` | Start with file watching |
| `npm start` | Production start |
| `npm test` | Run scoring + regression tests |

### Endpoints

#### `GET /health`

```json
{ "status": "ok" }
```

#### `POST /analyze`

**Required fields:** `subject`, `from`, `bodyText`, `urls`  
**Optional fields:** `replyTo`, `authenticationResults`, `bodyHtml`

**Example request:**

```bash
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d "{
    \"subject\": \"Urgent wire transfer needed\",
    \"from\": \"ceo@company.com\",
    \"bodyText\": \"Please process this wire transfer immediately.\",
    \"urls\": [],
    \"replyTo\": \"ceo@gmail.com\",
    \"authenticationResults\": \"\",
    \"bodyHtml\": \"\"
  }"
```

**Response:**

```json
{
  "score": 30,
  "verdict": "High Risk",
  "reasons": ["..."],
  "breakdown": {
    "authentication": { "score": 0, "findings": [] },
    "impersonation": { "score": 0, "findings": [] },
    "urlRisk": { "score": 0, "findings": [] },
    "replyTo": { "score": 5, "findings": ["..."] },
    "content": { "score": 15, "findings": ["..."] },
    "corroboration": { "score": 10, "findings": ["..."] }
  }
}
```

### Deployment

Deployed on [Render](https://render.com):

- **Root directory:** `apps/backend`
- **Build command:** `npm install`
- **Start command:** `npm start`

On the free tier, the service may sleep. Wake it with `GET /health` before a live demo.

---

## Gmail Add-on

### Files to copy into Apps Script

| Local file | Apps Script file |
|------------|------------------|
| `apps/gmail-addon/Code.js` | `Code.gs` |
| `apps/gmail-addon/Config.js` | `Config.gs` |
| `apps/gmail-addon/appsscript.json` | Project manifest |

`Config.js` sets the backend URL:

```javascript
var CONFIG = {
  BACKEND_URL: "https://upwind-malicious-email-scorer.onrender.com"
};
```

### OAuth scopes

| Scope | Why |
|-------|-----|
| `gmail.addons.current.message.readonly` | Read the currently opened message |
| `gmail.addons.execute` | Run the add-on |
| `script.external_request` | Call the backend via `UrlFetchApp` |

No broad mailbox access is requested.

### Install / demo

1. Create a project at [script.google.com](https://script.google.com).
2. Copy the three files above.
3. **Deploy → Test deployments → Install**.
4. Open Gmail, open a message, open the add-on, click **Analyze Email**.
5. If the backend was sleeping, hit `/health` first and wait for `{ "status": "ok" }`.

The add-on extracts: subject, from, plain body, URLs, Reply-To, `Authentication-Results`, and HTML body. It displays score, verdict, and reasons.

---

## Testing

```bash
cd apps/backend
npm test
```

The suite covers:

- Clean legitimate email
- Authentication failures and non-failure auth states (softfail / neutral / none / missing / temperror / permerror)
- Brand impersonation
- URL risk (shortener + displayed/href mismatch)
- Multi-signal phishing
- BEC-style financial request + Reply-To mismatch
- Reply-To mismatch alone
- Verdict threshold boundaries, global score capping at 100, and key reason/finding assertions
- Regressions: trailing punctuation on displayed domains, subdomain/domain-family equivalence, displayed email addresses (not treated as URLs), quoted Reply-To domains, same-family tracking links

The add-on was also manually tested end-to-end in Gmail across legitimate and suspicious messages, including deceptive/lookalike links and emails with attachments. Attachment contents are not scanned; analysis still uses the remaining header/body/URL signals.

---

## Security & Privacy Decisions

Emails and attachments are treated as **untrusted input**.

Implemented decisions:

- **Minimal Gmail access** — current-message scopes only; no full mailbox permission
- **Request validation** — `/analyze` validates required fields and expected types; invalid payloads return HTTP **400**
- **Payload size limit** — Express limits JSON request bodies to **256 KB**
- **No URL visiting** — links are parsed as strings only; destinations are never fetched
- **No LLM / no external threat APIs** — scoring is local deterministic heuristics
- **Input normalization** — domains are normalized for comparison (case, quotes, trailing punctuation); parent/subdomain pairs are treated as the same domain family where appropriate
- **No raw email body logging** — the backend does not log request bodies or message content (only the server listen message is logged)
- **Attachments** — attachment **contents are not inspected or scored**. An email with a normal PDF can still be analyzed from its headers/body signals. Attachment analysis is intentionally outside this MVP’s detection surface.

---

## Scope, Limitations & Trade-offs

Deliberate MVP boundaries:

| Limitation | Why |
|------------|-----|
| Attachment contents not analyzed | Safe file analysis requires a dedicated scanning pipeline and is outside the MVP scope. Attachment contents are not currently inspected or scored. |
| No URL reputation / sandboxing | Avoids outbound network dependency and privacy risk |
| Hardcoded brand list | Simple, explainable impersonation detection for an assignment MVP |
| Heuristic false positives/negatives | Expected with deterministic rules; mitigated with domain-family checks and conservative URL display matching |
| Minimal regex HTML parsing | Good enough for common `<a href>` mismatches; complex/obfuscated HTML may be missed |
| Backend API has no request authentication | The MVP `/analyze` endpoint is public. A production deployment should use authenticated add-on-to-backend requests and rate limiting. |

---

## Future Improvements

Realistic next steps given this architecture:

- Attachment metadata/content analysis through a dedicated safe scanning pipeline
- URL/domain reputation and threat-intelligence signals
- Richer authentication-header parsing
- More robust HTML parsing
- Broader impersonation/domain-similarity detection
- Authenticated add-on-to-backend requests and rate limiting
- Calibration of scoring weights and verdict thresholds against labeled email datasets
- Optional semantic analysis for ambiguous social-engineering cases, used as an additional signal rather than the sole verdict source

---

## Demo / Reviewer Quick Start

**Backend only**

```bash
cd apps/backend
npm install
npm test
npm run dev
# then: curl http://localhost:3000/health
```

**Full Gmail demo**

1. Wake the deployed backend: open `/health` and wait for OK.
2. Ensure the Apps Script test deployment is installed.
3. Open a real Gmail message → open the add-on → **Analyze Email**.
4. Confirm score, verdict, and reasons appear in the result card.
