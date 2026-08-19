# upwind-malicious-email-scorer

Gmail Add-on + backend service that analyzes the currently opened email and displays a maliciousness score, verdict, and explainable reasons.

## Project structure

```text
upwind-malicious-email-scorer/
  apps/
    backend/          # Node.js/Express API
    gmail-addon/      # Google Apps Script Gmail Add-on
```

## Backend

### Prerequisites

- Node.js 18+

### Local development

```bash
cd apps/backend
npm install
cp .env.example .env   # on Windows: Copy-Item .env.example .env
npm run dev
```

The server starts on `http://localhost:3000` by default.

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /health | Returns `{ "status": "ok" }` |
| POST | /analyze | Accepts `{ subject, from, bodyText, urls }` and returns a maliciousness analysis |

### Test

```bash
curl http://localhost:3000/health

curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"subject":"Invoice overdue","from":"billing@example.com","bodyText":"Please pay immediately.","urls":["http://example.com/pay"]}'
```

### Deployment

The backend is deployed on [Render](https://render.com). Render settings:

- **Root directory:** `apps/backend`
- **Build command:** `npm install`
- **Start command:** `npm start`

## Gmail Add-on

The add-on is built with Google Apps Script and CardService. It runs inside Gmail and displays a maliciousness analysis when the user opens an email.

### Setup

1. Create a new project at [script.google.com](https://script.google.com)
2. Copy the contents of `apps/gmail-addon/Code.js` into `Code.gs`
3. Enable "Show appsscript.json manifest file in editor" in Project Settings
4. Replace `appsscript.json` contents with `apps/gmail-addon/appsscript.json`
5. Deploy as a test deployment (Gmail Add-on type)
6. Open Gmail, open an email, and click the add-on icon
