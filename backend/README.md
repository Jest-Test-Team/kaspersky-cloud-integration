# Kaspersky Integration Console

Go + Gin backend and Next.js frontend for Kaspersky's official APIs:

- Kaspersky Threat Intelligence Portal lookup is the primary workflow.
- Kaspersky Security Center Open API calls target `https://s405.cloud.kaspersky.com:8080` by default.
- The existing Endpoint Security `swagger.json` explorer endpoints remain available for compatibility.

See [`integration.plan.md`](integration.plan.md) for API boundaries, references, and acceptance criteria.

## Configure

```bash
cp .env.example .env
```

Set `KASPERSKY_TIP_API_KEY` in `.env`. Request the token from the Kaspersky Threat Intelligence Portal after signing in. For Security Center, supply either a supported `KSC_AUTHORIZATION` value (such as `KSCT <token>`) or an existing `KSC_SESSION`. Do not put either credential in a `NEXT_PUBLIC_*` variable.

## Build and run containers

```bash
docker compose build
docker compose up -d
docker compose ps
```

Open `http://localhost:3000`. Backend health is at `http://localhost:8080/healthz`.

## Local verification

```bash
cd backend && go test ./... && go build ./...
cd ../frontend && npm ci && npm run build
```

## Backend API

- `GET /api/integrations/status` reports configuration state without returning secrets.
- `POST /api/intelligence/lookup` accepts `{ "indicator": "..." }` and detects hash, IPv4, domain, or URL.
- `POST /api/intelligence/file/scan` accepts multipart field `file` and submits it for Kaspersky Sandbox analysis.
- `POST /api/intelligence/file/report` accepts `{ "hash": "..." }` and retrieves a previously submitted file report.
- `POST /api/ksc/call` accepts `{ "method": "Class.Method", "args": {} }` and sends a constrained call to the configured KSC origin.
- `GET /api/spec/summary` and `POST /api/proxy` retain the legacy Endpoint Security Swagger workflow.
