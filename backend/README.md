# Kaspersky Cloud Threat Intelligence Console

This application integrates every REST operation documented for a standard Kaspersky Threat Intelligence Portal API token. It does not call KSC Administration Server OpenAPI or the endpoint-local KES Web API.

## Configuration

```bash
cp .env.example .env
```

Generate `KASPERSKY_TIP_API_KEY` at https://opentip.kaspersky.com/token/.

## API routes

- `GET /healthz`
- `GET /api/integrations/status`
- `POST /api/intelligence/lookup`
- `POST /api/intelligence/file/scan`
- `POST /api/intelligence/file/report`

## Run

```bash
docker compose up -d --build
```

Frontend: `http://localhost:3000`; backend: `http://localhost:8080`.

The KES Cloud console has no publicly documented general-purpose customer REST API. Supported MSP integrations must be configured with Kaspersky's vendor integration tooling.
