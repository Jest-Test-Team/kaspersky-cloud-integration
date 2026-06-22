# Testing Guide

## Automated coverage

- `go test ./...` validates input classification, credentials, methods, paths, queries, and bodies for all six Kaspersky endpoints against a mock upstream.
- `robot --outputdir test/results test/kaspersky_cloud.robot` exercises the running service and all six live integrations.
- `npm run build` validates the production frontend.
- `docker compose up -d --build --force-recreate` rebuilds and starts both images.

## Run locally

```bash
docker compose up -d --build --force-recreate
robot --outputdir test/results test/kaspersky_cloud.robot
```

The Robot suite requires a configured `KASPERSKY_TIP_API_KEY` in `.env` and a backend at `BACKEND_URL` (default `http://127.0.0.1:8080`). It uploads only `test/fixtures/benign.txt`.

## Evidence

Robot Framework generates `log.html`, `report.html`, and `output.xml` under the ignored `test/results/` directory. The latest summarized result is maintained in `docs/verification-results.md`.
