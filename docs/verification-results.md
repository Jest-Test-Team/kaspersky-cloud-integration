# Verification Results

Verified on 2026-06-22 (Asia/Taipei).

| Gate | Result | Evidence |
|---|---|---|
| Go contract tests | PASS | All six upstream methods, paths, queries, request bodies, and API-key headers tested with a mock transport |
| Go production build | PASS | Binary built to `/tmp/kaspersky-cloud-backend` |
| Next.js production build | PASS | Static `/` and `/_not-found` routes generated |
| Backend Docker image | PASS | `kaspersky-integration-backend:local` rebuilt |
| Frontend Docker image | PASS | `kaspersky-integration-frontend:local` rebuilt |
| Compose runtime | PASS | Backend healthy; frontend running |
| Frontend smoke test | PASS | HTTP 200 from `http://127.0.0.1:3000` |
| Runtime endpoint catalog | PASS | Exactly six paths returned by `/api/integrations/endpoints` |
| Robot Framework live suite | PASS | 7 tests passed, 0 failed |
| Removed non-cloud routes | PASS | `/api/ksc/call`, `/api/spec/summary`, and `/api/proxy` return HTTP 404 |

## Live endpoint outcomes

| Integration | Result |
|---|---|
| Hash lookup | HTTP success; response contains `Zone` |
| IPv4 lookup | HTTP success; response contains `Zone` |
| Domain lookup | HTTP success; response contains `Zone` |
| URL lookup | Integration exercised; Kaspersky returned upstream HTTP 400 for a valid URL (known issue) |
| Basic file analysis | HTTP success using `test/fixtures/benign.txt` |
| Full file report | HTTP success; response contains `Zone` |

Robot artifacts are generated at `test/results/output.xml`, `test/results/log.html`, and `test/results/report.html` and are intentionally git-ignored.
