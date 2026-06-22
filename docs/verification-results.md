# Verification Results

Verified on 2026-06-22 (Asia/Taipei).

| Gate | Result | Evidence |
|---|---|---|
| Go contract tests | PASS | All six OpenTIP methods + KSC client (call, accessor draining, auth headers, PxgError mapping, allow-list) tested with a mock transport (`go test ./...`) |
| Go production build | PASS | Binary built to `/tmp/kaspersky-cloud-backend` |
| Next.js production build | PASS | Static `/` and `/_not-found` routes generated |
| Backend Docker image | PASS | `kaspersky-integration-backend:local` rebuilt |
| Frontend Docker image | PASS | `kaspersky-integration-frontend:local` rebuilt |
| Compose runtime | PASS | Backend healthy; frontend running |
| Frontend smoke test | PASS | HTTP 200 from `http://127.0.0.1:3000` |
| Runtime endpoint catalog | PASS | Exactly six paths returned by `/api/integrations/endpoints` |
| Robot Framework intelligence suite | PASS | 7 tests passed, 0 failed (`test/kaspersky_cloud.robot`) |
| Robot Framework KSC suite | PASS | 8 tests passed, 0 failed (`test/ksc.robot`) |
| KSC allow-list enforcement | PASS | `POST /api/ksc/call` with `HostGroup.RemoveHost` returns HTTP 403 |
| Docker rebuild + up | PASS | Both images rebuilt; backend healthy, frontend HTTP 200; engine 29.5.2 |
| Robot suites vs. composed stack | PASS | 19 tests passed (KSC 12 + intelligence 7) against the running containers |
| Cloud auth scheme live | PASS | `/api/ksc/status` reports `authScheme: KSCBasic login (account/password)`, 9 operations |

## Live endpoint outcomes

| Integration | Result |
|---|---|
| Hash lookup | HTTP success; response contains `Zone` |
| IPv4 lookup | HTTP success; response contains `Zone` |
| Domain lookup | HTTP success; response contains `Zone` |
| URL lookup | Integration exercised; Kaspersky returned upstream HTTP 400 for a valid URL (known issue) |
| Basic file analysis | HTTP success using `test/fixtures/benign.txt` |
| Full file report | HTTP success; response contains `Zone` |
| KSC server-info / hosts / groups / licenses / session | Backend reached upstream; the KES Cloud console returned `401 credentials_required` (it does not serve the KSC Open API). Errors surfaced gracefully with the upstream status. Point `KSC_BASE_URL`/`KSC_AUTHORIZATION` at a real KSC 15.2 Administration Server (port 13299) for live data. |

Robot artifacts are generated at `test/results/output.xml`, `test/results/log.html`, and `test/results/report.html` and are intentionally git-ignored.
