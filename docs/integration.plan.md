# Kaspersky Cloud Integration Implementation Plan

## 1. Scope and product identity

The supplied console, `https://s405.cloud.kaspersky.com:8080`, identifies itself as **Kaspersky Endpoint Security Cloud**. It is not a customer-reachable Kaspersky Security Center Administration Server.

Integrate every officially documented public cloud endpoint that the supplied Kaspersky Threat Intelligence Portal API token can call. Do not scrape browser sessions or expose credentials to the frontend.

## 2. Official endpoint inventory

Base URL: `https://opentip.kaspersky.com/api/v1`; authentication: `X-API-KEY`.

| # | Method | Upstream endpoint | Purpose | Application route |
|---|---|---|---|---|
| 1 | GET | `/search/hash?request=...` | MD5, SHA-1, or SHA-256 lookup | `POST /api/intelligence/lookup` |
| 2 | GET | `/search/ip?request=...` | IPv4 lookup | `POST /api/intelligence/lookup` |
| 3 | GET | `/search/domain?request=...` | Domain lookup | `POST /api/intelligence/lookup` |
| 4 | GET | `/search/url?request=...` | HTTP(S) web-address lookup | `POST /api/intelligence/lookup` |
| 5 | POST | `/scan/file?filename=...` | Basic Sandbox file analysis | `POST /api/intelligence/file/scan` |
| 6 | POST | `/getresult/file?request=...` | Full file-analysis report | `POST /api/intelligence/file/report` |

The application also publishes this inventory at `GET /api/integrations/endpoints`.

## 2a. Kaspersky Security Center 15.2 Open API (added)

The backend now also integrates the documented KSC 15.2 Administration Server Open API (HTTP+JSON, `POST /api/v1.0/Class.Method`, default port 13299). Implemented operations: `Session.StartSession`, `HostGroup.GetStaticInfo`/`FindGroups`/`FindHosts`, `LicenseKeys.EnumKeys` (list results drained through `ChunkAccessor`), plus an allow-listed read-only generic call proxy. Credentials (`KSC_AUTHORIZATION` or `KSC_SESSION`) stay server-side. Application routes are documented in `docs/api-endpoints.md`. Reference: https://support.kaspersky.com/help/KSC/15.2/KSCAPI/

The supplied hosted console (`s405.cloud.kaspersky.com:8080`) is a KES Cloud Web Console and answers these calls with `401 credentials_required`; supply a real Administration Server to retrieve live data.

## 3. Explicitly unavailable surfaces

- Kaspersky Endpoint Security Cloud has no officially published general-purpose customer administration REST contract.
- KSC OpenAPI targets an Administration Server and its documentation requires the OpenAPI package on the Administration Server device. It is not a public KES Cloud API.
- Endpoint Security for Windows Web API is localhost-only.
- MSP connectors and the OpenCTI/TAXII connector are separately installed products and use different credentials/contracts.
- Undocumented Web Console endpoints are excluded because they are private implementation details, cannot be supported safely, and do not constitute an official API.

## 4. Implementation phases

1. Keep the API key exclusively in the Go backend and validate all user inputs.
2. Implement the four typed lookup calls, file upload, and full report retrieval.
3. Publish endpoint metadata and integration status for the frontend and automation.
4. Render lookup, Sandbox upload, endpoint inventory, and the product limitation in the frontend.
5. Verify all upstream mappings with a mock Kaspersky server in Go tests.
6. Exercise all six integrations against the configured token with Robot Framework.
7. Build production binaries and images, recreate the Compose stack, and rerun smoke tests.
8. Record outcomes, limitations, issues, and reproducible commands under `docs/`.

## 5. Acceptance criteria

- Exactly six official KTIP endpoints are cataloged and implemented.
- Authentication is server-side and absent from browser responses/logs.
- Every endpoint has contract coverage and live Robot coverage.
- Upstream errors retain the upstream HTTP status without leaking secrets.
- Go tests/build, Next.js production build, Docker image build, Compose health, frontend HTTP check, and Robot suite are executed successfully or any vendor-side failure is recorded precisely.

## 6. Official sources

- KTIP API overview: https://opentip.kaspersky.com/Help/Doc_data/WorkingWithAPI.htm
- KTIP complete reference: https://opentip.kaspersky.com/Help/Doc_data/all-in-one.htm?sectionUrl=WorkingWithAPI.htm
- KES Cloud overview: https://support.kaspersky.com/Cloud/1.0/en-us/123486.htm
- KES Cloud MSP integrations: https://support.kaspersky.com/msp/integrations/141380.htm
- KSC OpenAPI reference: https://support.kaspersky.com/ksc/14/en-US/211453.htm
- Endpoint-local KES API limitation: https://support.kaspersky.com/kes-for-windows/12.2/189442
