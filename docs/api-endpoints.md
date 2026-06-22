# API Endpoint Catalog

## Public Kaspersky cloud endpoints

All documented endpoints available to a standard Kaspersky Threat Intelligence Portal API token are listed below.

| Method | Full endpoint | Request | Expected success |
|---|---|---|---|
| GET | `https://opentip.kaspersky.com/api/v1/search/hash` | `request=<MD5/SHA1/SHA256>` | JSON reputation/report |
| GET | `https://opentip.kaspersky.com/api/v1/search/ip` | `request=<IPv4>` | JSON IP intelligence |
| GET | `https://opentip.kaspersky.com/api/v1/search/domain` | `request=<domain>` | JSON domain intelligence |
| GET | `https://opentip.kaspersky.com/api/v1/search/url` | `request=<HTTP(S) URL>` | JSON URL intelligence |
| POST | `https://opentip.kaspersky.com/api/v1/scan/file` | `filename=<name>`, octet-stream body | Basic analysis JSON |
| POST | `https://opentip.kaspersky.com/api/v1/getresult/file` | `request=<hash>` | Full analysis JSON |

Every request uses `X-API-KEY`. The source of truth is Kaspersky's [Working with the API](https://opentip.kaspersky.com/Help/Doc_data/WorkingWithAPI.htm) section; it links exactly these six operations.

## Application endpoints

| Method | Route | Purpose |
|---|---|---|
| GET | `/healthz` | Runtime and credential readiness |
| GET | `/api/integrations/status` | Configuration/product status |
| GET | `/api/integrations/endpoints` | Machine-readable catalog of all six operations |
| POST | `/api/intelligence/lookup` | Validated hash, IPv4, domain, or URL lookup |
| POST | `/api/intelligence/file/scan` | Validated file submission, maximum 256 MiB |
| POST | `/api/intelligence/file/report` | Full report retrieval by validated hash |

## Kaspersky Security Center 15.2 Administration Server Open API

The KSC Open API is an HTTP+JSON API (not JSON-RPC). Each method is invoked with `POST {base}/api/v1.0/[Instance.]Class.Method`, a JSON body of input parameters (`{}` when none), `Content-Type: application/json`, and either an `Authorization` header (`KSCT <token>`, `KSCWT <web-token>`, `KSCBasic ...`) or an `X-KSC-Session` header. Success returns `{"PxgRetVal": ..., <out params>}`; failure returns `{"PxgError": {code, module, message}}`. List operations return a server-side iterator that is drained through `ChunkAccessor.GetItemsCount`/`GetItemsChunk` and then `Release`. Default port is 13299. Reference: https://support.kaspersky.com/help/KSC/15.2/KSCAPI/

### Backend KSC routes

| Method | Route | KSC class.method | Purpose |
|---|---|---|---|
| GET | `/api/ksc/status` | — | KSC configuration, transport, operation catalog |
| GET | `/api/ksc/methods` | — | Machine-readable operation catalog |
| POST | `/api/ksc/session` | `Session.StartSession` | Open an authenticated session |
| GET | `/api/ksc/server-info` | `HostGroup.GetStaticInfo` | Static Administration Server attributes |
| GET | `/api/ksc/groups?limit=` | `HostGroup.FindGroups` + `ChunkAccessor.*` | Enumerate administration groups |
| GET | `/api/ksc/hosts?limit=` | `HostGroup.FindHosts` + `ChunkAccessor.*` | Enumerate managed hosts |
| GET | `/api/ksc/licenses?limit=` | `LicenseKeys.EnumKeys` + `ChunkAccessor.*` | Enumerate installed licenses |
| POST | `/api/ksc/call` | allow-listed read-only methods | Generic method proxy |

The generic `POST /api/ksc/call` proxy only accepts an allow-list of read-only/session methods (see `kscReadOnlyMethods` in `backend/ksc.go`); mutating methods (e.g. `HostGroup.RemoveHost`) are rejected with HTTP 403. Credentials live only in the backend and are sent server-side. Upstream `PxgError` and non-2xx responses are surfaced with their upstream status without leaking the configured token.

### Console vs. Administration Server note

The supplied hosted URL (`https://s405.cloud.kaspersky.com:8080`) is a KES Cloud Web Console. It answers KSC Open API calls with an OAuth-style `401 credentials_required` rather than the KSC `PxgError`/`PxgRetVal` contract, because the documented Open API is served by a KSC Administration Server (default port 13299) with the OpenAPI package installed. The backend therefore reaches upstream successfully and records the upstream authentication failure gracefully; point `KSC_BASE_URL` + `KSC_AUTHORIZATION` at a real Administration Server to retrieve live data.
