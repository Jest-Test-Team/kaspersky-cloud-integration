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

## Why KSC has hundreds of methods but they are not listed as cloud endpoints

KSC OpenAPI is an RPC-style API with a large class/method catalog for a KSC Administration Server. Kaspersky's own reference states its client package and scripts run on a device where Administration Server and the OpenAPI package are installed. The supplied hosted URL is a KES Cloud Web Console, not that Administration Server interface. Therefore those methods are not callable cloud endpoints for this account.
