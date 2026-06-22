# Kaspersky Cloud Integration Plan

## Product boundary

The supplied workspace URL is Kaspersky Endpoint Security Cloud (KES Cloud), not an on-premises Kaspersky Security Center Administration Server. This project integrates only publicly documented cloud APIs.

Excluded:

- KSC OpenAPI `/api/v1.0/Class.Method`, because it manages a KSC Administration Server and is not a public KES Cloud customer API.
- KSC `KSCT`, `KSCWT`, `KSCNT`, and `X-KSC-Session` credentials.
- Endpoint-local Kaspersky Endpoint Security Web API, which Kaspersky documents as localhost-only and unavailable for remote management.
- Undocumented browser endpoints and session scraping.

## Implemented official cloud API surface

Kaspersky Threat Intelligence Portal API (`https://opentip.kaspersky.com/api/v1`):

1. Hash lookup: `GET /search/hash`
2. IPv4 lookup: `GET /search/ip`
3. Domain lookup: `GET /search/domain`
4. Web-address lookup: `GET /search/url`
5. Basic file analysis: `POST /scan/file`
6. File-analysis result: `POST /getresult/file`

All requests are made by the Go backend with `KASPERSKY_TIP_API_KEY`; the browser never receives the token.

## KES Cloud integrations without a public REST contract

Kaspersky officially supports product-specific MSP integrations, including ConnectWise integrations through Kaspersky Security Integration Tool for MSP. Those workflows use the vendor tool, Kaspersky account credentials, integration IDs, and workspace mappings. They do not publish a reusable REST API contract for this application to implement.

Demo TAXII feeds require a separate Demo TAXII Server Token and are intended for the Kaspersky OpenCTI connector. TAXII is not enabled by the regular Threat Intelligence API token.

## Verification

- Go unit tests and production build.
- Next.js production build.
- Backend and frontend image builds.
- Compose health checks.
- Live safe tests for every configured Threat Intelligence operation.
- Unsupported or unlicensed upstream operations must return their real safe error rather than being represented as integrated.

## Official references

- Threat Intelligence API: https://opentip.kaspersky.com/Help/Doc_data/WorkingWithAPI.htm
- Threat Intelligence full API reference: https://opentip.kaspersky.com/Help/Doc_data/all-in-one.htm?sectionUrl=URLLookupAPI.htm
- KES Cloud product documentation: https://support.kaspersky.com/Cloud/1.0/en-us/123486.htm
- KES Cloud MSP integrations: https://support.kaspersky.com/msp/integrations/141380.htm
- Local-only Endpoint Security REST limitation: https://support.kaspersky.com/kes-for-windows/12.2/189442
