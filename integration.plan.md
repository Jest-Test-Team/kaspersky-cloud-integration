# Kaspersky Cloud Integration Plan

## Goal

Integrate the Go backend and Next.js frontend with official Kaspersky APIs, with Kaspersky Threat Intelligence Portal (KTIP/OpenTIP) indicator lookup as the primary workflow and Kaspersky Security Center (KSC) Cloud Console access as a secondary, explicitly authenticated workflow.

## Verified API boundaries

- **Threat Intelligence (priority 1):** official REST base URL `https://opentip.kaspersky.com/api/v1`. Hash, IPv4, domain, and URL lookups use `GET /search/{type}?request=...` and authenticate with an `X-API-KEY` header. The token must remain server-side.
- **Security Center (priority 2):** KSC Open API uses JSON over HTTP POST at `/api/v1.0/{Class}.{Method}`. Official authentication schemes include `KSCBasic`, `KSCT`, `KSCWT`, and web-console `KSCNT`, followed by an `X-KSC-Session` session header.
- `https://s405.cloud.kaspersky.com:8080` is reachable and serves the Cloud Console UI. A valid supported KSC Open API credential/session is still required before authenticated console calls can be verified.
- The repository's existing `swagger.json` describes the endpoint-local Kaspersky Endpoint Security API on port 8021. It is retained as a legacy tool, not treated as the Cloud Console contract.

## Implementation

1. Add a typed KTIP client to the Go backend.
   - Detect and validate hash, IPv4, domain, and URL indicators.
   - Expose `POST /api/intelligence/lookup`.
   - Read `KASPERSKY_TIP_API_KEY` only on the server.
   - Apply timeouts, response-size limits, normalized errors, and no secret logging.
2. Add a constrained KSC Open API client.
   - Expose connection status and a generic method-call endpoint for documented `Class.Method` names.
   - Configure `KSC_BASE_URL=https://s405.cloud.kaspersky.com:8080` and server-side `KSC_AUTHORIZATION` / `KSC_SESSION` secrets.
   - Prevent arbitrary-host proxying and redact authentication data.
3. Replace the Swagger-first frontend home screen with a Threat Intelligence lookup dashboard.
   - Make IOC lookup the first and dominant action.
   - Show detected indicator type, Kaspersky zone/verdict, raw official response, configuration state, and KSC connection state.
   - Keep an advanced KSC method caller for administrators.
4. Add deployable containers.
   - Multi-stage backend and frontend Dockerfiles.
   - Docker Compose with health checks, internal backend-to-frontend networking, environment templates, and non-root runtime users.
5. Verification.
   - Add Go tests for indicator detection, route validation, secret handling, and upstream behavior.
   - Run `go test ./...`, `go build ./...`, and `npm run build`.
   - Build both images, start them with Compose, verify health and UI HTTP responses, then record any credential-dependent checks that remain.

## Required secrets

- `KASPERSKY_TIP_API_KEY`: generated from Kaspersky Threat Intelligence Portal's **Request token** page.
- One supported KSC credential path:
  - preferred automation path: `KSC_AUTHORIZATION=KSCT <token>`; or
  - an already established `KSC_SESSION` value; or
  - a vendor-supported Cloud Console web token flow supplied for this workspace.

Secrets must be supplied through the runtime environment or a secret manager and must never use `NEXT_PUBLIC_*`, source control, image layers, or API responses.

## Acceptance criteria

- A configured API key can look up hashes, IP addresses, domains, and URLs through the backend without exposing the key to the browser.
- Invalid indicators fail locally with HTTP 400; missing credentials return a clear configuration error; upstream errors preserve a safe status/message.
- KSC calls are limited to the configured Kaspersky origin and documented method-name format.
- Backend and frontend production builds pass.
- Both container images build and the Compose stack starts healthy.

## Official references

- KTIP API overview: https://opentip.kaspersky.com/Help/Doc_data/WorkingWithAPI.htm
- KTIP complete endpoint reference: https://opentip.kaspersky.com/Help/Doc_data/all-in-one.htm?sectionUrl=URLLookupAPI.htm
- KSC Open API 15.2 protocol and authentication: https://support.kaspersky.com/help/KSC/15.2/KSCAPI/index.html
- KSC API Reference Guide: https://support.kaspersky.com/ksc/14/en-US/211453.htm
- KSC Cloud Console help: https://support.kaspersky.com/ksc_cloudconsole
