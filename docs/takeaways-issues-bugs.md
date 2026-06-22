# Takeaways, Issues, and Bugs

## Takeaways

1. “Kaspersky cloud” names several unrelated products. Product identity must be established before choosing an authentication scheme.
2. The supplied URL reports **Kaspersky Endpoint Security Cloud**. `KSCWT`, `KSCNT`, `KSCT`, and `X-KSC-Session` belong to KSC OpenAPI workflows and cannot be generated from this KES Cloud console.
3. The standard KTIP token exposes six documented REST operations. Rich result objects do not imply additional endpoints; domain responses can contain WHOIS, categories, and zone data in one call.
4. KSC OpenAPI contains hundreds of RPC methods, but that surface is for an Administration Server, not this hosted KES Cloud account.

## Cloud workspace API authentication (empirically verified)

The workspace `https://s405.cloud.kaspersky.com` exposes its management API on the `:8080` gateway under `/api/v1.0/Class.Method` — the same KSC Open API shape this backend integrates. Every auth scheme was tested against the live gateway:

| Sent to the gateway | Result |
|---|---|
| `Authorization: Bearer <jwt>` | `401 credentials_required` (header ignored) |
| `Authorization: KSCBasic user/pass` | `401 credentials_required` (header ignored) |
| `X-KSC-Session: <id>` | `401 credentials_required` (header ignored) |
| **`Cookie: access_token=<jwt>`** | **token read & validated** (`401 invalid_token / jwt expired` with a stale token) |

**Conclusions:**

1. The gateway's `express-jwt` layer reads the JWT only from the **`access_token` cookie**. The JWT payload is `{userId, iat, exp}` with a ~1-hour lifetime.
2. The `access_token` is **not minted by `s405:8080`** — there is no username/password login endpoint there (all `/api/v1.0/login|auth|token` paths sit behind the same JWT middleware). It is issued by Kaspersky's central **My Kaspersky / `cloud.kaspersky.com`** OAuth flow, which is CAPTCHA/anti-bot/MFA protected.
3. Therefore a backend account+password→token auto-login **cannot work for the cloud console** (only for a real on-prem KSC Administration Server). Scripting the central login is fragile and against Kaspersky ToS.
4. The supported automation credential for the cloud workspace is a **fresh `access_token` cookie** (`KSC_ACCESS_TOKEN`), refreshed ~hourly from an authenticated browser session.

The backend implements `KSCBasic` auto-login (`KSC_LOGIN`/`KSC_PASSWORD` → `Session.StartSession` → cached session token, auto re-login on 401) for real KSC servers, plus the `KSC_ACCESS_TOKEN` cookie path for the cloud console.

## Known issues and vendor behavior

### KTIP URL lookup returns HTTP 400

- **Observed:** `GET /api/v1/search/url` returns HTTP 400 for valid public HTTP(S) URLs with the configured token, while hash, IPv4, and domain lookups succeed.
- **Application behavior:** the backend returns HTTP 502 with `upstreamStatus: 400`; it does not convert the failure into a false verdict.
- **Coverage:** the Robot test executes this integration and accepts only either the documented HTTP 200 response or this exact known vendor failure.
- **Next action:** confirm URL-lookup entitlement/quota with Kaspersky support and provide the request timestamp. No alternate undocumented endpoint should be used.

### File analysis is asynchronous

Basic analysis may omit sections while Sandbox processing continues. Retrieve the full report by hash later. Automation must not assume the first response is complete.

### Quota and privacy

Live tests consume KTIP quota. File submissions leave the local trust boundary and must never contain confidential data.

## Resolved implementation/test bugs

- Robot initially parsed curl's `%{http_code}` as a Robot environment variable. The percent sign is now escaped.
- Robot initially parsed curl's multipart `file=@...` argument as a named keyword argument. The equals sign is now escaped.
- Go contract tests initially used a loopback `httptest` listener, which is incompatible with restricted CI sandboxes. They now use an injected in-memory HTTP transport and require no listening socket.

## Security decisions

- The API key remains backend-only.
- Upstream response bodies are capped at 4 MiB and error details at 500 characters.
- Uploads are capped at Kaspersky's documented 256 MiB limit.
- Inputs are restricted to documented hash, IPv4, domain, URL, and file forms.
- Private Web Console endpoints and session scraping are intentionally excluded.
