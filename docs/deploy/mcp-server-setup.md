# MCP server deployment and access

The `mcp-server/` module (see `mcp-server/README.md`) deploys automatically
alongside the main API - **no additional one-time GCP setup is needed**
beyond what's already documented in `gcp-cloud-run-setup.md`. It reuses:

- The same Workload Identity Federation trust and `github-actions-deployer`
  service account - `roles/run.admin` is project-scoped, so it can already
  deploy this second Cloud Run service.
- The same `cloud-run-runtime` runtime identity - this server holds no
  secrets of its own (it validates OAuth access tokens issued by
  `hello-world-api`'s Authorization Server, but never issues, stores, or
  forwards a raw password or long-lived credential itself), so no new
  Secret Manager entry is needed for this module specifically.
- The same four GitHub Actions repository variables.

It's a separate deployable (`.github/workflows/mcp-ci-cd.yml`, path-filtered
to only run on changes under `mcp-server/**`), deployed to its own Cloud Run
service: `hello-world-mcp-server`.

## Access model: OAuth 2.1, not GCP IAM

**This changed in the OAuth Authorization Server revision** (see
`docs/requirements/mcp-server.md` §5, Assumption 3 for the full reasoning).
PR #4's original posture deployed this service **without**
`--allow-unauthenticated`, requiring a GCP identity token on every request,
because at that time there was no real per-end-user authentication at the
application layer at all (tool arguments carried raw passwords/tokens, and
nothing verified them cryptographically). That gap is what the OAuth
revision closes:

- `hello-world-mcp-server` is now deployed **with**
  `--allow-unauthenticated` - the Cloud Run/GCP-IAM gate is no longer the
  authorization boundary.
- Every `POST /mcp` call to the one tool that needs authentication
  (`get_hello_greeting`) is independently authenticated per end user via a
  Spring Security-validated, audience-scoped OAuth 2.1 Bearer access token
  (see `mcp-server/README.md`'s "This server is an OAuth 2.1 Resource
  Server" section) - a real, cryptographically-verified per-request check,
  not a coarse "is this GCP account allowed to invoke the service at all"
  gate.
- `check_api_health` and `register_user` remain callable with no
  `Authorization` header at all, exactly as before.
- Standard, off-the-shelf MCP clients know how to perform the MCP/OAuth 2.1
  browser-redirect (`authorization_code` + PKCE) flow and attach the
  resulting Bearer token; they do not know how to additionally mint and
  attach a GCP-specific identity token. Keeping the IAM gate would have made
  this service unreachable by any such client, defeating the point of
  implementing the standards-based OAuth flow.

This is a legitimate architectural tradeoff (stacking both would be more
defense-in-depth), not a clear-cut technical requirement - see that
Assumption for the full weighing. It was confirmed by the product owner and
recorded there rather than left as an unreviewed default.

## How a human/MCP client actually authenticates now

Authentication happens against **`hello-world-api`**, not against
`mcp-server` or GCP:

1. The MCP client (or a human testing by hand) directs a browser to
   `hello-world-api`'s `GET /oauth2/authorize?response_type=code&client_id=mcp-server&redirect_uri=...&code_challenge=...&code_challenge_method=S256&state=...`
   (PKCE is mandatory - see `docs/requirements/hello-world-api.md` NFR-18).
2. The user logs in with their existing `hello-world-api` username/password
   (the same credentials `POST /api/v1/auth/register`/`login` use - NFR-17)
   via the HTML login form `hello-world-api` now serves at `/login`.
3. `hello-world-api` redirects back to the client's `redirect_uri` with an
   authorization `code`.
4. The client exchanges that code (plus its PKCE `code_verifier` and the
   pre-registered client's secret) at `hello-world-api`'s `POST
   /oauth2/token` for an access token (audience-scoped to `mcp-server` -
   NFR-19) and a refresh token.
5. The client attaches `Authorization: Bearer <access_token>` on its
   `POST /mcp` calls to `hello-world-mcp-server` when calling
   `get_hello_greeting`. When the access token expires, the client uses the
   standard `refresh_token` grant against the same `/oauth2/token` endpoint
   to get a new one - no re-login, and no MCP tool call involved.

`hello-world-mcp-server` never issues, stores, or forwards these
credentials itself beyond validating the Bearer token on each request - see
`mcp-server/README.md` for the exact `oauth.*` configuration
(`OAUTH_ISSUER_URI`, `MCP_RESOURCE_AUDIENCE`, `MCP_SERVER_BASE_URL`) and a
full by-hand curl walkthrough.

## Calling the deployed service as a human (testing)

```bash
SERVICE_URL=$(gcloud run services describe hello-world-mcp-server \
  --region=us-central1 --format='value(status.url)')

# Unauthenticated tools work with no Authorization header at all:
curl -X POST "$SERVICE_URL/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"check_api_health","arguments":{}}}'

# get_hello_greeting needs a Bearer access token from hello-world-api's
# Authorization Server (see the OAuth flow above / hello-world-api's README
# for the full by-hand curl walkthrough of /oauth2/authorize + /oauth2/token):
curl -X POST "$SERVICE_URL/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_hello_greeting","arguments":{}}}'
```

## Connecting an MCP client (e.g. Claude Desktop/Code)

Configure the client with:

- **URL**: the Cloud Run service URL + `/mcp`
- **OAuth**: point the client at `hello-world-api`'s
  `/.well-known/oauth-authorization-server` (or let it discover this via
  `hello-world-mcp-server`'s own `/.well-known/oauth-protected-resource`,
  which names that Authorization Server - RFC 9728) so it can perform the
  `authorization_code`+PKCE flow and standard `refresh_token` renewal itself.

Most MCP clients that support the MCP Authorization spec handle this
automatically once pointed at the server URL - no manual token minting or
GCP identity-token dance required, unlike the old IAM-gated posture.

## Rolling back to the old GCP-IAM-gated posture (not recommended)

If a future reviewer decides the interoperability tradeoff isn't worth it,
revert `.github/workflows/mcp-ci-cd.yml`'s `deploy-cloud-run` job flags back
to `--no-allow-unauthenticated`, and revisit whether the smoke-test step
needs to mint a GCP identity token again for the parts of the API IAM would
now be gating a second time.
