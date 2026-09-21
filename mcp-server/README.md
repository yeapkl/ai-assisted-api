# Hello World MCP Server

An [MCP](https://modelcontextprotocol.io) server that wraps the
[Authenticated Hello World API](../README.md) as tools an AI agent can call
directly in a conversation, instead of a developer writing HTTP client code
against it. Same backend, same auth/rate-limiting/JWT logic - this is a thin
translation layer, not a second copy of the business logic.

Built with [Spring AI's MCP Server Boot Starter](https://docs.spring.io/spring-ai/reference/api/mcp/mcp-server-boot-starter-docs.html)
(`spring-ai-starter-mcp-server-webmvc`), Spring Boot 4.1.0 / Java 21,
Streamable-HTTP transport in **stateless** mode (no session pinned to a
specific instance - required for a scale-to-zero, multi-instance platform
like Cloud Run).

## Tools exposed

| Tool | Wraps | Arguments | Auth required |
|---|---|---|---|
| `check_api_health` | `GET /health` | none | No |
| `register_user` | `POST /api/v1/auth/register` | `username`, `password` | No |
| `get_hello_greeting` | `GET /api/v1/hello` | none | Yes - valid, audience-scoped OAuth access token |

Every tool returns the wrapped API's JSON body as-is on success. On a
non-2xx response, it returns `{"http_status": <code>, "error": "..."}` -
the same information the REST API itself returns - rather than surfacing an
opaque MCP protocol error, so the calling agent can read and react to it.

The `login` and `refresh_access_token` tools from the original PR #4 build
have been **removed**. Authentication and token refresh now happen via the
standard OAuth 2.1 `authorization_code`+PKCE browser-redirect flow and
`refresh_token` grant against `hello-world-api`'s `/oauth2/authorize` and
`/oauth2/token` endpoints, handled by the MCP client library at connection
time - never as an LLM-visible tool call, and no password/token ever passes
through the calling LLM's own context. See
`docs/requirements/mcp-server.md` for the full rationale.

## This server is an OAuth 2.1 Resource Server

`get_hello_greeting` requires a valid Bearer access token issued by
`hello-world-api`'s Authorization Server, with an `aud` (audience) claim
naming `mcp-server` specifically (RFC 8707) - a token issued for some other
resource, an expired/tampered/self-signed token, or no token at all is
rejected with HTTP `401` and a `WWW-Authenticate` header pointing at this
server's own `/.well-known/oauth-protected-resource` (RFC 9728), so a
compliant MCP client can discover how to obtain a valid token. Because
every MCP tool is multiplexed behind the single `POST /mcp` JSON-RPC
endpoint, this per-tool enforcement happens in
`com.apitest.mcp.security.McpToolAuthorizationFilter`, which inspects the
JSON-RPC `tools/call` request to decide whether a token is required, then
delegates the actual verification to Spring Security's `JwtDecoder` - see
that class's Javadoc for why a URL-based Spring Security filter chain alone
can't express this.

`check_api_health` and `register_user` remain reachable with **no**
`Authorization` header at all, unchanged from PR #4's behavior.

### Deployment: `--allow-unauthenticated`

Unlike PR #4's original posture, this service is now deployed **with**
`--allow-unauthenticated` at the Cloud Run/GCP-IAM layer - the OAuth 2.1
resource-server check above is the sole authorization boundary at the
application layer. This is a deliberate, confirmed product decision (see
`docs/requirements/mcp-server.md` §5, Assumption 3), not an oversight: a
GCP identity-token gate would make this service unreachable by any
standard, off-the-shelf MCP client (which know how to perform the MCP/OAuth
browser-redirect flow, not how to additionally mint a GCP-specific
identity token). See `docs/deploy/mcp-server-setup.md` for the full
reasoning and how to call the deployed service.

## Run locally

Requires a locally running `hello-world-api` (see the repo root README) with
its OAuth Authorization Server enabled (`OAUTH_SIGNING_KEY_SECRET` and
`MCP_OAUTH_CLIENT_SECRET` set - see that module's `.env.example`).

```bash
cd mcp-server
API_BASE_URL=http://localhost:8000 \
OAUTH_ISSUER_URI=http://localhost:8000 \
MCP_RESOURCE_AUDIENCE=mcp-server \
MCP_SERVER_BASE_URL=http://localhost:8080 \
mvn spring-boot:run
```

By default (no env vars set) it talks to the deployed Cloud Run instances of
both services.

## Try it: full OAuth flow by hand

An MCP client normally drives the browser-redirect OAuth flow itself. To
exercise it by hand with curl (useful for local testing):

```bash
# 0. Register a user and generate a PKCE pair (see hello-world-api's own
#    README for the full curl-by-hand walkthrough of /oauth2/authorize and
#    /oauth2/token).

# 1. Unauthenticated tools still work with no Authorization header:
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"check_api_health","arguments":{}}}'

# 2. get_hello_greeting with no/bad token -> HTTP 401 + WWW-Authenticate,
#    not a bare MCP-level error:
curl -i -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_hello_greeting","arguments":{}}}'

# 3. get_hello_greeting with a valid, audience-scoped access token (from
#    step 0's /oauth2/token exchange):
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_hello_greeting","arguments":{}}}'

# 4. Discover this server's protected-resource metadata (unauthenticated):
curl http://localhost:8080/.well-known/oauth-protected-resource
```

## Run the tests

```bash
mvn test
```

`HelloApiToolsTest` stubs the upstream API with `MockRestServiceServer` and
sets an authenticated `JwtAuthenticationToken` into `SecurityContextHolder`
directly - no real network call, no dependency on a live deployment, and no
need to run a full OAuth flow just to unit-test the tool wrapper.

## Project layout

```
src/main/java/com/apitest/mcp/
  McpServerApplication.java  - @SpringBootApplication entry point
  ApiProperties.java         - api.base-url configuration (env: API_BASE_URL)
  ApiClientConfig.java       - RestClient bean pointed at api.base-url
  HelloApiTools.java         - the 3 @McpTool methods
  security/
    OAuthResourceServerProperties.java - oauth.* config (issuer-uri, resource-audience, resource-base-url)
    JwtDecoderConfig.java              - JwtDecoder bean (issuer-uri discovery + audience validator)
    AudienceValidator.java             - NFR-4's custom OAuth2TokenValidator<Jwt>
    McpToolAuthorizationFilter.java    - per-tool auth enforcement for POST /mcp
    CachedBodyHttpServletRequest.java  - lets the request body be read twice
    McpAuthenticationEntryPoint.java   - 401 + WWW-Authenticate response
    ProtectedResourceMetadataController.java - GET /.well-known/oauth-protected-resource
    SecurityConfig.java                - the SecurityFilterChain wiring it all together
src/main/resources/application.yml - MCP server + api.base-url + oauth.* config
src/test/java/com/apitest/mcp/
  HelloApiToolsTest.java     - tool-level tests against a stubbed upstream
```
