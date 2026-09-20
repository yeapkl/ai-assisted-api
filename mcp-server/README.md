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

| Tool | Wraps | Arguments |
|---|---|---|
| `check_api_health` | `GET /health` | none |
| `register_user` | `POST /api/v1/auth/register` | `username`, `password` |
| `login` | `POST /api/v1/auth/login` | `username`, `password` |
| `refresh_access_token` | `POST /api/v1/auth/refresh` | `refreshToken` |
| `get_hello_greeting` | `GET /api/v1/hello` | `accessToken` |

Every tool returns the wrapped API's JSON body as-is on success. On a
non-2xx response, it returns `{"http_status": <code>, "error": "..."}` -
the same information the REST API itself returns - rather than surfacing an
opaque MCP protocol error, so the calling agent can read and react to it
(e.g. explain *why* a login failed).

## This endpoint requires authentication

Unlike the main API, this MCP server is **not** deployed with
`--allow-unauthenticated`. Spring AI's own documentation warns that the
HTTP MCP transport exposes an unauthenticated JSON-RPC endpoint by default,
letting any caller who reaches it list and invoke every tool - so this
service requires a valid GCP identity token on every request instead. See
`docs/deploy/mcp-server-setup.md` at the repo root for how to call it
(as a human testing it, or by configuring an MCP client).

## Run locally

```bash
cd mcp-server
mvn spring-boot:run
```

By default it talks to the deployed Cloud Run instance of the main API
(`api.base-url` in `application.yml`). To point it at a locally running
copy of the main API instead:

```bash
API_BASE_URL=http://localhost:8000 mvn spring-boot:run
```

## Try it

```bash
# List available tools
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# Call a tool
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"check_api_health","arguments":{}}}'
```

(No auth needed when running locally - the identity-token requirement only
applies to the deployed Cloud Run instance, per its IAM policy.)

## Run the tests

```bash
mvn test
```

`HelloApiToolsTest` stubs the upstream API with `MockRestServiceServer` - no
real network call and no dependency on a live deployment.

## Project layout

```
src/main/java/com/apitest/mcp/
  McpServerApplication.java  - @SpringBootApplication entry point
  ApiProperties.java         - api.base-url configuration (env: API_BASE_URL)
  ApiClientConfig.java       - RestClient bean pointed at api.base-url
  HelloApiTools.java         - the 5 @McpTool methods
src/main/resources/application.yml - MCP server + api.base-url config
src/test/java/com/apitest/mcp/
  HelloApiToolsTest.java     - tool-level tests against a stubbed upstream
```
