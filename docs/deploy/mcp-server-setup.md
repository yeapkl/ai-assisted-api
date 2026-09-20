# MCP server deployment and access

The `mcp-server/` module (see `mcp-server/README.md`) deploys automatically
alongside the main API - **no additional one-time GCP setup is needed**
beyond what's already documented in `gcp-cloud-run-setup.md`. It reuses:

- The same Workload Identity Federation trust and `github-actions-deployer`
  service account - `roles/run.admin` is project-scoped, so it can already
  deploy this second Cloud Run service.
- The same `cloud-run-runtime` runtime identity - this server holds no
  secrets of its own (it only forwards whatever the caller passes as tool
  arguments to the main API), so no new Secret Manager entry is needed.
- The same four GitHub Actions repository variables.

It's a separate deployable (`.github/workflows/mcp-ci-cd.yml`, path-filtered
to only run on changes under `mcp-server/**`), deployed to its own Cloud Run
service: `hello-world-mcp-server`.

## This service requires authentication

Unlike `hello-world-api`, this is deployed **without**
`--allow-unauthenticated` - see `mcp-server/README.md` for why. Every
request needs a valid GCP identity token whose audience matches the
service's URL.

## Calling it as a human (testing)

```bash
SERVICE_URL=$(gcloud run services describe hello-world-mcp-server \
  --region=us-central1 --format='value(status.url)')

TOKEN=$(gcloud auth print-identity-token --audiences="$SERVICE_URL")

curl -X POST "$SERVICE_URL/mcp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

Identity tokens are short-lived (~1 hour) - re-run the `print-identity-token`
command to get a fresh one when it expires.

## Connecting an MCP client (e.g. Claude Desktop/Code)

Most MCP clients that support a remote HTTP server let you supply a custom
header. Configure:

- **URL**: the Cloud Run service URL + `/mcp`
- **Header**: `Authorization: Bearer <identity token>`

Since identity tokens expire hourly, this is workable for testing but not
for a long-lived client connection. For that, either:

- Have the client re-mint the token itself before each session (if it
  supports a token-refresh hook), or
- Grant a specific caller's service account `roles/run.invoker` on this
  service (`gcloud run services add-iam-policy-binding
  hello-world-mcp-server --region=us-central1
  --member="serviceAccount:<caller>@<project>.iam.gserviceaccount.com"
  --role="roles/run.invoker"`) and have that caller mint its own tokens the
  same way.

## Granting a specific person or service account access

By default, only project owners/editors (and anyone with `roles/run.admin`
or `roles/run.invoker` already) can call this service. To let a specific
Google account or service account invoke it:

```bash
gcloud run services add-iam-policy-binding hello-world-mcp-server \
  --region=us-central1 \
  --member="user:someone@example.com" \
  --role="roles/run.invoker"
```

(Use `serviceAccount:...` instead of `user:...` for a service account.)

## Rolling back to public/unauthenticated (not recommended)

If you deliberately want this endpoint public despite the exposure Spring
AI's docs describe, remove `--no-allow-unauthenticated` from
`.github/workflows/mcp-ci-cd.yml`'s `deploy-cloud-run` job and add
`--allow-unauthenticated` instead, matching the main API's job.
