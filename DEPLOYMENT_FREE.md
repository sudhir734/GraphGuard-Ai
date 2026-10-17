# GraphGuard AI — Free Cloud Deployment (Preparation)

This branch prepares a **separate demo deployment**. It does not deploy services, change `main`, or access the existing production graph.

## Architecture

- **API:** Render free web service built from `Dockerfile`.
- **Graph:** a separately provisioned FalkorDB-compatible cloud instance with TLS and authentication.
- **UI:** Streamlit Community Cloud can run `app.py` and call the Render API.
- **Data:** use a small, reproducible demo graph. Do not copy production data unless you have reviewed and approved an export and import plan.

Free tiers may sleep, have limited compute, and may not provide persistent storage. Confirm current provider terms before relying on them for a judging session.

## Render setup

1. Connect this GitHub repository to Render.
2. Select the `deployment/free-cloud` branch.
3. Use the repository Blueprint (`render.yaml`) or create a Docker web service from `Dockerfile`.
4. Configure the required secret environment variables in the Render dashboard:
   - `FALKORDB_HOST`: cloud database hostname only, no scheme or port.
   - `FALKORDB_USERNAME`: database username.
   - `FALKORDB_PASSWORD`: database password.
5. Keep `FALKORDB_TLS=true`; never disable certificate verification to work around connection failures.
6. Keep the graph name `GraphGuardDemo` so the deployment cannot accidentally point to the local production graph.
7. Check `/health` and `/health/ready` after configuration.

The API is configured to disable discovery jobs and live enrichment in the hosted environment by default. This avoids exposing unauthenticated public endpoints that can launch collection jobs or trigger provider traffic. Do not enable these operations publicly until an authentication and rate-limiting plan is implemented.

## Streamlit Community Cloud

1. Create a Streamlit Community Cloud app from branch `deployment/free-cloud`, main file `app.py`.
2. In the app's Streamlit Cloud settings, add only these values under **Secrets** in TOML format:
   ```toml
   GRAPHGUARD_API_URL = "https://YOUR-RENDER-SERVICE.onrender.com"
   GRAPHGUARD_PUBLIC_DEMO = "true"
   ```
   Replace the API URL with your actual Render URL. **Do not add FalkorDB credentials to Streamlit Secrets.** In public-demo mode the UI routes investigations through the API and disables direct Cypher execution and direct database probes. Keep the database credentials only in the Render service environment.
3. Run a clean deployment smoke test; do not assume a successful build proves the graph connection works.

## Before making the URL public

- Confirm the cloud graph is a new demo instance, not the production database.
- Load only a small, known demo dataset.
- Test API health, readiness, stored-graph investigation, graph relationships, UI connectivity, and provider failure handling.
- Confirm no secrets appear in logs, API responses, screenshots, or Git history.
- Keep the demo API read-only for visitors where possible.
- Do not claim live provider enrichment is enabled while the hosted configuration disables it.

## Rollback

Disable the Render service and/or Streamlit app. The local app and production graph remain separate. Do not use graph deletion or flush commands as a rollback mechanism.


## Experimental no-card host: Blitz Cloud (not yet validated)

The following is a **candidate only** for evaluation. No Blitz app has been created and this repository has not been deployed there. Do not use it for the judging URL until the image builds and passes the smoke tests below.

- `Dockerfile.blitz` is an experimental single-container image based on the official `falkordb/falkordb-server` image.
- `blitz-start.sh` starts FalkorDB bound to `127.0.0.1:6379` only, enables a required password and AOF persistence, then starts the FastAPI service on the host-provided `PORT`.
- Configure the host's persistent folder/volume to mount at `/var/lib/falkordb/data`. A folder that survives a container restart is not a backup; export and store backups separately.
- Configure `FALKORDB_PASSWORD` as a strong secret in the host's encrypted environment settings. Never place it in the repository or Streamlit secrets.
- This single-container mode intentionally uses `FALKORDB_TLS=false` only for the loopback connection inside the same container. The database port must not be exposed by the hosting platform; public traffic must terminate at the platform's HTTPS proxy and reach FastAPI only.
- Use `GRAPHGUARD_GRAPH=GraphGuardDemo`, and keep discovery, live enrichment, and the audit API disabled.

### Required validation before any deployment

1. Build the image locally with Docker using `docker build -f Dockerfile.blitz -t graphguard-blitz-test .`.
2. Run it with a local test password and a host directory mounted at `/var/lib/falkordb/data`; expose only the API port.
3. Verify `GET /health`, `GET /health/ready`, and a stored-graph investigation using synthetic demo data.
4. Stop and restart the container with the same mounted directory; verify the graph data remains available.
5. Confirm FalkorDB is not reachable from outside the container and that the API does not return secrets.
6. Check the hosting provider's current free-plan limits for persistent storage, container memory, sleeping, bandwidth, and account/card requirements before creating any app.

If the upstream image does not include the expected module/server utilities, or if the host does not provide persistent folders on its no-card free plan, **stop** and revise the approach instead of deploying an untested image. The existing Render preparation files are retained as a separate fallback.
