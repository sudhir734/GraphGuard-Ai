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
2. Configure the app's secret/environment setting `GRAPHGUARD_API_URL` to the deployed API's HTTPS base URL, without a trailing path.
3. Configure `FALKORDB_HOST`, `FALKORDB_PORT`, `FALKORDB_USERNAME`, `FALKORDB_PASSWORD`, `FALKORDB_TLS`, and `FALKORDB_GRAPH=GraphGuardDemo` as Streamlit secrets/environment values **only if** the UI's direct graph-query features are required. Do not put credentials in source control.
4. Run a clean deployment smoke test; do not assume a successful build proves the graph connection works.

## Before making the URL public

- Confirm the cloud graph is a new demo instance, not the production database.
- Load only a small, known demo dataset.
- Test API health, readiness, stored-graph investigation, graph relationships, UI connectivity, and provider failure handling.
- Confirm no secrets appear in logs, API responses, screenshots, or Git history.
- Keep the demo API read-only for visitors where possible.
- Do not claim live provider enrichment is enabled while the hosted configuration disables it.

## Rollback

Disable the Render service and/or Streamlit app. The local app and production graph remain separate. Do not use graph deletion or flush commands as a rollback mechanism.
