# Run GraphGuard AI completely locally (Windows)

This is the local-only run path. It does not require a cloud account and does not publish or deploy anything.

## Requirements

- Windows 10/11
- Docker Desktop using Linux containers, started before running the script
- Python 3.10+ available as `py -3`
- Internet access only for the first Docker image build and Python dependency installation; runtime passive intelligence features need internet when you explicitly use them

## Start

1. Download/clone this repository and switch to branch `deployment/free-cloud`.
2. Open PowerShell in the repository folder.
3. Run:

   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   .\run-local.ps1
   ```

4. Open **http://127.0.0.1:8501**.

The script builds the local image, generates a random local FalkorDB password in `.local.env`, starts the API and FalkorDB in one container, waits for readiness, installs UI dependencies in `.venv`, and opens the browser.

## Local addresses

- UI: http://127.0.0.1:8501
- API health: http://127.0.0.1:8000/health
- API readiness: http://127.0.0.1:8000/health/ready
- API documentation: http://127.0.0.1:8000/docs

All service ports are bound to loopback (127.0.0.1); they are not exposed to your local network. FalkorDB's host-side port is 16379 and is also loopback-only.

## Persistence and safety

- Graph data is stored in `.local-data\`. Keep this folder if you want your data to survive container replacement or restarts.
- The generated database password is stored in `.local.env`. Do not share it or commit it.
- Both paths are ignored by Git.
- The local launcher uses a separate graph named `GraphGuardDemo`; it does not automatically import or modify the existing `GraphGuard` graph or any production dataset.
- To stop the local API/database container and the Streamlit UI, run `.\stop-local.ps1`. This does not delete graph data.
- To restart, run `.\run-local.ps1` again. The container is recreated while the `.local-data` folder remains.
- To fully remove local data, stop the service and manually delete `.local-data\`. This is destructive; export anything you need first.

## Troubleshooting

- **Docker command fails:** open Docker Desktop, wait until it says it is running, and retry.
- **Python launcher missing:** install Python 3.10+ and enable the Python Launcher (`py.exe`), then retry.
- **Port already in use:** close the application using port 8000, 8501, or 16379, then rerun.
- **API is not ready:** run `docker logs --tail 150 graphguard-local` and check the error. Do not delete `.local-data\` as a first troubleshooting step.
- **UI starts but no graph is reachable:** verify `http://127.0.0.1:8000/health/ready` reports FalkorDB status `ok`.

## Important limitation

This provides a live **local** URL on this computer, not a public internet URL. A judge on another computer cannot open your localhost address. For an offline judging setup, run it on the presentation laptop and demo it directly.
