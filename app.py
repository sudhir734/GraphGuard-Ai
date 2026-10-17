
import html
import json
import os
from datetime import datetime

import requests
import streamlit as st
import streamlit.components.v1 as components

from api_destination import validate_api_base_url

# ==========================================================
# GRAPHGUARD AI — INTERACTIVE EVIDENCE INVESTIGATION
# ==========================================================

st.set_page_config(
    page_title="GraphGuard AI | Evidence Investigation",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded",
)

try:
    API_BASE_URL = validate_api_base_url(os.getenv(
        "GRAPHGUARD_API_URL",
        "http://127.0.0.1:8000",
    ))
    API_CONFIG_ERROR = None
except ValueError as exc:
    API_BASE_URL = None
    API_CONFIG_ERROR = str(exc)


def esc(value):
    return html.escape(str(value if value is not None else "—"))


def safe_json(value):
    # Avoid accidentally terminating an embedded script element.
    return json.dumps(value, ensure_ascii=True).replace("</", "<\\/")


def confidence_display(value):
    if value is None:
        return "Not supplied"

    try:
        number = float(value)
    except (TypeError, ValueError):
        return f"Uninterpreted value: {value}"

    if 0 <= number <= 1:
        return f"{number:.0%} supplied score"
    if 0 <= number <= 100:
        return f"{number:g}/100 supplied score"

    return f"{number:g} supplied score"


st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');

    :root {
        --bg:#080b10; --panel:#0e141d; --line:#263342;
        --text:#eaf0f8; --muted:#8a99ac;
        --lime:#c4f36b; --cyan:#63d9f5; --amber:#ffc66d;
    }
    html, body, [class*="css"] {font-family:Manrope,sans-serif;}
    .stApp {
        background:radial-gradient(ellipse at 85% -10%,#17343a 0%,transparent 36%),#080b10;
        color:var(--text);
    }
    [data-testid="stSidebar"] {background:#0a0e14;border-right:1px solid var(--line);}
    .block-container {max-width:1600px;padding-top:1.6rem;padding-bottom:3rem;}
    .mono {font-family:'DM Mono',monospace;}
    .brand {display:flex;align-items:center;gap:12px;padding:5px 0 22px;}
    .mark {
        background:var(--lime);color:#10170b;border-radius:12px;
        width:43px;height:43px;display:flex;align-items:center;
        justify-content:center;font-size:25px;font-weight:800;
    }
    .brand-name {font-weight:800;letter-spacing:.13em;font-size:16px;}
    .muted {color:var(--muted);font-size:12px;line-height:1.8;}
    .eyebrow {font-family:'DM Mono',monospace;color:var(--lime);
        font-size:10px;letter-spacing:.14em;text-transform:uppercase;}
    .hero {
        padding:30px;border:1px solid #2a3b43;border-radius:20px;
        background:radial-gradient(circle at 90% 10%,#27483a30,transparent 34%),#101720;
        margin-bottom:24px;
    }
    .hero h1 {font-size:clamp(30px,4vw,47px);line-height:1.12;
        letter-spacing:-.05em;margin:13px 0;font-weight:800;color:var(--text);}
    .hero h1 span {color:var(--lime);}
    .hero-copy {color:#a4b1c1;max-width:730px;font-size:13px;line-height:1.9;}
    .chips {display:flex;gap:8px;flex-wrap:wrap;margin-top:20px;}
    .chip {border:1px solid #30404a;border-radius:30px;padding:7px 10px;
        color:#b9c8d4;font:10px 'DM Mono',monospace;}
    .section {margin:25px 0 12px;color:#a2b0c0;
        font:11px 'DM Mono',monospace;letter-spacing:.12em;text-transform:uppercase;}
    .panel {border:1px solid var(--line);border-radius:14px;
        background:linear-gradient(140deg,#111925,#0c1118);padding:17px;margin-bottom:12px;}
    .panel-title {font-size:14px;font-weight:800;color:#edf3fa;margin-bottom:6px;}
    .panel-copy {font-size:12px;color:var(--muted);line-height:1.8;}
    .metric {border:1px solid var(--line);border-radius:13px;
        padding:16px;background:#101721;min-height:92px;}
    .metric-label {font:10px 'DM Mono',monospace;color:var(--muted);
        text-transform:uppercase;letter-spacing:.1em;}
    .metric-value {font-size:25px;font-weight:800;margin-top:10px;overflow-wrap:anywhere;}
    .metric-note {font-size:10px;color:var(--muted);margin-top:4px;}
    .evidence {border:1px solid #263342;background:#0d131b;
        border-radius:12px;padding:15px;margin:10px 0;overflow-wrap:anywhere;}
    .field-label {font:9px 'DM Mono',monospace;letter-spacing:.1em;
        color:#7f90a5;text-transform:uppercase;margin-top:10px;}
    .field-value {font-size:12px;color:#e4edf6;margin-top:4px;font-weight:600;}
    .tag {display:inline-block;border:1px solid #34434e;border-radius:6px;
        padding:4px 7px;font:10px 'DM Mono',monospace;color:var(--cyan);}
    .caution {border:1px solid #57442b;background:#ffc66d0d;color:#d9c6a5;
        border-radius:10px;padding:13px;font-size:12px;line-height:1.8;margin:12px 0;}
    .empty {padding:30px;text-align:center;border:1px dashed #2c3a49;
        border-radius:12px;background:#0b1017;color:var(--muted);font-size:12px;line-height:1.8;}
    [data-testid="stForm"] {border:1px solid var(--line);border-radius:13px;background:#0d131b;padding:17px;}
    .stTextInput input {background:#080d13!important;color:#edf3fa!important;
        border:1px solid #2b3948!important;border-radius:8px!important;}
    .stFormSubmitButton button {background:var(--lime)!important;color:#10170b!important;
        border:0!important;border-radius:8px!important;font-weight:800!important;}
    .stButton button {border:1px solid #30404a;border-radius:8px;
        background:#111923;color:#eaf0f8;}
    [data-testid="stExpander"] {border:1px solid var(--line);border-radius:10px;background:#0d131b;}
    hr {border-color:var(--line);}
    footer {visibility:hidden;}
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------- STATE ---------------------------

if "result" not in st.session_state:
    st.session_state.result = None
if "history" not in st.session_state:
    st.session_state.history = []
if "last_domain" not in st.session_state:
    st.session_state.last_domain = ""
if "error" not in st.session_state:
    st.session_state.error = None


# --------------------------- SIDEBAR -------------------------

with st.sidebar:
    st.markdown(
        """
        <div class="brand">
          <div class="mark">◈</div>
          <div>
            <div class="brand-name">GRAPHGUARD</div>
            <div class="muted">THREAT INVESTIGATION SYSTEM</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="eyebrow">Connection settings</div>',
                unsafe_allow_html=True)

    if API_BASE_URL:
        st.caption(f"FastAPI: {API_BASE_URL}")
    else:
        st.error(API_CONFIG_ERROR)

    api_online = False
    graph_online = False
    if API_BASE_URL:
        try:
            health = requests.get(
                f"{API_BASE_URL}/health",
                timeout=3,
                allow_redirects=False,
            )
            health.raise_for_status()
            health_data = health.json()
            api_online = health_data.get("status") == "ok"
            graph_online = (
                health_data.get("falkordb", {}).get("status") == "ok"
            )
        except (requests.RequestException, ValueError):
            api_online = False

    if api_online:
        st.success("Backend API reachable")
        if graph_online:
            st.caption("FalkorDB reachable")
        else:
            st.warning("Backend is reachable, but FalkorDB is unavailable.")
    else:
        st.error("Backend API unavailable")

    st.markdown("---")
    st.markdown('<div class="eyebrow">Analysis principles</div>',
                unsafe_allow_html=True)
    st.markdown(
        """
        <div class="panel">
          <div class="panel-title">Graph-backed</div>
          <div class="panel-copy">Entities and edges come from the backend graph query.</div>
        </div>
        <div class="panel">
          <div class="panel-title">Evidence-first</div>
          <div class="panel-copy">A connected relationship is not proof of maliciousness.</div>
        </div>
        <div class="panel">
          <div class="panel-title">Provenance-aware</div>
          <div class="panel-copy">Missing sources and confidence values remain explicitly unknown.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.caption("SynapGraph · Track 1 · Demo build 1.0")


# ---------------------------- HERO ---------------------------

st.markdown(
    """
    <div class="hero">
      <div class="eyebrow">◈ Evidence intelligence / Graph investigation</div>
      <h1>See the connections.<br><span>Inspect the evidence.</span></h1>
      <div class="hero-copy">
        Explore graph relationships and examine the provenance and limitations
        of each returned record. GraphGuard helps organize evidence; it does
        not declare a target malicious merely because it is connected.
      </div>
      <div class="chips">
        <span class="chip">INTERACTIVE GRAPH</span>
        <span class="chip">EVIDENCE INSPECTOR</span>
        <span class="chip">PROVENANCE</span>
        <span class="chip">UNCERTAINTY-AWARE</span>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# -------------------- GLOBAL DISCOVERY & METRICS -------------

st.markdown('<div class="section">01 / Global discovery & metrics</div>',
            unsafe_allow_html=True)

with st.expander("◈ Global Discovery Pipeline & Infrastructure Metrics", expanded=False):
    metrics_data = None
    if API_BASE_URL and api_online:
        try:
            m_resp = requests.get(f"{API_BASE_URL}/discovery/metrics", timeout=5)
            if m_resp.status_code == 200:
                metrics_data = m_resp.json()
        except Exception:
            metrics_data = None

    if metrics_data:
        def _fmt(val):
            if isinstance(val, int):
                return f"{val:,}"
            return "—" if val is None else str(val)

        graph_m = metrics_data.get("graph", {})
        disc_m = metrics_data.get("discovery_repository", {})

        total_d = graph_m.get("total_domains", metrics_data.get("total_domains_in_graph"))
        investigated_d = graph_m.get("investigated_domains", metrics_data.get("investigated_domains"))
        awaiting_d = disc_m.get("awaiting_enrichment", metrics_data.get("awaiting_investigation"))
        sources_cnt = graph_m.get("unique_sources", metrics_data.get("unique_sources_used"))

        ips_cnt = graph_m.get("total_ips", metrics_data.get("associated_ip_addresses"))
        certs_cnt = graph_m.get("total_certificates", metrics_data.get("associated_certificates"))
        reps_cnt = graph_m.get("total_reports", metrics_data.get("associated_threat_reports"))
        repo_total = disc_m.get("total_discovered", metrics_data.get("staged_in_sqlite"))

        st.caption("◈ **FalkorDB Global Graph Baseline** (Active Production Dataset)")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Graph Total Domains", _fmt(total_d), help="Total domain nodes currently stored in the FalkorDB GraphGuard graph")
        c2.metric("Investigated Domains", _fmt(investigated_d), help="Domains with stored passive observations in the graph")
        c3.metric("Awaiting Investigation", _fmt(awaiting_d), help="Domains imported into graph awaiting passive observation collection")
        c4.metric("Unique Sources", _fmt(sources_cnt), help="Distinct passive intelligence sources linked in the graph")

        st.caption("◈ **Global Infrastructure Entities & Staged Repository**")
        c5, c6, c7, c8 = st.columns(4)
        c5.metric("Global Graph IPs", _fmt(ips_cnt), help="Total distinct IP address nodes across all records in the graph")
        c6.metric("Global Graph Certificates", _fmt(certs_cnt), help="Total distinct TLS Certificate nodes across all records in the graph")
        c7.metric("Global Threat Reports", _fmt(reps_cnt), help="Total threat report nodes across all records in the graph")
        c8.metric("Staged Candidates (SQLite)", _fmt(repo_total), help="Unique candidate domains staged in local SQLite repository from Tranco (10k imported to graph)")
    else:
        st.info("Discovery metrics available when backend API is reachable.")

    st.markdown("---")
    st.markdown("**Run Incremental Passive Discovery**")
    st.caption("Expand infrastructure from seed domains using passive Certificate Transparency, DNS-over-HTTPS, and RDAP.")

    with st.form("discovery_run_form", clear_on_submit=False):
        seed_input = st.text_input(
            "Seed Domains (comma or space-separated)",
            placeholder="e.g. example.com, test.org",
        )
        col_scope, col_depth, col_budget = st.columns(3)
        with col_scope:
            scope_input = st.text_input(
                "Scope Restriction (optional)",
                placeholder="e.g. example.com",
                help="Only discover subdomains within this apex domain.",
            )
        with col_depth:
            run_depth = st.selectbox("Max Depth", options=[1, 2], index=0)
        with col_budget:
            run_budget = st.slider("Max Domains Budget", min_value=10, max_value=100, value=30, step=10)

        enrich_cb = st.checkbox("Enrich Discovered Domains with Passive Intel", value=True)
        disc_submitted = st.form_submit_button("◈ LAUNCH PASSIVE DISCOVERY", use_container_width=True)

    if disc_submitted:
        seeds = [s.strip().lower() for s in seed_input.replace(",", " ").split() if s.strip()]
        if not seeds:
            st.warning("Enter at least one valid seed domain.")
        else:
            try:
                scope_val = scope_input.strip().lower() if scope_input.strip() else None
                with st.spinner("Dispatching discovery job to backend..."):
                    d_resp = requests.post(
                        f"{API_BASE_URL}/discovery/run",
                        json={
                            "seeds": seeds,
                            "max_depth": run_depth,
                            "max_domains": run_budget,
                            "scope": scope_val,
                            "enrich_discovered": enrich_cb,
                            "delay": 0.3,
                            "background": True,
                        },
                        timeout=10,
                    )
                    d_resp.raise_for_status()
                    job_info = d_resp.json()
                    st.success(f"Discovery job dispatched! Status: {job_info.get('status', 'RUNNING')}")
            except Exception as exc:
                st.error(f"Failed to start discovery: {exc}")

    # Job Status display
    if API_BASE_URL and api_online:
        try:
            status_resp = requests.get(f"{API_BASE_URL}/discovery/status", timeout=3)
            if status_resp.status_code == 200:
                job_status = status_resp.json()
                if job_status.get("status") in {"RUNNING", "COMPLETED", "FAILED"}:
                    disc_cnt = job_status.get("discovered_count", job_status.get("discovered", 0))
                    enr_cnt = job_status.get("enriched_count", job_status.get("enriched", 0))
                    raw_errs = job_status.get("errors", [])
                    err_cnt = len(raw_errs) if isinstance(raw_errs, list) else int(raw_errs)
                    st.caption(
                        f"Active Job Status: **{job_status.get('status')}** · "
                        f"Discovered: {disc_cnt:,} · "
                        f"Enriched: {enr_cnt:,} · "
                        f"Errors: {err_cnt:,}"
                    )
        except Exception:
            pass


# ----------------------- TARGET SEARCH -----------------------

st.markdown('<div class="section">02 / Target investigation</div>',
            unsafe_allow_html=True)

with st.form("investigation", clear_on_submit=False):
    domain_input = st.text_input(
        "Domain",
        value=st.session_state.last_domain,
        placeholder="Enter a domain name",
    )
    limit_col, depth_col = st.columns(2)
    with depth_col:
        max_depth = st.select_slider(
            "Maximum graph depth",
            options=[1, 2, 3],
            value=2,
            help="Graph traversal is capped at three relationships.",
        )
    with limit_col:
        max_entities = st.slider(
            "Maximum entities",
            min_value=1,
            max_value=200,
            value=100,
            step=1,
        )
    live_enrichment = st.checkbox(
        "◈ Run Live Passive Enrichment (query DNS, RDAP & CT if unindexed or re-enriching)",
        value=False,
        help="When checked, performs safe passive intelligence collection (DNS DoH, RDAP, CT) before querying FalkorDB.",
    )
    submitted = st.form_submit_button(
        "◈  INVESTIGATE DOMAIN",
        use_container_width=True,
    )

if submitted:
    domain = domain_input.strip().lower()
    st.session_state.error = None

    if not domain:
        st.session_state.error = "Enter a domain first."
    elif any(char.isspace() for char in domain):
        st.session_state.error = "A domain must not contain spaces."
    else:
        try:
            with st.spinner("Querying FalkorDB through the API..."):
                if not API_BASE_URL:
                    raise ValueError(API_CONFIG_ERROR)
                response = requests.post(
                    f"{API_BASE_URL}/investigate",
                    json={
                        "domain": domain,
                        "max_depth": max_depth,
                        "max_entities": max_entities,
                        "live_enrichment": live_enrichment,
                    },
                    timeout=30,
                    allow_redirects=False,
                )
                response.raise_for_status()
                result = response.json()

            st.session_state.result = result
            st.session_state.last_domain = domain
            st.session_state.history.insert(
                0,
                {
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "domain": domain,
                    "found": bool(result.get("found")),
                    "records": len(result.get("evidence", [])),
                },
            )
            st.session_state.history = st.session_state.history[:20]

        except requests.HTTPError as exc:
            status_code = (
                exc.response.status_code if exc.response is not None else "?"
            )
            detail = None
            if exc.response is not None:
                try:
                    detail = exc.response.json().get("detail")
                except (ValueError, AttributeError):
                    detail = None

            if isinstance(detail, str):
                st.session_state.error = detail
            elif isinstance(detail, list):
                messages = [
                    item.get("msg")
                    for item in detail
                    if isinstance(item, dict) and item.get("msg")
                ]
                st.session_state.error = (
                    "; ".join(messages)
                    if messages
                    else f"API returned HTTP {status_code}."
                )
            else:
                st.session_state.error = (
                    f"API returned HTTP {status_code}. Check backend availability."
                )
            st.session_state.result = None
        except requests.Timeout:
            st.session_state.error = "The API timed out. Check the backend."
            st.session_state.result = None
        except requests.ConnectionError:
            st.session_state.error = (
                "Could not reach the API. Check the URL, server, and firewall."
            )
            st.session_state.result = None
        except (requests.RequestException, ValueError) as exc:
            st.session_state.error = f"Could not process API response: {exc}"
            st.session_state.result = None

if st.session_state.error:
    st.error(st.session_state.error)


# ----------------------- RESULT WORKSPACE --------------------

st.markdown('<div class="section">03 / Evidence workspace</div>',
            unsafe_allow_html=True)

result = st.session_state.result

if result is None:
    st.markdown(
        '<div class="empty">Awaiting investigation.<br>'
        'Submit a domain above to load its graph and evidence.</div>',
        unsafe_allow_html=True,
    )
else:
    nodes = result.get("nodes") or []
    edges = result.get("edges") or []
    evidence = result.get("evidence") or []
    found = bool(result.get("found"))

    origin = result.get("data_origin", "STORED_GRAPH")
    if origin == "LIVE_PASSIVE":
        st.success("🟢 **DATA ORIGIN: LIVE PASSIVE FETCH** — Live network collection (DNS DoH, RDAP, CT) executed and synchronized with FalkorDB.")
    else:
        st.info("⚡ **DATA ORIGIN: FALKORDB STORED GRAPH** — Fast local graph index traversal. No live network requests were made.")

    m1, m2, m3, m4 = st.columns(4)

    metrics = [
        ("Target", result.get("domain", "—"), "Requested domain"),
        ("Graph nodes", len(nodes), "Actual returned entities"),
        ("Relationships", len(edges), "Actual returned edges"),
        ("Evidence records", len(evidence), "Backend response"),
    ]

    for column, (label, value, note) in zip([m1, m2, m3, m4], metrics):
        with column:
            st.markdown(
                f"""
                <div class="metric">
                  <div class="metric-label">{esc(label)}</div>
                  <div class="metric-value">{esc(value)}</div>
                  <div class="metric-note">{esc(note)}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("")

    if not found:
        st.warning(
            "No matching domain was found. This does not mean the domain is safe."
        )

    graph_col, detail_col = st.columns([1.65, 1], gap="large")

    with graph_col:
        st.markdown(
            """
            <div class="panel">
              <div class="panel-title">Relationship graph</div>
              <div class="panel-copy">
                Select a node to inspect its properties. Arrows and edge labels
                represent the relationships returned by the backend.
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if nodes:
            # Create graph objects without altering the underlying topology.
            vis_nodes = []
            for node in nodes:
                node_type = str(node.get("type", "Entity"))
                props = node.get("properties") or {}

                vis_nodes.append({
                    "id": str(node["id"]),
                    "label": str(node.get("label", node_type)),
                    "group": node_type,
                    "title": (
                        f"{node_type}\\n"
                        + "\\n".join(
                            f"{key}: {value}"
                            for key, value in props.items()
                        )
                    ),
                    "properties": props,
                    "labels": node.get("labels", []),
                })

            vis_edges = [
                {
                    "id": str(edge["id"]),
                    "from": str(edge["from"]),
                    "to": str(edge["to"]),
                    "label": str(edge.get("label", "")),
                    "arrows": edge.get("arrows", "to"),
                    "font": {
                        "color": "#b5c4d4",
                        "size": 11,
                        "background": "#0b1119",
                        "strokeWidth": 0,
                    },
                }
                for edge in edges
                if edge.get("from") is not None
                and edge.get("to") is not None
            ]

            graph_payload = safe_json({
                "nodes": vis_nodes,
                "edges": vis_edges,
            })

            graph_html = """
            <!doctype html>
            <html>
            <head>
              <meta charset="utf-8">
              <style>
                * { box-sizing: border-box; }
                body {
                  margin:0; padding:0; background:#0a0f16; color:#eaf0f8;
                  font-family:Arial,sans-serif;
                }
                #graph {
                  height:440px; width:100%; border:1px solid #263342;
                  border-radius:12px; background:#0b1119;
                }
                #inspector {
                  margin-top:10px; border:1px solid #263342;
                  border-radius:10px; background:#0e151e; padding:14px;
                  overflow-wrap:anywhere;
                }
                .eyebrow {
                  color:#c4f36b; font-size:10px; letter-spacing:1.5px;
                  font-family:monospace; text-transform:uppercase;
                }
                .title { font-size:16px; font-weight:bold; margin:8px 0; }
                .muted { color:#8a99ac; font-size:12px; line-height:1.6; }
                .key { color:#8092a8; font-size:10px; text-transform:uppercase;
                  letter-spacing:1px; margin-top:11px; }
                .val { color:#e5edf7; font-size:12px; margin-top:4px;
                  white-space:pre-wrap; overflow-wrap:anywhere; }
                .legend { display:flex; gap:12px; flex-wrap:wrap;
                  color:#a8b7c8; font-size:11px; padding:11px 2px; }
                .dot { display:inline-block; width:8px; height:8px;
                  border-radius:50%; margin-right:5px; }
                .error { color:#ffc66d; padding:25px; }
              </style>
            </head>
            <body>
              <div id="graph"></div>
              <div class="legend">
                <span><i class="dot" style="background:#c4f36b"></i>Domain</span>
                <span><i class="dot" style="background:#63d9f5"></i>IPAddress</span>
                <span><i class="dot" style="background:#b49aff"></i>Certificate</span>
                <span><i class="dot" style="background:#ffc66d"></i>Report</span>
                <span><i class="dot" style="background:#94a3b8"></i>Other</span>
              </div>
              <div id="inspector">
                <div class="eyebrow">Selected entity</div>
                <div class="title">Choose a graph node</div>
                <div class="muted">Click any node to inspect its returned properties.</div>
              </div>
              <script>
                const payload = __GRAPH_DATA__;
                const container = document.getElementById("graph");
                const detail = document.getElementById("inspector");

                function escapeHtml(v) {
                  return String(v ?? "—").replace(/[&<>"']/g, c => ({
                    "&":"&amp;", "<":"&lt;", ">":"&gt;",
                    '"':"&quot;", "'":"&#39;"
                  }[c]));
                }

                function showNode(node) {
                  if (!node) {
                    detail.innerHTML =
                      '<div class="eyebrow">Selected entity</div>' +
                      '<div class="title">Choose a graph node</div>' +
                      '<div class="muted">Click a node to inspect its properties.</div>';
                    return;
                  }

                  let fields = Object.entries(node.properties || {})
                    .map(([key, value]) =>
                      '<div class="key">' + escapeHtml(key) + '</div>' +
                      '<div class="val">' + escapeHtml(value) + '</div>'
                    ).join("");

                  if (!fields) {
                    fields = '<div class="muted">No additional properties returned.</div>';
                  }

                  detail.innerHTML =
                    '<div class="eyebrow">Entity inspector</div>' +
                    '<div class="title">' + escapeHtml(node.label) + '</div>' +
                    '<div class="muted">' + escapeHtml(node.group) + '</div>' +
                    fields;
                }

                const colors = {
                  "Domain": "#c4f36b",
                  "IPAddress": "#63d9f5",
                  "Certificate": "#b49aff",
                  "Report": "#ffc66d"
                };

                const nodeData = payload.nodes.map(n => ({
                  ...n,
                  color: {
                    background: colors[n.group] || "#94a3b8",
                    border: "#e5edf7",
                    highlight: {
                      background: colors[n.group] || "#94a3b8",
                      border: "#ffffff"
                    }
                  },
                  font: { color: "#081018", size: 13, face: "Arial" },
                  borderWidth: 1.5,
                  shape: "dot",
                  size: 22
                }));

                const edgeData = payload.edges.map(e => ({
                  ...e,
                  color: { color: "#607487", highlight: "#c4f36b" },
                  width: 1.5,
                  smooth: { type: "dynamic" }
                }));

                const nodes = new vis.DataSet(nodeData);
                const edges = new vis.DataSet(edgeData);

                const network = new vis.Network(
                  container,
                  { nodes, edges },
                  {
                    autoResize: true,
                    interaction: {
                      hover: true,
                      navigationButtons: true,
                      keyboard: true
                    },
                    physics: {
                      stabilization: { iterations: 100 },
                      barnesHut: {
                        gravitationalConstant: -3500,
                        springLength: 145,
                        springConstant: 0.04
                      }
                    },
                    nodes: {
                      scaling: { min: 15, max: 32 }
                    },
                    edges: {
                      arrows: { to: { enabled: true, scaleFactor: 0.7 } }
                    }
                  }
                );

                network.on("click", params => {
                  const id = params.nodes[0];
                  showNode(id ? nodes.get(id) : null);
                });

                network.on("doubleClick", params => {
                  if (params.nodes.length) {
                    network.focus(params.nodes[0], {
                      scale: 1.2, animation: true
                    });
                  }
                });
              </script>
            </body>
            </html>
            """.replace("__GRAPH_DATA__", graph_payload)

            # vis-network is loaded from a public CDN by the iframe.
            graph_html = graph_html.replace(
                "<head>",
                '<head><script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>',
            )

            components.html(
                graph_html,
                height=585,
                scrolling=False,
            )
        else:
            st.markdown(
                '<div class="empty">No graph nodes were returned by the API.</div>',
                unsafe_allow_html=True,
            )

    with detail_col:
        st.markdown(
            """
            <div class="panel">
              <div class="eyebrow">Evidence assessment</div>
              <div class="panel-title">What the graph establishes</div>
              <div class="panel-copy">
                The graph shows relationships represented in the current dataset.
                It does not independently establish that the target is malicious.
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("**Backend explanation**")
        st.info(result.get("explanation", "No explanation returned."))

        assessment = result.get("assessment") or {}
        investigation_status = result.get("investigation_status", "NOT_ASSESSED")
        reg_domain = result.get("registered_domain")
        st.markdown(
            f"**Investigation Status:** `{esc(investigation_status)}` · "
            f"**Registered Apex:** `{esc(reg_domain or '—')}`"
        )
        st.markdown(
            f"**Assessment Verdict:** `{esc(assessment.get('verdict', 'UNKNOWN'))}`"
        )
        st.caption(
            assessment.get(
                "justification",
                "No assessment justification was returned.",
            )
        )
        st.caption(
            "Discovery status: "
            f"{esc(result.get('discovery_status', 'UNKNOWN'))} · "
            "Enrichment status: "
            f"{esc(result.get('enrichment_status', 'UNKNOWN'))} · "
            "Outcome: "
            f"{esc(result.get('enrichment_outcome', 'UNKNOWN'))}"
        )
        enrichment_sources = result.get("enrichment_sources") or []
        observed_sources = result.get("observed_sources") or []
        if enrichment_sources:
            st.markdown("**Passive collection provider outcomes**")
            for source in enrichment_sources:
                st.markdown(
                    f"- {esc(source.get('source'))}: "
                    f"`{esc(source.get('status'))}`"
                )
        elif observed_sources:
            st.markdown("**Sources observed in stored evidence**")
            for source in observed_sources:
                st.markdown(f"- {esc(source)}")

        associated_ips = result.get("associated_ips") or []
        associated_certs = result.get("associated_certificates") or []
        associated_reports = result.get("associated_reports") or []
        associated_ns = result.get("associated_nameservers") or []

        if associated_ips or associated_certs or associated_reports or associated_ns:
            target_name = result.get("target_domain", "Target")
            with st.expander(f"Structured Connected Infrastructure for {esc(target_name)} ({len(associated_certs)} certs, {len(associated_ns)} nameservers)", expanded=True):
                st.caption(f"Showing infrastructure entities directly connected to **{esc(target_name)}** in FalkorDB (global graph contains 46 total certificates across all indexed domains).")
                if associated_ips:
                    st.markdown(f"**Associated IP Addresses ({len(associated_ips)})**")
                    for ip in associated_ips:
                        st.markdown(f"- `{esc(ip)}`")
                if associated_certs:
                    st.markdown(f"**Associated TLS Certificates ({len(associated_certs)})**")
                    for cert in associated_certs:
                        subj = cert.get("subject") or cert.get("sha256", "—")
                        st.markdown(f"- `{esc(subj)}` (Issuer: {esc(cert.get('issuer', '—'))})")
                if associated_reports:
                    st.markdown("**Associated Threat Reports**")
                    for rep in associated_reports:
                        st.markdown(f"- Source: `{esc(rep.get('source', '—'))}` · Threat: `{esc(rep.get('threat', '—'))}` · ID: `{esc(rep.get('id', '—'))}`")
                if associated_ns:
                    st.markdown("**Associated Nameservers**")
                    for ns in associated_ns:
                        st.markdown(f"- `{esc(ns)}`")

        st.markdown("**Evidence limitations**")
        limitations = result.get("limitations") or [
            "No limitations were supplied by the backend."
        ]
        for limitation in limitations:
            st.markdown(f"- {limitation}")

        query_metadata = result.get("query_metadata") or {}
        if (
            query_metadata.get("row_limit_reached")
            or query_metadata.get("entity_limit_reached")
            or query_metadata.get("evidence_limit_reached")
        ):
            st.warning(
                "A configured query or report limit was reached. "
                "This result may omit additional graph records."
            )

        missing_information = result.get("missing_information") or []
        if missing_information:
            st.markdown("**Missing information**")
            for item in missing_information:
                st.markdown(f"- {esc(item)}")

        if not evidence:
            st.markdown(
                '<div class="empty">No evidence records were returned.</div>',
                unsafe_allow_html=True,
            )

        for index, item in enumerate(evidence, 1):
            if not isinstance(item, dict):
                item = {"value": item}

            with st.container(border=True):
                st.markdown(
                    f'<span class="tag">EVIDENCE {index:03d}</span>',
                    unsafe_allow_html=True,
                )

                for key in (
                    "domain",
                    "ip_address",
                    "certificate",
                    "report_id",
                    "source",
                    "kind",
                    "observed_at",
                    "observation_id",
                ):
                    if item.get(key) is not None:
                        st.markdown(
                            f"""
                            <div class="field-label">{esc(key.replace("_", " "))}</div>
                            <div class="field-value">{esc(item[key])}</div>
                            """,
                            unsafe_allow_html=True,
                        )

                score = item.get("confidence")
                st.markdown(
                    f"""
                    <div class="field-label">Supplied confidence score</div>
                    <div class="field-value">{esc(confidence_display(score))}</div>
                    <div class="muted">
                      This is a score supplied by the dataset, not automatically
                      a probability of maliciousness.
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                relationships = item.get("relationships") or []
                if relationships:
                    st.markdown("**Relationship types in returned graph**")
                    for relationship in relationships:
                        st.code(str(relationship), language=None)

                with st.expander("Full evidence record"):
                    st.json(item)

        shared_infrastructure = result.get("shared_infrastructure") or []
        if shared_infrastructure:
            with st.expander(
                f"Shared infrastructure paths · {len(shared_infrastructure)}"
            ):
                for item in shared_infrastructure:
                    infrastructure = item.get("infrastructure", {})
                    related_domain = item.get("related_domain", {})
                    st.markdown(
                        f"- `{esc(infrastructure.get('label', 'Infrastructure'))}` "
                        f"connects to `{esc(related_domain.get('label', 'Domain'))}`"
                    )
                    st.json({
                        "evidence_ids": item.get("evidence_ids", []),
                        "graph_record_ids": item.get("graph_record_ids", []),
                        "relationship_types": (
                            item.get("relationship_path", {})
                            .get("relationship_types", [])
                        ),
                    })

        timeline = result.get("timeline") or []
        if timeline:
            st.markdown("**Evidence timeline**")
            for item in timeline:
                st.markdown(
                    f"- `{esc(item.get('timestamp'))}` · "
                    f"{esc(item.get('event'))} · "
                    f"{esc(item.get('source'))} · "
                    f"evidence `{esc(item.get('evidence_id'))}`"
                )

    with st.expander("Raw investigation response"):
        st.json(result)

    st.download_button(
        "Export investigation JSON",
        data=json.dumps(result, indent=2, ensure_ascii=False),
        file_name=f"graphguard-{datetime.now():%Y%m%d-%H%M%S}.json",
        mime="application/json",
    )


# --------------------------- HISTORY -------------------------

st.markdown('<div class="section">04 / Analyst activity</div>',
            unsafe_allow_html=True)

with st.expander(f"Recent investigations · {len(st.session_state.history)}"):
    if st.session_state.history:
        for item in st.session_state.history:
            st.markdown(
                f"""
                <div class="evidence">
                  <div class="field-value">{esc(item["domain"])}</div>
                  <div class="field-label">
                    {esc(item["time"])} ·
                    {"MATCH FOUND" if item["found"] else "NO MATCH"} ·
                    {esc(item["records"])} evidence records
                  </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        if st.button("Clear session history"):
            st.session_state.history = []
            st.rerun()
    else:
        st.caption("No investigations yet.")

st.markdown("---")
st.markdown(
    '<div class="muted">GRAPHGUARD AI / SYNAPGRAPH · '
    'INTERACTIVE EVIDENCE INVESTIGATION · DEMO BUILD 1.0</div>',
    unsafe_allow_html=True,
)
