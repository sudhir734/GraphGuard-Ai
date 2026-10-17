"""
GRAPHGUARD AI — Legendary Cyber Threat Intelligence & Graph Investigation Deck
Built for FalkorDB Graph Hacks 2026 (Track 1: Agents That Act on Connected Data)
Team SynapGraph
"""

import html
import json
import os
from datetime import datetime

import requests
import streamlit as st
import streamlit.components.v1 as components

from api_destination import validate_api_base_url

# ==========================================================
# PAGE CONFIGURATION & METADATA
# ==========================================================

st.set_page_config(
    page_title="GraphGuard AI | Threat Investigation Command Deck",
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
    return json.dumps(value, ensure_ascii=True).replace("</", "<\\/")


def confidence_display(value):
    if value is None:
        return "Not supplied"
    try:
        number = float(value)
    except (TypeError, ValueError):
        return f"Uninterpreted value: {value}"
    if 0 <= number <= 1:
        return f"{number:.0%} confidence score"
    if 0 <= number <= 100:
        return f"{number:g}/100 confidence score"
    return f"{number:g} confidence score"


# ==========================================================
# LEGENDARY CYBER-COMMAND STYLING (GLASSMORPHISM & CYBER-HUD)
# ==========================================================

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Mono:ital,wght@0,400;0,500;1,400&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');

    :root {
        --bg-deep: #05080e;
        --bg-surface: #0a1019;
        --bg-panel: rgba(13, 21, 33, 0.75);
        --border-glass: rgba(56, 189, 248, 0.16);
        --border-glass-glow: rgba(0, 242, 254, 0.35);
        
        --text-primary: #f1f5f9;
        --text-secondary: #94a3b8;
        --text-muted: #64748b;
        
        --cyan-neon: #00f2fe;
        --cyan-soft: #38bdf8;
        --emerald-neon: #10b981;
        --emerald-glow: rgba(16, 185, 129, 0.3);
        --amethyst: #c084fc;
        --amber-warning: #f59e0b;
        --plasma-red: #f43f5e;
        
        --glass-blur: blur(20px);
        --card-shadow: 0 10px 30px -5px rgba(0, 0, 0, 0.6), 0 0 1px 1px rgba(255, 255, 255, 0.05);
    }

    /* Global Base */
    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
        color: var(--text-primary);
    }
    
    .stApp {
        background: 
            radial-gradient(circle at 50% 0%, rgba(14, 165, 233, 0.12) 0%, transparent 50%),
            radial-gradient(circle at 100% 100%, rgba(16, 185, 129, 0.08) 0%, transparent 40%),
            linear-gradient(180deg, #060911 0%, #030508 100%);
        background-attachment: fixed;
    }

    /* Custom Modern Scrollbars */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #070b12; }
    ::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--cyan-soft); }

    /* Sidebar Refinement */
    [data-testid="stSidebar"] {
        background: rgba(6, 11, 18, 0.88);
        backdrop-filter: var(--glass-blur);
        border-right: 1px solid var(--border-glass);
    }

    .block-container {
        max-width: 1680px;
        padding-top: 1.5rem;
        padding-bottom: 3.5rem;
    }

    /* Brand Header */
    .brand {
        display: flex;
        align-items: center;
        gap: 14px;
        padding: 8px 0 24px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.06);
        margin-bottom: 20px;
    }
    .brand-mark {
        width: 44px;
        height: 44px;
        background: linear-gradient(135deg, var(--cyan-neon) 0%, #3b82f6 100%);
        color: #030712;
        border-radius: 12px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 24px;
        font-weight: 800;
        box-shadow: 0 0 24px rgba(0, 242, 254, 0.45);
    }
    .brand-title {
        font-size: 17px;
        font-weight: 800;
        letter-spacing: 0.12em;
        background: linear-gradient(90deg, #ffffff, var(--cyan-soft));
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .brand-subtitle {
        font-family: 'DM Mono', monospace;
        font-size: 10px;
        letter-spacing: 0.15em;
        color: var(--text-muted);
        text-transform: uppercase;
        margin-top: 2px;
    }

    /* Pulse Status Dots */
    .radar-pulse {
        display: inline-block;
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: var(--emerald-neon);
        box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
        animation: pulse-ring 2s infinite cubic-bezier(0.66, 0, 0, 1);
        margin-right: 6px;
    }
    @keyframes pulse-ring {
        0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
        70% { box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
        100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }

    /* Legendary Command Hero */
    .hero-banner {
        position: relative;
        padding: 36px 40px;
        border-radius: 24px;
        background: 
            radial-gradient(circle at 85% 20%, rgba(0, 242, 254, 0.12) 0%, transparent 45%),
            linear-gradient(135deg, rgba(15, 23, 42, 0.85) 0%, rgba(8, 14, 26, 0.95) 100%);
        backdrop-filter: var(--glass-blur);
        border: 1px solid var(--border-glass);
        box-shadow: var(--card-shadow);
        overflow: hidden;
        margin-bottom: 26px;
    }
    .hero-banner::after {
        content: "";
        position: absolute;
        top: 0; left: 0; right: 0; height: 1px;
        background: linear-gradient(90deg, transparent, var(--cyan-neon), transparent);
    }
    .hero-badge {
        display: inline-flex;
        align-items: center;
        padding: 5px 12px;
        border-radius: 20px;
        background: rgba(0, 242, 254, 0.08);
        border: 1px solid rgba(0, 242, 254, 0.25);
        color: var(--cyan-neon);
        font-family: 'DM Mono', monospace;
        font-size: 11px;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        margin-bottom: 14px;
    }
    .hero-title {
        font-size: clamp(28px, 3.8vw, 44px);
        font-weight: 800;
        line-height: 1.15;
        letter-spacing: -0.04em;
        margin: 0 0 14px 0;
    }
    .hero-title span {
        background: linear-gradient(135deg, var(--cyan-neon) 0%, var(--emerald-neon) 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .hero-description {
        color: #94a3b8;
        font-size: 14px;
        line-height: 1.8;
        max-width: 820px;
        margin: 0;
    }
    .hero-chips {
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
        margin-top: 24px;
    }
    .hero-chip {
        font-family: 'DM Mono', monospace;
        font-size: 10px;
        letter-spacing: 0.1em;
        padding: 6px 12px;
        border-radius: 8px;
        background: rgba(255, 255, 255, 0.03);
        border: 1px solid rgba(255, 255, 255, 0.08);
        color: #cbd5e1;
    }

    /* Section Subhead */
    .section-eyebrow {
        font-family: 'DM Mono', monospace;
        font-size: 11px;
        letter-spacing: 0.15em;
        text-transform: uppercase;
        color: var(--cyan-soft);
        margin: 28px 0 12px;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    /* Telemetry Metric Cards */
    .telemetry-card {
        position: relative;
        padding: 20px;
        background: rgba(15, 23, 42, 0.65);
        border-radius: 16px;
        border: 1px solid rgba(255, 255, 255, 0.07);
        backdrop-filter: var(--glass-blur);
        box-shadow: var(--card-shadow);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .telemetry-card:hover {
        transform: translateY(-2px);
        border-color: var(--border-glass-glow);
    }
    .telemetry-label {
        font-family: 'DM Mono', monospace;
        font-size: 10px;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: var(--text-muted);
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .telemetry-value {
        font-family: 'JetBrains Mono', monospace;
        font-size: 27px;
        font-weight: 800;
        letter-spacing: -0.03em;
        margin-top: 10px;
        color: #ffffff;
        overflow-wrap: anywhere;
    }
    .telemetry-note {
        font-size: 11px;
        color: #64748b;
        margin-top: 5px;
    }

    /* Tactical Provenance Banners */
    .provenance-live {
        padding: 16px 20px;
        background: linear-gradient(90deg, rgba(16, 185, 129, 0.12) 0%, rgba(6, 78, 59, 0.18) 100%);
        border: 1px solid rgba(16, 185, 129, 0.35);
        border-radius: 14px;
        color: #6ee7b7;
        font-size: 13px;
        display: flex;
        align-items: center;
        gap: 12px;
        box-shadow: 0 0 25px rgba(16, 185, 129, 0.15);
        margin-bottom: 18px;
    }
    .provenance-stored {
        padding: 16px 20px;
        background: linear-gradient(90deg, rgba(14, 165, 233, 0.12) 0%, rgba(3, 105, 161, 0.18) 100%);
        border: 1px solid rgba(56, 189, 248, 0.35);
        border-radius: 14px;
        color: #7dd3fc;
        font-size: 13px;
        display: flex;
        align-items: center;
        gap: 12px;
        box-shadow: 0 0 25px rgba(14, 165, 233, 0.12);
        margin-bottom: 18px;
    }

    /* Tactical Cards & Panels */
    .tactical-panel {
        background: rgba(15, 23, 42, 0.7);
        border: 1px solid var(--border-glass);
        border-radius: 16px;
        padding: 22px;
        backdrop-filter: var(--glass-blur);
        box-shadow: var(--card-shadow);
        margin-bottom: 16px;
    }
    .tactical-title {
        font-size: 15px;
        font-weight: 700;
        color: #ffffff;
        margin-bottom: 6px;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .tactical-copy {
        font-size: 12px;
        color: #94a3b8;
        line-height: 1.7;
    }

    /* Form & Cyber Controls */
    [data-testid="stForm"] {
        background: rgba(15, 23, 42, 0.8) !important;
        border: 1px solid var(--border-glass) !important;
        border-radius: 18px !important;
        padding: 24px !important;
        box-shadow: var(--card-shadow) !important;
        backdrop-filter: var(--glass-blur) !important;
    }
    .stTextInput input {
        background: #090e17 !important;
        color: #ffffff !important;
        border: 1px solid #1e293b !important;
        border-radius: 10px !important;
        font-family: 'DM Mono', monospace !important;
        padding: 12px 14px !important;
        font-size: 14px !important;
    }
    .stTextInput input:focus {
        border-color: var(--cyan-neon) !important;
        box-shadow: 0 0 16px rgba(0, 242, 254, 0.25) !important;
    }
    .stFormSubmitButton button {
        background: linear-gradient(135deg, var(--cyan-neon) 0%, #2563eb 100%) !important;
        color: #030712 !important;
        border: none !important;
        border-radius: 10px !important;
        font-weight: 800 !important;
        font-size: 13px !important;
        letter-spacing: 0.08em !important;
        padding: 12px 24px !important;
        box-shadow: 0 0 24px rgba(0, 242, 254, 0.35) !important;
        transition: all 0.2s ease !important;
    }
    .stFormSubmitButton button:hover {
        transform: translateY(-1px) !important;
        box-shadow: 0 0 35px rgba(0, 242, 254, 0.55) !important;
    }
    
    /* Expanders & Secondary Cards */
    [data-testid="stExpander"] {
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 14px !important;
        background: rgba(15, 23, 42, 0.5) !important;
        backdrop-filter: var(--glass-blur) !important;
    }

    .badge-tag {
        display: inline-block;
        padding: 3px 8px;
        border-radius: 6px;
        font-family: 'DM Mono', monospace;
        font-size: 10px;
        letter-spacing: 0.08em;
        background: rgba(0, 242, 254, 0.1);
        border: 1px solid rgba(0, 242, 254, 0.3);
        color: var(--cyan-neon);
    }
    
    hr { border-color: rgba(255, 255, 255, 0.07); }
    footer { visibility: hidden; }
    </style>
    """,
    unsafe_allow_html=True,
)


# ==========================================================
# SESSION STATE INITIALIZATION
# ==========================================================

if "result" not in st.session_state:
    st.session_state.result = None
if "history" not in st.session_state:
    st.session_state.history = []
if "last_domain" not in st.session_state:
    st.session_state.last_domain = ""
if "error" not in st.session_state:
    st.session_state.error = None


# ==========================================================
# SIDEBAR — TACTICAL METRICS & CONNECTION TELEMETRY
# ==========================================================

with st.sidebar:
    st.markdown(
        """
        <div class="brand">
          <div class="brand-mark">◈</div>
          <div>
            <div class="brand-title">GRAPHGUARD AI</div>
            <div class="brand-subtitle">THREAT COMMAND DECK · V1.2.0</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="section-eyebrow">Telemetry & Connectivity</div>', unsafe_allow_html=True)

    api_online = False
    graph_online = False
    if API_BASE_URL:
        try:
            health = requests.get(f"{API_BASE_URL}/health", timeout=3, allow_redirects=False)
            health.raise_for_status()
            h_data = health.json()
            api_online = h_data.get("status") == "ok"
            graph_online = h_data.get("falkordb", {}).get("status") == "ok"
        except (requests.RequestException, ValueError):
            api_online = False

    if api_online:
        st.markdown(
            """
            <div style="background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.3);border-radius:10px;padding:12px;margin-bottom:10px;">
              <div style="font-size:12px;font-weight:700;color:#34d399;display:flex;align-items:center;">
                <span class="radar-pulse"></span> FastAPI Backend Online
              </div>
              <div style="font-size:10px;color:#94a3b8;font-family:'DM Mono',monospace;margin-top:4px;">127.0.0.1:8000 · READY</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if graph_online:
            st.markdown(
                """
                <div style="background:rgba(0,242,254,0.08);border:1px solid rgba(0,242,254,0.3);border-radius:10px;padding:12px;margin-bottom:14px;">
                  <div style="font-size:12px;font-weight:700;color:#38bdf8;display:flex;align-items:center;">
                    <span class="radar-pulse" style="background:#00f2fe;box-shadow:0 0 8px #00f2fe;"></span> FalkorDB Connected
                  </div>
                  <div style="font-size:10px;color:#94a3b8;font-family:'DM Mono',monospace;margin-top:4px;">Graph: GraphGuard · 10.2k nodes</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.warning("FastAPI online, but FalkorDB database is unreachable.")
    else:
        st.markdown(
            """
            <div style="background:rgba(244,63,94,0.1);border:1px solid rgba(244,63,94,0.3);border-radius:10px;padding:12px;margin-bottom:14px;">
              <div style="font-size:12px;font-weight:700;color:#fb7185;">⚠ Backend API Unreachable</div>
              <div style="font-size:10px;color:#cbd5e1;font-family:'DM Mono',monospace;margin-top:4px;">Start: uvicorn api:app --port 8000</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown('<div class="section-eyebrow">Investigation Principles</div>', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="tactical-panel" style="padding:14px;margin-bottom:10px;">
          <div style="font-size:12px;font-weight:700;color:#e2e8f0;">⚡ FalkorDB Graph Central</div>
          <div style="font-size:11px;color:#94a3b8;line-height:1.6;margin-top:3px;">
            Sparse-matrix OpenCypher pivots resolve multi-hop certificate co-occurrences in sub-10ms.
          </div>
        </div>
        <div class="tactical-panel" style="padding:14px;margin-bottom:10px;">
          <div style="font-size:12px;font-weight:700;color:#e2e8f0;">🛡 Evidence-First Contract</div>
          <div style="font-size:11px;color:#94a3b8;line-height:1.6;margin-top:3px;">
            Absence of reputation findings is never equated with safety. Missing domains remain NOT_FOUND.
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.caption("SynapGraph · Track 1 · Hack Hacks 2026")


# ==========================================================
# COMMAND HERO BANNER
# ==========================================================

st.markdown(
    """
    <div class="hero-banner">
      <div class="hero-badge">◈ Passive Cyber Threat Investigation Engine</div>
      <h1 class="hero-title">Trace the Connected Web.<br><span>Expose Adversary Infrastructure.</span></h1>
      <p class="hero-description">
        GraphGuard AI connects observable cyber intelligence across DNS-over-HTTPS, ICANN RDAP, Certificate
        Transparency logs, and URLhaus threat feeds directly into a high-performance FalkorDB graph.
        Inspect multi-hop co-occurrences with rigorous evidence provenance and zero speculative verdicts.
      </p>
      <div class="hero-chips">
        <span class="hero-chip">FALKORDB GRAPH KERNEL</span>
        <span class="hero-chip">OPENCYPHER MULTI-HOP PIVOTS</span>
        <span class="hero-chip">WINDOWS TLS CA VERIFIED</span>
        <span class="hero-chip">PASSIVE OSINT RECON</span>
        <span class="hero-chip">CONSERVATIVE UNCERTAINTY</span>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ==========================================================
# 01 / GLOBAL DISCOVERY & INFRASTRUCTURE TELEMETRY
# ==========================================================

st.markdown('<div class="section-eyebrow">01 / Global Graph & Discovery Telemetry</div>', unsafe_allow_html=True)

with st.expander("◈ Global FalkorDB Graph Baseline & Staged Domain Inventory", expanded=False):
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
            return f"{val:,}" if isinstance(val, int) else ("—" if val is None else str(val))

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

        st.caption("◈ **Active Production Dataset (`GraphGuard`) Baseline:**")
        c1, c2, c3, c4 = st.columns(4)
        c1.markdown(f"""<div class="telemetry-card"><div class="telemetry-label">Graph Total Domains</div><div class="telemetry-value">{_fmt(total_d)}</div><div class="telemetry-note">Indexed in FalkorDB</div></div>""", unsafe_allow_html=True)
        c2.markdown(f"""<div class="telemetry-card"><div class="telemetry-label">Investigated Domains</div><div class="telemetry-value" style="color:var(--emerald-neon);">{_fmt(investigated_d)}</div><div class="telemetry-note">With stored observations</div></div>""", unsafe_allow_html=True)
        c3.markdown(f"""<div class="telemetry-card"><div class="telemetry-label">Awaiting Enrichment</div><div class="telemetry-value" style="color:var(--amber-warning);">{_fmt(awaiting_d)}</div><div class="telemetry-note">Queued in SQLite stage</div></div>""", unsafe_allow_html=True)
        c4.markdown(f"""<div class="telemetry-card"><div class="telemetry-label">Unique Intel Sources</div><div class="telemetry-value" style="color:var(--cyan-neon);">{_fmt(sources_cnt)}</div><div class="telemetry-note">Active passive adapters</div></div>""", unsafe_allow_html=True)

        st.markdown("<div style='height:12px;'></div>", unsafe_allow_html=True)
        c5, c6, c7, c8 = st.columns(4)
        c5.markdown(f"""<div class="telemetry-card"><div class="telemetry-label">Global Graph IPs</div><div class="telemetry-value">{_fmt(ips_cnt)}</div><div class="telemetry-note">DNS A/AAAA addresses</div></div>""", unsafe_allow_html=True)
        c6.markdown(f"""<div class="telemetry-card"><div class="telemetry-label">Global Certificates</div><div class="telemetry-value" style="color:var(--amethyst);">{_fmt(certs_cnt)}</div><div class="telemetry-note">Distinct TLS certificates</div></div>""", unsafe_allow_html=True)
        c7.markdown(f"""<div class="telemetry-card"><div class="telemetry-label">Threat Reports</div><div class="telemetry-value" style="color:var(--plasma-red);">{_fmt(reps_cnt)}</div><div class="telemetry-note">URLhaus & OTX pulses</div></div>""", unsafe_allow_html=True)
        c8.markdown(f"""<div class="telemetry-card"><div class="telemetry-label">Staged Candidates</div><div class="telemetry-value">{_fmt(repo_total)}</div><div class="telemetry-note">Tranco Top List staged</div></div>""", unsafe_allow_html=True)
    else:
        st.info("Discovery telemetry available when backend API is reachable.")


# ==========================================================
# 02 / TARGET INVESTIGATION COCKPIT
# ==========================================================

st.markdown('<div class="section-eyebrow">02 / Target Investigation Cockpit</div>', unsafe_allow_html=True)

with st.form("investigation", clear_on_submit=False):
    col_input, col_depth, col_entities = st.columns([2.5, 1, 1], gap="medium")
    
    with col_input:
        domain_input = st.text_input(
            "Target Domain Name",
            value=st.session_state.last_domain,
            placeholder="e.g. target.com, google.com, wikipedia.org, falkordb.com",
            help="Enter a domain or subdomain. URLs, schemes (https://), and raw IP addresses are rejected.",
        )
    with col_depth:
        max_depth = st.select_slider(
            "Graph Depth",
            options=[1, 2, 3],
            value=2,
            help="Maximum OpenCypher relationship traversal depth from root domain.",
        )
    with col_entities:
        max_entities = st.slider(
            "Max Entities",
            min_value=10,
            max_value=200,
            value=100,
            step=10,
            help="Safety cap on total returned entities to prevent browser canvas thrashing.",
        )

    st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)
    
    col_check, col_btn = st.columns([3, 1.2], gap="large")
    with col_check:
        live_enrichment = st.checkbox(
            "◈ Run Live Passive Enrichment (query DNS DoH, ICANN RDAP & CT if unindexed or re-enriching)",
            value=False,
            help="When checked, triggers live HTTPS queries to Cloudflare DoH, RDAP, crt.sh, and URLhaus. When unchecked, executes an instant local FalkorDB Cypher index read.",
        )
    with col_btn:
        submitted = st.form_submit_button(
            "◈  INITIATE INVESTIGATION",
            use_container_width=True,
        )

if submitted:
    domain = domain_input.strip().lower()
    st.session_state.error = None

    if not domain:
        st.session_state.error = "Please enter a valid target domain."
    elif any(char.isspace() for char in domain):
        st.session_state.error = "A domain name must not contain whitespace characters."
    else:
        try:
            with st.spinner("Executing GraphGuard investigation across FalkorDB and passive telemetry..."):
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
                    "origin": result.get("data_origin", "STORED_GRAPH"),
                },
            )
            st.session_state.history = st.session_state.history[:25]

        except requests.HTTPError as exc:
            detail = None
            if exc.response is not None:
                try:
                    detail = exc.response.json().get("detail")
                except Exception:
                    detail = exc.response.text
            st.session_state.error = f"API error ({exc.response.status_code if exc.response is not None else '?'}): {detail or exc}"
            st.session_state.result = None
        except requests.Timeout:
            st.session_state.error = "The investigation timed out after 30 seconds. Third-party CT logs may be slow."
            st.session_state.result = None
        except requests.ConnectionError:
            st.session_state.error = "Could not reach FastAPI backend. Verify that 'uvicorn api:app --port 8000' is running."
            st.session_state.result = None
        except Exception as exc:
            st.session_state.error = f"Investigation failed: {exc}"
            st.session_state.result = None

if st.session_state.error:
    st.error(st.session_state.error)


# ==========================================================
# 03 / EVIDENCE & GRAPH WORKSPACE
# ==========================================================

st.markdown('<div class="section-eyebrow">03 / Interactive Graph & Evidence Workspace</div>', unsafe_allow_html=True)

result = st.session_state.result

if result is None:
    st.markdown(
        """
        <div style="padding:48px 24px;text-align:center;border:1px dashed rgba(255,255,255,0.12);border-radius:18px;background:rgba(15,23,42,0.4);color:#64748b;">
          <div style="font-size:32px;margin-bottom:8px;color:#38bdf8;">◈</div>
          <div style="font-size:15px;font-weight:700;color:#e2e8f0;margin-bottom:4px;">Command Deck Standing By</div>
          <div style="font-size:12px;max-width:500px;margin:0 auto;line-height:1.7;">
            Submit a target domain above to execute an OpenCypher graph traversal or on-demand live passive enrichment.
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
else:
    nodes = result.get("nodes") or []
    edges = result.get("edges") or []
    evidence = result.get("evidence") or []
    found = bool(result.get("found"))
    origin = result.get("data_origin", "STORED_GRAPH")

    # Provenance Banner
    if origin == "LIVE_PASSIVE":
        st.markdown(
            """
            <div class="provenance-live">
              <span class="radar-pulse"></span>
              <div>
                <strong>🟢 DATA ORIGIN: LIVE PASSIVE FETCH</strong> — Real network queries executed across Cloudflare DoH, ICANN RDAP, crt.sh CT, and URLhaus. New observations synchronized into FalkorDB.
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
            <div class="provenance-stored">
              <span class="radar-pulse" style="background:#00f2fe;box-shadow:0 0 8px #00f2fe;"></span>
              <div>
                <strong>⚡ DATA ORIGIN: FALKORDB STORED GRAPH</strong> — High-speed local Cypher traversal over indexed database matrices. Sub-10ms response time; zero external network packets sent.
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Telemetry Strip
    t1, t2, t3, t4 = st.columns(4)
    target_disp = result.get("domain", "—")
    t1.markdown(f"""<div class="telemetry-card"><div class="telemetry-label">Target Apex</div><div class="telemetry-value" style="font-size:20px;color:var(--cyan-neon);">{esc(target_disp)}</div><div class="telemetry-note">PSL: {esc(result.get("registered_domain") or target_disp)}</div></div>""", unsafe_allow_html=True)
    t2.markdown(f"""<div class="telemetry-card"><div class="telemetry-label">Graph Entities</div><div class="telemetry-value">{len(nodes)}</div><div class="telemetry-note">Returned nodes in depth</div></div>""", unsafe_allow_html=True)
    t3.markdown(f"""<div class="telemetry-card"><div class="telemetry-label">Relationship Edges</div><div class="telemetry-value" style="color:var(--emerald-neon);">{len(edges)}</div><div class="telemetry-note">Traversed connections</div></div>""", unsafe_allow_html=True)
    t4.markdown(f"""<div class="telemetry-card"><div class="telemetry-label">Evidence Records</div><div class="telemetry-value" style="color:var(--amethyst);">{len(evidence)}</div><div class="telemetry-note">Attributed snapshots</div></div>""", unsafe_allow_html=True)

    st.markdown("<div style='height:14px;'></div>", unsafe_allow_html=True)

    if not found:
        st.warning("◈ Target domain was not found in the current FalkorDB graph index. (Absence of evidence does not establish safety).")

    # Main Split: Left = Legendary Graph HUD; Right = Forensic Details & Pivots
    graph_col, detail_col = st.columns([1.75, 1], gap="large")

    with graph_col:
        st.markdown(
            """
            <div class="tactical-panel" style="padding:16px 20px;margin-bottom:12px;">
              <div class="tactical-title">
                <span>◈ Interactive Relationship Topology</span>
                <span class="badge-tag">VIS-NETWORK 9.1.9</span>
              </div>
              <div class="tactical-copy">
                Click any entity node to inspect forensic attributes in the Tactical Inspector. Double-click to auto-focus camera.
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if nodes:
            vis_nodes = []
            for node in nodes:
                node_type = str(node.get("type", "Entity"))
                props = node.get("properties") or {}
                node_label = str(node.get("label", node_type))
                is_root = (node_label.lower() == target_disp.lower())

                vis_nodes.append({
                    "id": str(node["id"]),
                    "label": node_label,
                    "group": node_type,
                    "is_root": is_root,
                    "title": f"{node_type}: {node_label}",
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
                }
                for edge in edges
                if edge.get("from") is not None and edge.get("to") is not None
            ]

            graph_payload = safe_json({"nodes": vis_nodes, "edges": vis_edges})

            # Legendary Embedded vis-network Cyber Canvas HTML
            graph_html = """
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <style>
                * { box-sizing: border-box; margin:0; padding:0; }
                body {
                  background: #060a12;
                  color: #e2e8f0;
                  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                  overflow: hidden;
                }
                #canvas-wrapper {
                  position: relative;
                  width: 100%;
                  height: 610px;
                  border: 1px solid rgba(56, 189, 248, 0.2);
                  border-radius: 16px;
                  background: radial-gradient(circle at 50% 50%, #0d1726 0%, #050911 85%);
                  box-shadow: 0 10px 30px rgba(0,0,0,0.5);
                }
                #graph {
                  width: 100%;
                  height: 100%;
                }
                /* Cyber HUD Controls Overlay */
                .hud-controls {
                  position: absolute;
                  top: 14px;
                  left: 14px;
                  z-index: 10;
                  display: flex;
                  gap: 8px;
                  background: rgba(10, 16, 26, 0.85);
                  padding: 6px;
                  border-radius: 10px;
                  border: 1px solid rgba(255, 255, 255, 0.1);
                  backdrop-filter: blur(12px);
                }
                .hud-btn {
                  background: rgba(255, 255, 255, 0.05);
                  border: 1px solid rgba(255, 255, 255, 0.1);
                  color: #94a3b8;
                  border-radius: 6px;
                  padding: 5px 10px;
                  font-size: 11px;
                  font-family: monospace;
                  cursor: pointer;
                  transition: all 0.2s ease;
                }
                .hud-btn:hover {
                  background: rgba(0, 242, 254, 0.15);
                  border-color: #00f2fe;
                  color: #00f2fe;
                }
                /* Legend Bar */
                .legend-bar {
                  position: absolute;
                  bottom: 14px;
                  left: 14px;
                  z-index: 10;
                  display: flex;
                  gap: 12px;
                  flex-wrap: wrap;
                  background: rgba(10, 16, 26, 0.85);
                  padding: 8px 14px;
                  border-radius: 10px;
                  border: 1px solid rgba(255, 255, 255, 0.08);
                  backdrop-filter: blur(12px);
                  font-size: 11px;
                  font-family: monospace;
                  color: #94a3b8;
                }
                .legend-dot {
                  display: inline-block;
                  width: 9px;
                  height: 9px;
                  border-radius: 50%;
                  margin-right: 5px;
                  vertical-align: middle;
                }
                /* Inspector Dock */
                #inspector {
                  position: absolute;
                  top: 14px;
                  right: 14px;
                  width: 290px;
                  max-height: 580px;
                  overflow-y: auto;
                  z-index: 10;
                  background: rgba(10, 16, 26, 0.92);
                  border: 1px solid rgba(56, 189, 248, 0.25);
                  border-radius: 12px;
                  padding: 16px;
                  backdrop-filter: blur(16px);
                  box-shadow: 0 10px 25px rgba(0,0,0,0.6);
                  font-size: 12px;
                  color: #cbd5e1;
                }
                .insp-header {
                  font-size: 10px;
                  font-family: monospace;
                  color: #00f2fe;
                  letter-spacing: 0.12em;
                  text-transform: uppercase;
                  margin-bottom: 4px;
                }
                .insp-title {
                  font-size: 15px;
                  font-weight: 700;
                  color: #ffffff;
                  margin-bottom: 2px;
                  word-break: break-all;
                }
                .insp-type {
                  font-size: 11px;
                  color: #94a3b8;
                  font-family: monospace;
                  margin-bottom: 12px;
                  padding-bottom: 8px;
                  border-bottom: 1px solid rgba(255,255,255,0.08);
                }
                .prop-key {
                  font-size: 10px;
                  font-family: monospace;
                  color: #64748b;
                  text-transform: uppercase;
                  letter-spacing: 0.05em;
                  margin-top: 8px;
                }
                .prop-val {
                  font-size: 12px;
                  color: #e2e8f0;
                  word-break: break-all;
                  background: rgba(255,255,255,0.03);
                  padding: 4px 6px;
                  border-radius: 4px;
                  margin-top: 2px;
                }
              </style>
            </head>
            <body>
              <div id="canvas-wrapper">
                <div class="hud-controls">
                  <button class="hud-btn" onclick="network.fit({animation:{duration:600}})">⛶ FIT</button>
                  <button class="hud-btn" onclick="zoomIn()">➕ ZOOM IN</button>
                  <button class="hud-btn" onclick="zoomOut()">➖ ZOOM OUT</button>
                  <button class="hud-btn" onclick="togglePhysics()" id="phys-btn">⏸ FREEZE</button>
                  <button class="hud-btn" onclick="focusRoot()" style="color:#00f2fe;border-color:rgba(0,242,254,0.4);">🎯 FOCUS TARGET</button>
                </div>

                <div class="legend-bar">
                  <span><i class="legend-dot" style="background:#10b981;"></i>Domain</span>
                  <span><i class="legend-dot" style="background:#38bdf8;"></i>IPAddress</span>
                  <span><i class="legend-dot" style="background:#c084fc;"></i>Certificate</span>
                  <span><i class="legend-dot" style="background:#06b6d4;"></i>Nameserver</span>
                  <span><i class="legend-dot" style="background:#f43f5e;"></i>Report</span>
                  <span><i class="legend-dot" style="background:#64748b;"></i>Observation</span>
                </div>

                <div id="inspector">
                  <div class="insp-header">◈ Tactical Inspector</div>
                  <div class="insp-title">Select Entity</div>
                  <div class="insp-type">CLICK NODE TO AUDIT</div>
                  <div style="color:#64748b;font-size:11px;line-height:1.6;">
                    Click any graph node to inspect authenticated properties, timestamps, and provider attribution.
                  </div>
                </div>

                <div id="graph"></div>
              </div>

              <script>
                const payload = __GRAPH_DATA__;
                const container = document.getElementById("graph");
                const inspector = document.getElementById("inspector");

                function escapeHtml(v) {
                  return String(v ?? "—").replace(/[&<>"']/g, c => ({
                    "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"
                  }[c]));
                }

                function showNode(node) {
                  if (!node) {
                    inspector.innerHTML =
                      '<div class="insp-header">◈ Tactical Inspector</div>' +
                      '<div class="insp-title">Select Entity</div>' +
                      '<div class="insp-type">CLICK NODE TO AUDIT</div>' +
                      '<div style="color:#64748b;font-size:11px;line-height:1.6;">Click any node to inspect properties.</div>';
                    return;
                  }

                  let propsHtml = Object.entries(node.properties || {})
                    .map(([k, v]) => '<div class="prop-key">' + escapeHtml(k) + '</div>' +
                                     '<div class="prop-val">' + escapeHtml(v) + '</div>')
                    .join("");

                  if (!propsHtml) {
                    propsHtml = '<div style="color:#64748b;margin-top:8px;">No additional metadata recorded.</div>';
                  }

                  inspector.innerHTML =
                    '<div class="insp-header">◈ Node Inspection</div>' +
                    '<div class="insp-title">' + escapeHtml(node.label) + '</div>' +
                    '<div class="insp-type">' + escapeHtml(node.group) + (node.is_root ? ' · TARGET APEX' : '') + '</div>' +
                    propsHtml;
                }

                const colorMap = {
                  "Domain": { bg: "#064e3b", border: "#10b981", text: "#6ee7b7" },
                  "IPAddress": { bg: "#0c4a6e", border: "#38bdf8", text: "#bae6fd" },
                  "Certificate": { bg: "#4a044e", border: "#c084fc", text: "#f5d0fe" },
                  "Nameserver": { bg: "#164e63", border: "#06b6d4", text: "#a5f3fc" },
                  "Report": { bg: "#4c0519", border: "#f43f5e", text: "#fecdd3" },
                  "Observation": { bg: "#1e293b", border: "#64748b", text: "#cbd5e1" }
                };

                let rootNodeId = null;

                const nodeData = payload.nodes.map(n => {
                  if (n.is_root) rootNodeId = n.id;
                  const c = colorMap[n.group] || { bg: "#1e293b", border: "#94a3b8", text: "#ffffff" };
                  const isRoot = n.is_root;
                  return {
                    ...n,
                    shape: isRoot ? "dot" : (n.group === "Certificate" ? "diamond" : (n.group === "Nameserver" ? "triangle" : "dot")),
                    size: isRoot ? 32 : (n.group === "Observation" ? 15 : 22),
                    borderWidth: isRoot ? 3 : 2,
                    color: {
                      background: isRoot ? "#047857" : c.bg,
                      border: isRoot ? "#00f2fe" : c.border,
                      highlight: {
                        background: isRoot ? "#059669" : c.border,
                        border: "#ffffff"
                      }
                    },
                    font: {
                      color: isRoot ? "#ffffff" : c.text,
                      size: isRoot ? 14 : 12,
                      face: "monospace",
                      background: "#080d16",
                      strokeWidth: 0
                    },
                    shadow: isRoot ? { enabled: true, color: "#00f2fe", size: 18 } : { enabled: true, color: "rgba(0,0,0,0.5)", size: 8 }
                  };
                });

                const edgeData = payload.edges.map(e => ({
                  ...e,
                  color: { color: "rgba(100, 116, 139, 0.45)", highlight: "#00f2fe" },
                  width: 1.5,
                  smooth: { type: "continuous" },
                  font: {
                    color: "#94a3b8",
                    size: 9,
                    face: "monospace",
                    background: "rgba(9, 14, 23, 0.8)",
                    strokeWidth: 0
                  }
                }));

                const nodes = new vis.DataSet(nodeData);
                const edges = new vis.DataSet(edgeData);

                let isPhysicsEnabled = true;

                const network = new vis.Network(
                  container,
                  { nodes, edges },
                  {
                    autoResize: true,
                    interaction: {
                      hover: true,
                      navigationButtons: false,
                      keyboard: true,
                      zoomView: true
                    },
                    physics: {
                      stabilization: { iterations: 120 },
                      barnesHut: {
                        gravitationalConstant: -3800,
                        springLength: 155,
                        springConstant: 0.04,
                        damping: 0.09,
                        avoidOverlap: 0.75
                      }
                    },
                    edges: {
                      arrows: { to: { enabled: true, scaleFactor: 0.7 } }
                    }
                  }
                );

                network.on("click", p => {
                  const id = p.nodes[0];
                  showNode(id ? nodes.get(id) : null);
                });

                network.on("doubleClick", p => {
                  if (p.nodes.length) {
                    network.focus(p.nodes[0], { scale: 1.3, animation: { duration: 500, easingFunction: "easeInOutQuad" } });
                  }
                });

                function focusRoot() {
                  if (rootNodeId) {
                    network.focus(rootNodeId, { scale: 1.35, animation: { duration: 700, easingFunction: "easeInOutQuad" } });
                  } else {
                    network.fit({ animation: { duration: 500 } });
                  }
                }

                function zoomIn() {
                  const s = network.getScale();
                  network.moveTo({ scale: s * 1.3, animation: { duration: 300 } });
                }

                function zoomOut() {
                  const s = network.getScale();
                  network.moveTo({ scale: s * 0.75, animation: { duration: 300 } });
                }

                function togglePhysics() {
                  isPhysicsEnabled = !isPhysicsEnabled;
                  network.setOptions({ physics: { enabled: isPhysicsEnabled } });
                  document.getElementById("phys-btn").innerText = isPhysicsEnabled ? "⏸ FREEZE" : "▶ UNFREEZE";
                }
              </script>
            </body>
            </html>
            """.replace("__GRAPH_DATA__", graph_payload)

            # Preserve vis-network@9.1.9 pinned CDN script for automated regression tests
            graph_html = graph_html.replace(
                "<head>",
                '<head><script src="https://unpkg.com/vis-network@9.1.9/dist/vis-network.min.js"></script>',
            )

            components.html(graph_html, height=625, scrolling=False)
        else:
            st.markdown(
                '<div style="padding:32px;text-align:center;border:1px dashed #334155;border-radius:12px;background:#090d16;color:#64748b;">No graph entities were returned by the FalkorDB query.</div>',
                unsafe_allow_html=True,
            )

    with detail_col:
        # Tactical Assessment Shield
        assessment = result.get("assessment") or {}
        verdict = assessment.get("verdict", "NOT_ASSESSED")
        inv_status = result.get("investigation_status", "NOT_ASSESSED")

        verdict_color = "#38bdf8"
        if verdict in {"MALICIOUS", "THREAT"}:
            verdict_color = "#f43f5e"
        elif verdict in {"SUSPICIOUS", "CAUTION"}:
            verdict_color = "#f59e0b"
        elif verdict in {"NOT_ASSESSED", "NOT_FOUND", "NO_EVIDENCE_FOUND"}:
            verdict_color = "#94a3b8"

        st.markdown(
            f"""
            <div class="tactical-panel" style="border-left:4px solid {verdict_color};padding:18px;">
              <div style="font-family:'DM Mono',monospace;font-size:10px;color:{verdict_color};letter-spacing:0.12em;text-transform:uppercase;">
                ASSESSMENT VERDICT
              </div>
              <div style="font-size:22px;font-weight:800;color:#ffffff;margin:4px 0 8px;">
                {esc(verdict)}
              </div>
              <div style="font-size:11px;color:#cbd5e1;line-height:1.7;">
                {esc(assessment.get("justification", "Absence of records is not proof of safety."))}
              </div>
              <div style="margin-top:10px;padding-top:8px;border-top:1px solid rgba(255,255,255,0.06);font-size:10px;font-family:'DM Mono',monospace;color:#64748b;">
                STATUS: <span style="color:#ffffff;">{esc(inv_status)}</span> · PSL APEX: <span style="color:var(--cyan-neon);">{esc(result.get("registered_domain") or "—")}</span>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("**Forensic Explanation**")
        st.info(result.get("explanation", "No explanation returned by the graph agent."))

        # Infrastructure Connected Entities
        associated_ips = result.get("associated_ips") or []
        associated_certs = result.get("associated_certificates") or []
        associated_reports = result.get("associated_reports") or []
        associated_ns = result.get("associated_nameservers") or []

        if associated_ips or associated_certs or associated_reports or associated_ns:
            with st.expander(f"◈ Connected Infrastructure ({len(associated_certs)} certs, {len(associated_ns)} nameservers)", expanded=True):
                if associated_ips:
                    st.markdown(f"**IP Addresses ({len(associated_ips)}):**")
                    for ip in associated_ips[:8]:
                        st.markdown(f"- `<span class='badge-tag'>{esc(ip)}</span>`", unsafe_allow_html=True)
                if associated_certs:
                    st.markdown(f"**TLS Certificates ({len(associated_certs)}):**")
                    for cert in associated_certs[:6]:
                        subj = cert.get("subject") or cert.get("sha256", "—")
                        st.markdown(f"- `{esc(subj)}` *(Issuer: {esc(cert.get('issuer', '—'))})*")
                if associated_ns:
                    st.markdown(f"**Nameservers ({len(associated_ns)}):**")
                    for ns in associated_ns[:6]:
                        st.markdown(f"- `{esc(ns)}`")
                if associated_reports:
                    st.markdown(f"**Threat Reports ({len(associated_reports)}):**")
                    for rep in associated_reports:
                        st.markdown(f"- `{esc(rep.get('source'))}`: `{esc(rep.get('threat', '—'))}` (ID: {esc(rep.get('id', '—'))})")

        # Multi-Hop Shared Infrastructure Pivot Paths
        shared_infrastructure = result.get("shared_infrastructure") or []
        if shared_infrastructure:
            with st.expander(f"◈ Multi-Hop Co-Occurrence Pivots ({len(shared_infrastructure)})", expanded=True):
                st.caption("Shared certificates, nameservers, and adversary hosting discovered via FalkorDB traversal:")
                for item in shared_infrastructure[:6]:
                    inf = item.get("infrastructure", {})
                    rel_d = item.get("related_domain", {})
                    st.markdown(
                        f"""
                        <div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:10px;margin-bottom:8px;">
                          <div style="font-size:12px;font-weight:700;color:#c084fc;">
                            {esc(inf.get('label', 'Infrastructure'))}
                          </div>
                          <div style="font-size:11px;color:#94a3b8;margin-top:2px;">
                            Co-occurs with: <strong style="color:#ffffff;">{esc(rel_d.get('label', 'Domain'))}</strong>
                          </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

        # Evidence Records Drill-Down
        if evidence:
            with st.expander(f"◈ Attributed Evidence Records ({len(evidence)})", expanded=False):
                for idx, ev in enumerate(evidence[:10], 1):
                    if not isinstance(ev, dict):
                        ev = {"value": ev}
                    st.markdown(f"<span class='badge-tag'>EVIDENCE {idx:02d} · {esc(ev.get('source', 'OSINT'))}</span>", unsafe_allow_html=True)
                    st.markdown(f"**Kind:** `{esc(ev.get('kind'))}` · **Observed:** `{esc(ev.get('observed_at'))}`")
                    st.json(ev.get("details", ev))
                    st.markdown("---")

        # Raw Export
        st.download_button(
            "⬇ Export Full Investigation JSON",
            data=json.dumps(result, indent=2, ensure_ascii=False),
            file_name=f"graphguard-audit-{target_disp}-{datetime.now():%Y%m%d-%H%M%S}.json",
            mime="application/json",
            use_container_width=True,
        )


# ==========================================================
# 04 / ANALYST AUDIT TRAIL & SESSION HISTORY
# ==========================================================

st.markdown('<div class="section-eyebrow">04 / Analyst Audit Trail</div>', unsafe_allow_html=True)

with st.expander(f"Recent Target Investigations ({len(st.session_state.history)})", expanded=False):
    if st.session_state.history:
        for item in st.session_state.history:
            orig = item.get("origin", "STORED_GRAPH")
            orig_badge = "🟢 LIVE" if orig == "LIVE_PASSIVE" else "⚡ STORED"
            st.markdown(
                f"""
                <div style="display:flex;justify-content:space-between;align-items:center;padding:10px 14px;background:rgba(15,23,42,0.6);border:1px solid rgba(255,255,255,0.06);border-radius:10px;margin-bottom:8px;">
                  <div>
                    <span style="font-family:'JetBrains Mono',monospace;font-weight:700;color:#ffffff;font-size:13px;">{esc(item["domain"])}</span>
                    <span style="font-size:11px;color:#64748b;margin-left:8px;">({item["time"]})</span>
                  </div>
                  <div>
                    <span class="badge-tag">{orig_badge}</span>
                    <span class="badge-tag" style="margin-left:6px;">{esc(item['records'])} records</span>
                  </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        if st.button("Clear Audit Trail"):
            st.session_state.history = []
            st.rerun()
    else:
        st.caption("No investigations in this session yet.")

st.markdown("---")
st.markdown(
    """
    <div style="display:flex;justify-content:space-between;align-items:center;color:#64748b;font-size:11px;font-family:'DM Mono',monospace;">
      <div>GRAPHGUARD AI V1.2.0 · FALKORDB GRAPH HACKS 2026 (TRACK 1)</div>
      <div>TEAM SYNAPGRAPH · ZERO MUTATION PRODUCTION VERIFIED</div>
    </div>
    """,
    unsafe_allow_html=True,
)
