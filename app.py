import html
import json
import time
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import plotly.graph_objects as go
import streamlit as st


# ==============================
# Streamlit Setup
# ==============================

st.set_page_config(
    page_title="HackForge AI",
    page_icon="HF",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ==============================
# ML Asset Setup
# ==============================

MODEL_SETUP_STATUS: Dict[str, str] = {}
MODEL_SETUP_ERROR: Optional[str] = None

try:
    from model_loader import setup_models

    @st.cache_resource(show_spinner=False)
    def initialize_models() -> Dict[str, str]:
        return setup_models()

    with st.spinner("Preparing ML models..."):
        MODEL_SETUP_STATUS = initialize_models()
except Exception as exc:
    MODEL_SETUP_ERROR = str(exc)


# ==============================
# Real Backend Imports
# ==============================

BACKEND_IMPORT_ERRORS: Dict[str, str] = {}

if MODEL_SETUP_ERROR:
    BACKEND_IMPORT_ERRORS["Model setup"] = MODEL_SETUP_ERROR

try:
    from scanner.scanner import run_scan
except Exception as exc:
    run_scan = None
    BACKEND_IMPORT_ERRORS["Web scanner"] = str(exc)

try:
    from scanner.report_generator import ReportGenerator
except Exception as exc:
    ReportGenerator = None
    BACKEND_IMPORT_ERRORS["Report synthesis"] = str(exc)

try:
    from modules.text_scanner import scan_text_message
except Exception as exc:
    scan_text_message = None
    BACKEND_IMPORT_ERRORS["Text threat scanner"] = str(exc)

try:
    from modules.url_scanner import scan_live_url
except Exception as exc:
    scan_live_url = None
    BACKEND_IMPORT_ERRORS["URL threat scanner"] = str(exc)

try:
    from modules.ai_explainer import generate_ai_explanation
except Exception as exc:
    generate_ai_explanation = None
    BACKEND_IMPORT_ERRORS["AI explainer"] = str(exc)

try:
    from modules.intel_engine import (
        recommended_actions,
        text_risk_indicators,
        url_risk_indicators,
    )
except Exception as exc:
    recommended_actions = None
    text_risk_indicators = None
    url_risk_indicators = None
    BACKEND_IMPORT_ERRORS["Intel indicators"] = str(exc)


APP_VERSION = "2.0.0"
PAGES = {
    "home": "Home",
    "web": "Web Scan",
    "threat": "Threat Checks",
    "message": "Message Check",
    "url": "URL Check",
    "results": "Report",
    "analytics": "Analytics",
    "reference": "Coverage Reference",
}


def get_query_page() -> Optional[str]:
    try:
        page = st.query_params.get("page")
    except Exception:
        try:
            params = st.experimental_get_query_params()
            value = params.get("page")
            page = value[0] if isinstance(value, list) else value
        except Exception:
            page = None

    if isinstance(page, list):
        page = page[0] if page else None

    return page if page in PAGES else None


def set_query_page(page: str) -> None:
    try:
        st.query_params["page"] = page
    except Exception:
        try:
            st.experimental_set_query_params(page=page)
        except Exception:
            pass


def navigate(page: str) -> None:
    st.session_state.page = page
    set_query_page(page)


def init_state() -> None:
    defaults = {
        "page": "home",
        "scan_results": None,
        "threat_results": None,
        "last_result_type": None,
        "last_run_at": None,
        "selected_engine": "Home",
        "web_target": "",
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

    query_page = get_query_page()
    if query_page:
        st.session_state.page = query_page


init_state()


# ==============================
# Styling
# ==============================

CYBER_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&display=swap');

:root {
    --hf-bg: #050912;
    --hf-panel: rgba(9, 17, 29, 0.88);
    --hf-panel-strong: rgba(11, 21, 35, 0.95);
    --hf-line: rgba(108, 255, 183, 0.18);
    --hf-line-soft: rgba(140, 168, 206, 0.17);
    --hf-green: #31f58f;
    --hf-green-soft: rgba(49, 245, 143, 0.18);
    --hf-cyan: #50d5ff;
    --hf-amber: #f7c948;
    --hf-red: #ff5577;
    --hf-muted: #91a3bc;
    --hf-text: #edf6ff;
    --hf-blue: #101a2c;
}

html,
body,
[class*="css"] {
    font-family: "Inter", sans-serif;
}

#MainMenu,
footer,
header,
[data-testid="stToolbar"],
[data-testid="stDecoration"] {
    visibility: hidden;
    height: 0;
}

.stApp {
    color: var(--hf-text);
    background:
        radial-gradient(circle at 18% 6%, rgba(49, 245, 143, 0.12), transparent 25%),
        radial-gradient(circle at 82% 8%, rgba(80, 213, 255, 0.08), transparent 23%),
        radial-gradient(circle at 72% 88%, rgba(49, 245, 143, 0.06), transparent 26%),
        linear-gradient(rgba(255,255,255,0.018) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,0.018) 1px, transparent 1px),
        linear-gradient(145deg, #050912 0%, #07101d 48%, #03070d 100%);
    background-size: auto, auto, auto, 38px 38px, 38px 38px, auto;
}

.stApp::before {
    content: "";
    position: fixed;
    inset: 0;
    pointer-events: none;
    background:
        linear-gradient(115deg, transparent 0%, rgba(49,245,143,0.045) 45%, transparent 46%),
        repeating-linear-gradient(0deg, rgba(255,255,255,0.025) 0, rgba(255,255,255,0.025) 1px, transparent 1px, transparent 6px);
    mix-blend-mode: screen;
    opacity: 0.35;
    z-index: 0;
}

.block-container {
    max-width: 1540px;
    padding: 1.15rem 2.1rem 3rem;
}

section[data-testid="stSidebar"] {
    background:
        linear-gradient(180deg, rgba(8, 16, 28, 0.97), rgba(5, 10, 18, 0.98)),
        linear-gradient(rgba(49,245,143,0.04) 1px, transparent 1px),
        linear-gradient(90deg, rgba(49,245,143,0.035) 1px, transparent 1px);
    background-size: auto, 28px 28px, 28px 28px;
    border-right: 1px solid rgba(49, 245, 143, 0.16);
    box-shadow: 16px 0 36px rgba(0,0,0,0.22);
}

section[data-testid="stSidebar"] > div {
    padding-top: 1rem;
}

section[data-testid="stSidebar"] .block-container {
    padding-top: 1rem;
}

h1, h2, h3, h4, h5, h6, p, label, span {
    color: inherit;
}

[data-testid="stMarkdownContainer"] p {
    color: inherit;
}

div[data-testid="stVerticalBlock"] {
    gap: 0.85rem;
}

[data-testid="column"] {
    padding-top: 0;
}

.stTextInput input,
.stTextArea textarea,
.stNumberInput input,
.stSelectbox div[data-baseweb="select"] > div,
div[data-baseweb="input"] input {
    background: rgba(7, 14, 24, 0.94) !important;
    border: 1px solid rgba(144, 167, 204, 0.22) !important;
    color: #edf6ff !important;
    border-radius: 14px !important;
    min-height: 52px !important;
    box-shadow: inset 0 0 0 1px rgba(49,245,143,0.02), 0 14px 35px rgba(0,0,0,0.16) !important;
}

.stTextInput input:focus,
.stTextArea textarea:focus,
.stNumberInput input:focus {
    border-color: rgba(49, 245, 143, 0.62) !important;
    box-shadow: 0 0 0 2px rgba(49, 245, 143, 0.12), 0 0 24px rgba(49,245,143,0.08) !important;
}

.stTextArea textarea {
    min-height: 212px !important;
}

.stTextInput label,
.stTextArea label,
.stNumberInput label,
.stSlider label,
.stToggle label,
.stCheckbox label,
.stSelectbox label {
    color: #9eb0c7 !important;
    font-family: "IBM Plex Mono", monospace !important;
    font-size: 0.74rem !important;
    letter-spacing: 0.08em !important;
    text-transform: uppercase !important;
}

.stSlider [data-baseweb="slider"] div {
    color: var(--hf-green) !important;
}

.stSlider div[role="slider"] {
    background-color: var(--hf-green) !important;
    box-shadow: 0 0 18px rgba(49,245,143,0.5) !important;
}

.stToggle [data-testid="stWidgetLabel"] p,
.stCheckbox [data-testid="stWidgetLabel"] p {
    color: #b9c6d7 !important;
}

.stButton > button,
.stDownloadButton > button {
    width: 100%;
    min-height: 52px;
    border: 1px solid rgba(148, 170, 205, 0.18) !important;
    border-radius: 14px !important;
    background: rgba(8, 17, 29, 0.84) !important;
    color: #d9e7f6 !important;
    font-weight: 850 !important;
    letter-spacing: 0 !important;
    text-transform: none;
    box-shadow: 0 12px 32px rgba(0,0,0,0.16);
    transition: transform 0.2s ease, box-shadow 0.2s ease, filter 0.2s ease;
}

.stButton > button[kind="primary"],
.stDownloadButton > button {
    border-color: rgba(49, 245, 143, 0.42) !important;
    background: linear-gradient(180deg, rgba(52, 255, 150, 1), rgba(21, 199, 101, 1)) !important;
    color: #03150a !important;
    font-weight: 900 !important;
    letter-spacing: 0.04em !important;
    text-transform: uppercase;
    box-shadow: 0 0 26px rgba(49,245,143,0.24), inset 0 1px 0 rgba(255,255,255,0.34);
}

.stButton > button:hover,
.stDownloadButton > button:hover {
    transform: translateY(-1px);
    border-color: rgba(49,245,143,0.38) !important;
    filter: brightness(1.04);
    box-shadow: 0 0 26px rgba(49,245,143,0.14);
}

.stButton > button[kind="primary"]:hover,
.stDownloadButton > button:hover {
    box-shadow: 0 0 38px rgba(49,245,143,0.34), inset 0 1px 0 rgba(255,255,255,0.42);
}

section[data-testid="stSidebar"] .stButton > button {
    min-height: 44px;
    border: 1px solid rgba(148,170,205,0.16) !important;
    background: rgba(9, 19, 32, 0.82) !important;
    color: #d9e7f6 !important;
    box-shadow: none;
    text-transform: none;
    letter-spacing: 0;
    font-weight: 800 !important;
}

section[data-testid="stSidebar"] .stButton > button:hover {
    border-color: rgba(49,245,143,0.38) !important;
    box-shadow: 0 0 24px rgba(49,245,143,0.12);
}

.stButton > button:disabled {
    color: rgba(217,230,244,0.38) !important;
    background: rgba(13, 24, 38, 0.76) !important;
    border-color: rgba(148, 171, 205, 0.18) !important;
    box-shadow: none !important;
}

div[data-testid="stMetric"] {
    background: linear-gradient(180deg, rgba(13, 25, 41, 0.9), rgba(8, 16, 28, 0.88));
    border: 1px solid rgba(147, 174, 212, 0.16);
    border-radius: 16px;
    padding: 1rem 1.05rem;
    min-height: 104px;
    box-shadow: 0 12px 32px rgba(0,0,0,0.18);
}

div[data-testid="stMetricLabel"] {
    color: #93a6bf !important;
    font-family: "IBM Plex Mono", monospace !important;
    font-size: 0.71rem !important;
    letter-spacing: 0.08em !important;
}

div[data-testid="stMetricValue"] {
    color: #f4fbff !important;
    font-size: 1.45rem !important;
    font-weight: 900 !important;
}

.stAlert {
    border-radius: 16px !important;
    border: 1px solid rgba(49,245,143,0.18) !important;
    background: rgba(9, 17, 29, 0.9) !important;
}

.streamlit-expanderHeader {
    background: rgba(11, 22, 36, 0.82) !important;
    border-radius: 14px !important;
    border: 1px solid rgba(148,170,205,0.14) !important;
    color: #edf6ff !important;
    font-weight: 800 !important;
}

div[data-testid="stExpander"] {
    border: 1px solid rgba(148,170,205,0.14) !important;
    border-radius: 16px !important;
    background: rgba(7, 14, 24, 0.68) !important;
    overflow: hidden;
}

.hf-shell {
    position: relative;
    z-index: 1;
}

.hf-topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    padding: 0.45rem 0 1rem;
}

.hf-brand-mini {
    display: inline-flex;
    align-items: center;
    gap: 0.75rem;
    font-weight: 900;
    letter-spacing: 0.01em;
}

.hf-mark {
    width: 42px;
    height: 42px;
    display: grid;
    place-items: center;
    border: 1px solid rgba(49,245,143,0.36);
    border-radius: 12px;
    color: var(--hf-green);
    background: rgba(49,245,143,0.08);
    font-family: "IBM Plex Mono", monospace;
    box-shadow: 0 0 26px rgba(49,245,143,0.14);
}

.hf-status {
    display: inline-flex;
    align-items: center;
    gap: 0.6rem;
    color: #b5c2d4;
    font-family: "IBM Plex Mono", monospace;
    font-size: 0.73rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
}

.main-nav {
    display: grid;
    grid-template-columns: repeat(5, minmax(0, 1fr));
    gap: 0.72rem;
    margin: 0.2rem 0 1.1rem;
}

.main-nav a {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.8rem;
    min-height: 58px;
    padding: 0.82rem 0.95rem;
    border: 1px solid rgba(148,170,205,0.15);
    border-radius: 15px;
    background: rgba(7, 15, 26, 0.72);
    color: #d9e7f6 !important;
    text-decoration: none !important;
    box-shadow: 0 12px 34px rgba(0,0,0,0.16);
    transition: transform 0.18s ease, border-color 0.18s ease, background 0.18s ease;
}

.main-nav a:hover {
    transform: translateY(-2px);
    border-color: rgba(49,245,143,0.38);
    background: rgba(11, 25, 41, 0.88);
}

.main-nav strong {
    display: block;
    color: #f4fbff;
    font-size: 0.88rem;
}

.main-nav span {
    display: block;
    color: #7f92aa;
    font-family: "IBM Plex Mono", monospace;
    font-size: 0.66rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
}

.main-nav .nav-mark {
    width: 28px;
    height: 28px;
    display: grid;
    place-items: center;
    flex: 0 0 auto;
    border-radius: 9px;
    background: rgba(49,245,143,0.10);
    color: var(--hf-green);
    font-family: "IBM Plex Mono", monospace;
    font-size: 0.7rem;
    font-weight: 900;
}

.hf-dot {
    width: 8px;
    height: 8px;
    border-radius: 99px;
    background: var(--hf-green);
    box-shadow: 0 0 14px rgba(49,245,143,0.9);
}

.hf-dot.warn {
    background: var(--hf-amber);
    box-shadow: 0 0 14px rgba(247,201,72,0.8);
}

.hero-card {
    position: relative;
    overflow: hidden;
    border: 1px solid rgba(49,245,143,0.18);
    border-radius: 28px;
    padding: clamp(1.65rem, 3vw, 3.05rem);
    background:
        linear-gradient(135deg, rgba(12, 25, 42, 0.9), rgba(5, 12, 22, 0.92)),
        radial-gradient(circle at 82% 26%, rgba(49,245,143,0.18), transparent 28%);
    box-shadow: 0 30px 80px rgba(0,0,0,0.34), inset 0 1px 0 rgba(255,255,255,0.05);
}

.hero-card::before {
    content: "";
    position: absolute;
    inset: -40%;
    background:
        conic-gradient(from 120deg, transparent 0deg, rgba(49,245,143,0.13) 32deg, transparent 74deg),
        repeating-linear-gradient(90deg, rgba(255,255,255,0.03) 0 1px, transparent 1px 16px);
    animation: slow-pan 13s linear infinite;
    opacity: 0.7;
}

.hero-card::after {
    content: "";
    position: absolute;
    inset: 0;
    background: linear-gradient(180deg, transparent, rgba(4,8,14,0.28));
    pointer-events: none;
}

.hero-inner {
    position: relative;
    z-index: 1;
}

.hero-kicker,
.section-kicker,
.micro-label {
    color: #7d91aa;
    font-family: "IBM Plex Mono", monospace;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.16em;
    text-transform: uppercase;
}

.hero-title {
    margin-top: 0.8rem;
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 0.08em;
    font-size: clamp(2.75rem, 6.4vw, 6.8rem);
    line-height: 0.92;
    font-weight: 900;
    letter-spacing: 0;
}

.hero-title .letter {
    display: inline-block;
    opacity: 0;
    transform: translateY(26px) scale(0.92);
    color: #f5fbff;
    text-shadow: 0 0 28px rgba(49,245,143,0.2);
    animation: letter-reveal 0.72s cubic-bezier(.2,.9,.2,1) forwards;
}

.hero-title .letter:nth-child(1) { animation-delay: 0.05s; }
.hero-title .letter:nth-child(2) { animation-delay: 0.14s; }
.hero-title .letter:nth-child(3) { animation-delay: 0.23s; }
.hero-title .letter:nth-child(4) { animation-delay: 0.32s; }
.hero-title .letter:nth-child(5) { animation-delay: 0.41s; }
.hero-title .letter:nth-child(6) { animation-delay: 0.50s; }
.hero-title .letter:nth-child(7) { animation-delay: 0.59s; }
.hero-title .letter:nth-child(8) { animation-delay: 0.68s; }
.hero-title .letter:nth-child(9) { animation-delay: 0.77s; }

.hero-title .ai {
    margin-left: 0.18em;
    color: var(--hf-green);
    opacity: 0;
    animation: title-ai 0.75s ease forwards;
    animation-delay: 1.02s;
    text-shadow: 0 0 34px rgba(49,245,143,0.46);
}

.hero-subtitle {
    margin-top: 1.1rem;
    max-width: 780px;
    font-size: clamp(1.05rem, 2vw, 1.45rem);
    color: #d9e6f5;
    font-weight: 700;
}

.hero-copy {
    margin-top: 1rem;
    max-width: 760px;
    color: #95a7bd;
    line-height: 1.72;
    font-size: 0.98rem;
}

.status-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 0.9rem;
    margin-top: 1.9rem;
}

.status-strip {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    padding: 1rem 1.1rem;
    border: 1px solid rgba(148, 170, 205, 0.16);
    border-radius: 16px;
    background: rgba(7, 15, 26, 0.72);
    backdrop-filter: blur(18px);
}

.status-strip strong {
    display: block;
    color: #f5fbff;
    font-size: 0.92rem;
}

.status-strip span {
    color: #8799b0;
    font-family: "IBM Plex Mono", monospace;
    font-size: 0.71rem;
    letter-spacing: 0.07em;
    text-transform: uppercase;
}

.launch-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 1rem;
    margin-top: 1rem;
}

.launch-card {
    display: flex;
    flex-direction: column;
    min-height: 250px;
    position: relative;
    overflow: hidden;
    padding: 1.45rem;
    border-radius: 22px;
    border: 1px solid rgba(148, 170, 205, 0.15);
    background:
        linear-gradient(180deg, rgba(13, 27, 45, 0.88), rgba(6, 14, 25, 0.9)),
        radial-gradient(circle at 88% 14%, rgba(49,245,143,0.13), transparent 28%);
    color: #edf6ff !important;
    text-decoration: none !important;
    box-shadow: 0 18px 48px rgba(0,0,0,0.28);
    transition: transform 0.22s ease, border-color 0.22s ease, box-shadow 0.22s ease;
}

.launch-card::before {
    content: "";
    position: absolute;
    inset: 0;
    background: linear-gradient(110deg, transparent, rgba(49,245,143,0.11), transparent);
    transform: translateX(-100%);
    transition: transform 0.55s ease;
}

.launch-card:hover {
    transform: translateY(-4px);
    border-color: rgba(49,245,143,0.46);
    box-shadow: 0 26px 70px rgba(0,0,0,0.32), 0 0 36px rgba(49,245,143,0.16);
}

.launch-card:hover::before {
    transform: translateX(100%);
}

.launch-icon {
    width: 56px;
    height: 56px;
    display: grid;
    place-items: center;
    border-radius: 16px;
    border: 1px solid rgba(49,245,143,0.35);
    background: rgba(49,245,143,0.08);
    color: var(--hf-green);
    font-family: "IBM Plex Mono", monospace;
    font-size: 1.1rem;
    font-weight: 900;
    box-shadow: 0 0 24px rgba(49,245,143,0.13);
}

.launch-card h3 {
    margin: 1.1rem 0 0.6rem;
    color: #f4fbff;
    font-size: 1.15rem;
    line-height: 1.25;
    font-weight: 900;
}

.launch-card p {
    color: #9badc3;
    line-height: 1.65;
    font-size: 0.91rem;
    margin: 0;
}

.launch-footer {
    position: relative;
    margin-top: auto;
    display: flex;
    align-items: center;
    justify-content: space-between;
    color: var(--hf-green);
    font-family: "IBM Plex Mono", monospace;
    font-size: 0.72rem;
    font-weight: 800;
    letter-spacing: 0.1em;
    text-transform: uppercase;
}

.reference-band {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    margin-top: 0.95rem;
    padding: 1rem 1.15rem;
    border: 1px solid rgba(148,170,205,0.13);
    border-radius: 18px;
    background: rgba(7, 15, 26, 0.58);
    color: #dce8f6 !important;
    text-decoration: none !important;
}

.reference-band strong {
    color: #f4fbff;
    display: block;
    font-size: 0.96rem;
}

.reference-band span {
    color: #91a3ba;
    display: block;
    margin-top: 0.25rem;
    line-height: 1.5;
    font-size: 0.86rem;
}

.reference-band small {
    color: var(--hf-green);
    font-family: "IBM Plex Mono", monospace;
    font-size: 0.7rem;
    font-weight: 900;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    white-space: nowrap;
}

.section-head {
    display: flex;
    justify-content: space-between;
    align-items: end;
    gap: 1rem;
    margin: 0.2rem 0 1rem;
}

.section-title {
    margin: 0.35rem 0 0;
    color: #f4fbff;
    font-size: clamp(2rem, 4vw, 3.4rem);
    line-height: 1;
    font-weight: 900;
    letter-spacing: 0;
}

.section-subtitle {
    margin-top: 0.65rem;
    color: #96a8be;
    line-height: 1.65;
    max-width: 790px;
}

.panel {
    position: relative;
    overflow: hidden;
    border: 1px solid rgba(148, 170, 205, 0.16);
    border-radius: 22px;
    background: linear-gradient(180deg, rgba(11, 23, 38, 0.9), rgba(6, 13, 24, 0.9));
    box-shadow: 0 22px 60px rgba(0,0,0,0.28), inset 0 1px 0 rgba(255,255,255,0.04);
    padding: 1.35rem;
}

.panel::before {
    content: "";
    position: absolute;
    left: 0;
    right: 0;
    top: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, rgba(49,245,143,0.66), transparent);
}

.panel-title {
    margin: 0;
    color: #f4fbff;
    font-size: 1.25rem;
    font-weight: 900;
}

.panel-copy {
    color: #91a3ba;
    line-height: 1.62;
    font-size: 0.91rem;
    margin-top: 0.55rem;
}

.mission-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 0.8rem;
    margin-top: 1rem;
}

.mission-chip {
    border: 1px solid rgba(148,170,205,0.14);
    border-radius: 14px;
    padding: 0.85rem;
    background: rgba(6, 14, 24, 0.72);
}

.mission-chip span {
    color: #7d8fa7;
    display: block;
    font-family: "IBM Plex Mono", monospace;
    font-size: 0.68rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
}

.mission-chip strong {
    color: #f4fbff;
    display: block;
    margin-top: 0.35rem;
    font-size: 0.95rem;
}

.sidebar-card {
    border: 1px solid rgba(148,170,205,0.15);
    border-radius: 18px;
    padding: 1rem;
    background: rgba(7, 15, 26, 0.72);
    margin-bottom: 0.8rem;
}

.sidebar-brand {
    display: flex;
    align-items: center;
    gap: 0.8rem;
    margin-bottom: 0.9rem;
}

.sidebar-brand-mark {
    width: 46px;
    height: 46px;
    display: grid;
    place-items: center;
    border-radius: 14px;
    border: 1px solid rgba(49,245,143,0.38);
    background: rgba(49,245,143,0.09);
    color: var(--hf-green);
    font-family: "IBM Plex Mono", monospace;
    font-weight: 900;
}

.sidebar-brand h2 {
    margin: 0;
    color: #f4fbff;
    font-size: 1.05rem;
    font-weight: 900;
}

.sidebar-brand span {
    color: #7588a0;
    display: block;
    font-family: "IBM Plex Mono", monospace;
    font-size: 0.62rem;
    letter-spacing: 0.11em;
    text-transform: uppercase;
}

.side-row {
    display: flex;
    justify-content: space-between;
    gap: 0.75rem;
    border-top: 1px solid rgba(148,170,205,0.11);
    padding-top: 0.62rem;
    margin-top: 0.62rem;
}

.side-row span {
    color: #788ca5;
    font-family: "IBM Plex Mono", monospace;
    font-size: 0.66rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
}

.side-row strong {
    color: #e9f4ff;
    font-size: 0.78rem;
    text-align: right;
}

.severity-pill,
.verdict-pill {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 76px;
    padding: 0.34rem 0.65rem;
    border-radius: 999px;
    font-family: "IBM Plex Mono", monospace;
    font-size: 0.68rem;
    font-weight: 900;
    letter-spacing: 0.08em;
    text-transform: uppercase;
}

.sev-critical {
    color: #ffd7de;
    background: rgba(255,85,119,0.16);
    border: 1px solid rgba(255,85,119,0.38);
}

.sev-high {
    color: #ffe3bf;
    background: rgba(255,145,77,0.16);
    border: 1px solid rgba(255,145,77,0.38);
}

.sev-medium {
    color: #fff3bc;
    background: rgba(247,201,72,0.16);
    border: 1px solid rgba(247,201,72,0.34);
}

.sev-low {
    color: #c9fff0;
    background: rgba(49,245,143,0.12);
    border: 1px solid rgba(49,245,143,0.28);
}

.status-pill {
    border-radius: 999px;
    padding: 0.42rem 0.72rem;
    font-family: "IBM Plex Mono", monospace;
    font-size: 0.66rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    white-space: nowrap;
}

.status-confirmed {
    color: #c9fff0;
    background: rgba(49,245,143,0.12);
    border: 1px solid rgba(49,245,143,0.3);
}

.status-review {
    color: #fff3bc;
    background: rgba(247,201,72,0.15);
    border: 1px solid rgba(247,201,72,0.34);
}

.report-brief {
    padding: 1.3rem;
    border-radius: 20px;
    border: 1px solid rgba(49,245,143,0.21);
    background:
        linear-gradient(135deg, rgba(12, 28, 43, 0.94), rgba(6, 14, 24, 0.94)),
        radial-gradient(circle at 90% 12%, rgba(49,245,143,0.15), transparent 26%);
    box-shadow: 0 22px 60px rgba(0,0,0,0.24);
}

.report-brief h3 {
    margin: 0 0 0.55rem;
    color: #f4fbff;
    font-size: 1.2rem;
    font-weight: 900;
}

.report-brief p {
    margin: 0;
    color: #b7c5d7;
    line-height: 1.72;
}

.finding-card {
    border: 1px solid rgba(148,170,205,0.14);
    border-radius: 18px;
    padding: 1rem;
    background: rgba(7, 15, 26, 0.72);
    margin-bottom: 0.8rem;
}

.finding-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    margin-bottom: 0.75rem;
}

.finding-head h4 {
    margin: 0;
    color: #f3f9ff;
    font-size: 1rem;
    font-weight: 900;
}

.finding-badges {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
    justify-content: flex-end;
}

.finding-meta {
    color: #8b9db4;
    font-family: "IBM Plex Mono", monospace;
    font-size: 0.72rem;
    word-break: break-word;
}

.confidence-track {
    width: 100%;
    height: 8px;
    border-radius: 99px;
    overflow: hidden;
    background: rgba(148,170,205,0.13);
}

.confidence-fill {
    height: 100%;
    border-radius: inherit;
    background: linear-gradient(90deg, var(--hf-green), var(--hf-cyan));
    box-shadow: 0 0 16px rgba(49,245,143,0.35);
}

.detail-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 0.8rem;
    margin-top: 0.8rem;
}

.detail-tile {
    border: 1px solid rgba(148,170,205,0.12);
    border-radius: 14px;
    background: rgba(5, 11, 20, 0.68);
    padding: 0.8rem;
}

.detail-tile span {
    color: #778aa2;
    display: block;
    font-family: "IBM Plex Mono", monospace;
    font-size: 0.66rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
}

.detail-tile strong {
    color: #f4fbff;
    display: block;
    margin-top: 0.32rem;
}

.indicator-grid,
.coverage-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 0.85rem;
}

.indicator-card,
.coverage-card {
    border: 1px solid rgba(148,170,205,0.15);
    border-radius: 18px;
    background: rgba(7, 15, 26, 0.76);
    padding: 1rem;
    min-height: 130px;
    box-shadow: 0 16px 42px rgba(0,0,0,0.18);
}

.indicator-card strong,
.coverage-card strong {
    color: #f4fbff;
    display: block;
    font-size: 0.98rem;
    margin-bottom: 0.5rem;
}

.indicator-card span,
.coverage-card span {
    color: #91a3ba;
    line-height: 1.55;
    font-size: 0.88rem;
}

.coverage-card small {
    display: inline-flex;
    margin-bottom: 0.7rem;
    color: var(--hf-green);
    border: 1px solid rgba(49,245,143,0.26);
    border-radius: 999px;
    padding: 0.22rem 0.5rem;
    font-family: "IBM Plex Mono", monospace;
    font-size: 0.62rem;
    font-weight: 800;
    letter-spacing: 0.08em;
    text-transform: uppercase;
}

.empty-state {
    border: 1px solid rgba(148,170,205,0.16);
    border-radius: 22px;
    background: rgba(7, 15, 26, 0.72);
    padding: 2rem;
    text-align: center;
}

.empty-state h3 {
    color: #f4fbff;
    margin: 0 0 0.65rem;
}

.empty-state p {
    color: #95a7bd;
    margin: 0 auto;
    max-width: 660px;
    line-height: 1.7;
}

.chart-frame {
    border: 1px solid rgba(148,170,205,0.14);
    border-radius: 20px;
    background: rgba(7, 15, 26, 0.72);
    padding: 0.8rem;
}

.footer-note {
    color: #6f8198;
    font-family: "IBM Plex Mono", monospace;
    font-size: 0.68rem;
    letter-spacing: 0.1em;
    margin-top: 1.5rem;
    text-transform: uppercase;
}

@keyframes letter-reveal {
    0% { opacity: 0; transform: translateY(26px) scale(0.92); filter: blur(6px); }
    55% { opacity: 1; filter: blur(0); }
    100% { opacity: 1; transform: translateY(0) scale(1); filter: blur(0); }
}

@keyframes title-ai {
    from { opacity: 0; transform: translateX(16px); filter: blur(6px); }
    to { opacity: 1; transform: translateX(0); filter: blur(0); }
}

@keyframes slow-pan {
    from { transform: translateX(-8%) rotate(0deg); }
    to { transform: translateX(8%) rotate(360deg); }
}

@media (max-width: 1050px) {
    .main-nav,
    .launch-grid,
    .indicator-grid,
    .coverage-grid,
    .mission-grid,
    .detail-grid,
    .status-grid {
        grid-template-columns: 1fr;
    }

    .section-head,
    .hf-topbar {
        align-items: flex-start;
        flex-direction: column;
    }
}
</style>
"""

st.markdown(CYBER_CSS, unsafe_allow_html=True)


# ==============================
# Helpers
# ==============================

def safe_text(value: Any, default: str = "Not available") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def esc(value: Any) -> str:
    return html.escape(safe_text(value, ""))


def to_percent(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if number <= 1:
        number *= 100
    return max(0.0, min(100.0, number))


def normalize_confidence(value: Any) -> float:
    return round(to_percent(value), 1)


def severity_class(severity: str) -> str:
    sev = safe_text(severity, "low").lower()
    if sev not in {"critical", "high", "medium", "low"}:
        sev = "low"
    return f"sev-{sev}"


def is_ml_suspected_finding(finding: Dict[str, Any]) -> bool:
    title = safe_text(finding.get("vulnerability_type") or finding.get("title"), "").lower()
    source = safe_text(finding.get("source"), "").lower()
    status = safe_text(finding.get("validation_status"), "").lower()
    cwe = safe_text(finding.get("cwe"), "").lower()
    return (
        "ml suspected" in title
        or source == "ml_prediction"
        or status == "needs_review"
        or cwe == "heuristic-ml"
    )


def finding_review_label(finding: Dict[str, Any]) -> Tuple[str, str]:
    if is_ml_suspected_finding(finding):
        return "Needs Review", "status-review"
    return "Confirmed", "status-confirmed"


def severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = Counter(safe_text(f.get("severity"), "low").lower() for f in findings)
    return {
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
    }


def calculate_risk_level(risk_score: float) -> str:
    if risk_score >= 70:
        return "critical"
    if risk_score >= 45:
        return "high"
    if risk_score >= 20:
        return "medium"
    return "low"


def ensure_url(target: str) -> str:
    cleaned = target.strip()
    if not cleaned:
        raise ValueError("Enter a target URL before initiating assessment.")
    parsed = urlparse(cleaned)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Use a full target URL such as https://example.com.")
    return cleaned.rstrip("/")


def backend_ready_for(engine: str) -> bool:
    required = {
        "web": ["Web scanner"],
        "threat_text": ["Text threat scanner"],
        "threat_url": ["URL threat scanner"],
    }
    return not any(name in BACKEND_IMPORT_ERRORS for name in required.get(engine, []))


def backend_status_label(engine: str) -> str:
    return "Online" if backend_ready_for(engine) else "Attention"


def extract_json_lines(data: Any) -> str:
    try:
        return json.dumps(data, indent=2, default=str)
    except Exception:
        return safe_text(data)


def build_web_ai_overview(scan_data: Dict[str, Any], report: Optional[Dict[str, Any]]) -> str:
    if report:
        summary = report.get("executive_summary", {}).get("summary")
        if summary:
            return summary

    findings = scan_data.get("validated_results", [])
    review_count = sum(1 for item in findings if is_ml_suspected_finding(item))
    confirmed_count = max(0, len(findings) - review_count)
    risk = scan_data.get("risk_assessment", {})
    risk_level = safe_text(risk.get("risk_level"), "unknown").upper()
    risk_score = risk.get("risk_score", 0)
    return (
        f"HackForge AI completed the assessment with a {risk_level} exposure profile "
        f"and a risk score of {risk_score}/100 across {len(findings)} reported findings. "
        f"{confirmed_count} are confirmed by active checks or scanner rules, and {review_count} are ML leads that need review."
    )


def explain_finding_for_reader(finding: Dict[str, Any]) -> str:
    title = safe_text(finding.get("vulnerability_type") or finding.get("title"), "Security finding")
    lowered = title.lower()
    confidence = normalize_confidence(finding.get("confidence", 0))
    severity = safe_text(finding.get("severity"), "low").lower()

    if "sql" in lowered:
        base = (
            "This finding means the scanner saw signs that user input may be reaching a database query. "
            "If confirmed, an attacker could try special input to read, change, or delete data."
        )
    elif "xss" in lowered or "cross site" in lowered:
        base = (
            "This finding means a page may be reflecting user input back into the browser. "
            "If confirmed, an attacker could make a victim's browser run unwanted script code."
        )
    elif "csrf" in lowered:
        base = (
            "This finding means a form may allow an action without a strong anti-CSRF token. "
            "If confirmed, another site could trick a logged-in user into sending an unwanted request."
        )
    elif "cookie" in lowered:
        base = (
            "This finding means a browser cookie may be missing protective flags. "
            "If confirmed, the session data may be easier to steal or misuse in some attack scenarios."
        )
    elif "misconfiguration" in lowered or "header" in lowered:
        base = (
            "This finding means the website is missing one or more hardening settings. "
            "These settings help browsers block clickjacking, unsafe content loading, and other common attacks."
        )
    else:
        base = (
            "This finding means the scanner found a pattern that deserves review. "
            "It may not be an immediate exploit, but it should be checked and fixed if it affects a real user path."
        )

    if is_ml_suspected_finding(finding):
        base += " This is an ML lead, not a proven exploit. Treat it as something to review before calling it a confirmed vulnerability."

    return f"{base} Current severity is {severity}, and scanner confidence is {confidence}%."


def summarize_finding_details(details: Any) -> List[str]:
    if not isinstance(details, dict) or not details:
        return []

    summary: List[str] = []
    reason = details.get("reason")
    if reason:
        summary.append(safe_text(reason))

    issues = details.get("issues")
    if isinstance(issues, list):
        summary.extend(safe_text(issue) for issue in issues if safe_text(issue, ""))

    cookie_name = details.get("cookie_name")
    if cookie_name:
        summary.append(f"Cookie reviewed: {cookie_name}")

    score = details.get("score")
    if score is not None:
        summary.append(f"Security header score: {score}")

    missing = details.get("missing")
    if isinstance(missing, list) and missing:
        summary.append(f"Missing headers: {', '.join(str(item) for item in missing[:5])}")

    if not summary:
        for key in ["manual_probe", "sqlmap", "xsstrike"]:
            if key in details:
                summary.append(f"{key.replace('_', ' ').title()} returned supporting evidence.")

    return summary[:5]


def run_web_assessment(target: str, depth: int, pages: int) -> Dict[str, Any]:
    if run_scan is None:
        detail = BACKEND_IMPORT_ERRORS.get("Web scanner", "Web scanner backend is unavailable.")
        raise RuntimeError(f"Web scanner backend is unavailable: {detail}")

    started = time.time()
    raw_scan = run_scan(target, int(depth), int(pages))
    duration = round(time.time() - started, 2)

    findings = raw_scan.get("final_findings", []) or []
    risk_score = float(raw_scan.get("risk_score", 0) or 0)
    counts = severity_counts(findings)
    crawl_summary = raw_scan.get("crawl_summary", {}) or {}

    normalized = {
        "scan_id": f"HF-{int(time.time())}",
        "scan_type": "web",
        "target_url": raw_scan.get("target_url", target),
        "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "duration": duration,
        "crawl_summary": crawl_summary,
        "crawl_data": raw_scan.get("raw_crawl_data", {}) or {},
        "raw_scan": raw_scan,
        "validated_results": findings,
        "risk_assessment": {
            "risk_score": round(risk_score, 2),
            "overall_score": round(max(0, 100 - risk_score), 2),
            "risk_level": calculate_risk_level(risk_score),
            "critical_count": counts["critical"],
            "high_count": counts["high"],
            "medium_count": counts["medium"],
            "low_count": counts["low"],
            "total_findings": len(findings),
        },
    }

    report = None
    if ReportGenerator is not None:
        try:
            report = ReportGenerator(normalized).generate()
        except Exception as exc:
            normalized["report_error"] = str(exc)

    normalized["report"] = report
    normalized["ai_overview"] = build_web_ai_overview(normalized, report)
    return normalized


def run_text_assessment(message: str) -> Dict[str, Any]:
    if scan_text_message is None:
        detail = BACKEND_IMPORT_ERRORS.get("Text threat scanner", "Text scanner backend is unavailable.")
        raise RuntimeError(f"Text threat scanner is unavailable: {detail}")

    if not message.strip():
        raise ValueError("Paste suspicious communication before launching analysis.")

    base = scan_text_message(message)
    indicators = text_risk_indicators(message) if text_risk_indicators else []
    if not indicators and "Dangerous" in safe_text(base.get("status")):
        indicators = ["Classifier detected malicious communication patterns"]

    actions = recommended_actions(base.get("status", "")) if recommended_actions else [
        "Verify the sender through an independent channel",
        "Do not share credentials, OTPs, or financial information",
    ]

    if generate_ai_explanation is not None:
        advisory = generate_ai_explanation(
            "Text Communication Scan",
            base,
            indicators or ["no major explicit lexical indicators"],
        )
    else:
        advisory = (
            f"HackForge AI classified this communication as {base.get('status')} "
            f"with {base.get('confidence')}% confidence."
        )

    return {
        "scan_type": "threat_text",
        "label": "Communication Threat Analyzer",
        "submitted": message,
        "result": base,
        "indicators": indicators,
        "actions": actions,
        "ai": advisory.strip(),
        "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def run_url_assessment(url: str) -> Dict[str, Any]:
    if scan_live_url is None:
        detail = BACKEND_IMPORT_ERRORS.get("URL threat scanner", "URL scanner backend is unavailable.")
        raise RuntimeError(f"URL threat scanner is unavailable: {detail}")

    cleaned = url.strip()
    if not cleaned:
        raise ValueError("Enter a URL before launching malicious URL analysis.")

    base = scan_live_url(cleaned)
    indicators: List[str] = []
    indicators.extend(base.get("reasons", []) or [])
    if url_risk_indicators:
        indicators.extend(url_risk_indicators(cleaned))
    indicators = list(dict.fromkeys(indicators))

    actions = recommended_actions(base.get("status", "")) if recommended_actions else [
        "Avoid opening the link directly",
        "Inspect the destination in a sandbox before access",
    ]

    if generate_ai_explanation is not None:
        advisory = generate_ai_explanation(
            "URL Threat Scan",
            base,
            indicators or ["no strong lexical anomalies"],
        )
    else:
        advisory = (
            f"HackForge AI classified this URL as {base.get('status')} "
            f"with {base.get('confidence')}% confidence."
        )

    return {
        "scan_type": "threat_url",
        "label": "Malicious URL Analyzer",
        "submitted": cleaned,
        "result": base,
        "indicators": indicators,
        "actions": actions,
        "ai": advisory.strip(),
        "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def store_web_result(result: Dict[str, Any]) -> None:
    st.session_state.scan_results = result
    st.session_state.threat_results = None
    st.session_state.last_result_type = "web"
    st.session_state.last_run_at = result.get("started_at")
    navigate("results")


def store_threat_result(result: Dict[str, Any]) -> None:
    st.session_state.threat_results = result
    st.session_state.scan_results = None
    st.session_state.last_result_type = "threat"
    st.session_state.last_run_at = result.get("started_at")
    navigate("results")


def plot_layout(fig: go.Figure, title: Optional[str] = None) -> go.Figure:
    layout = {
        "paper_bgcolor": "rgba(0,0,0,0)",
        "plot_bgcolor": "rgba(0,0,0,0)",
        "font": {"color": "#d8e6f5", "family": "Inter"},
        "margin": {"l": 20, "r": 20, "t": 54 if title else 20, "b": 20},
        "legend": {
            "orientation": "h",
            "yanchor": "bottom",
            "y": 1.02,
            "xanchor": "right",
            "x": 1,
        },
    }
    if title:
        layout["title"] = title
    fig.update_layout(**layout)
    return fig


def create_risk_gauge(value: float, title: str) -> go.Figure:
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=max(0, min(100, value)),
            number={"suffix": "/100", "font": {"size": 34, "color": "#f4fbff"}},
            title={"text": title, "font": {"size": 16, "color": "#a9bad0"}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": "#7f92aa"},
                "bar": {"color": "#31f58f"},
                "bgcolor": "rgba(255,255,255,0.03)",
                "borderwidth": 1,
                "bordercolor": "rgba(148,170,205,0.20)",
                "steps": [
                    {"range": [0, 25], "color": "rgba(49,245,143,0.16)"},
                    {"range": [25, 55], "color": "rgba(247,201,72,0.14)"},
                    {"range": [55, 80], "color": "rgba(255,145,77,0.15)"},
                    {"range": [80, 100], "color": "rgba(255,85,119,0.16)"},
                ],
                "threshold": {
                    "line": {"color": "#50d5ff", "width": 4},
                    "thickness": 0.75,
                    "value": value,
                },
            },
        )
    )
    return plot_layout(fig)


def render_topbar() -> None:
    backend_online = len(BACKEND_IMPORT_ERRORS) == 0
    status_text = "Ready to scan" if backend_online else "Setup needs attention"
    dot_class = "hf-dot" if backend_online else "hf-dot warn"
    st.markdown(
        f"""
        <div class="hf-shell hf-topbar">
            <div class="hf-brand-mini">
                <div class="hf-mark">HF</div>
                <div>
                    <div style="font-size:1.02rem;">HackForge AI</div>
                    <div class="micro-label">Security toolkit</div>
                </div>
            </div>
            <div class="hf-status"><span class="{dot_class}"></span>{status_text}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_main_navigation() -> None:
    labels = [
        ("Home", "home"),
        ("Web Scan", "web"),
        ("Message Check", "message"),
        ("URL Check", "url"),
        ("Report", "results"),
        ("Analytics", "analytics"),
    ]
    cols = st.columns(len(labels), gap="small")
    for col, (label, page) in zip(cols, labels):
        with col:
            is_current = st.session_state.page == page
            st.button(
                label,
                key=f"top_nav_{page}",
                on_click=navigate,
                args=(page,),
                use_container_width=True,
                type="primary" if is_current else "secondary",
            )


def sidebar_button(label: str, page: str) -> None:
    st.button(label, key=f"nav_{page}", on_click=navigate, args=(page,))


def render_sidebar() -> None:
    with st.sidebar:
        selected_engine = PAGES.get(st.session_state.page, "Home")
        last_run = st.session_state.last_run_at or "No report yet"
        project_status = "Ready" if not BACKEND_IMPORT_ERRORS else "Needs setup"
        st.markdown(
            f"""
            <div class="sidebar-card">
                <div class="sidebar-brand">
                    <div class="sidebar-brand-mark">HF</div>
                    <div>
                        <h2>HackForge AI</h2>
                        <span>Security toolkit</span>
                    </div>
                </div>
                <div class="side-row"><span>Now Viewing</span><strong>{esc(selected_engine)}</strong></div>
                <div class="side-row"><span>Status</span><strong>{project_status}</strong></div>
                <div class="side-row"><span>Last Report</span><strong>{esc(last_run)}</strong></div>
            </div>
            <div class="sidebar-card">
                <div class="micro-label">Available checks</div>
                <div class="side-row"><span>Website</span><strong>Forms, headers, routes</strong></div>
                <div class="side-row"><span>Message</span><strong>Phishing and scam cues</strong></div>
                <div class="side-row"><span>URL</span><strong>Suspicious link patterns</strong></div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if st.session_state.page == "web":
            st.markdown(
                """
                <div class="sidebar-card" style="margin-top:0.9rem;">
                    <div class="micro-label">What happens here</div>
                    <div class="side-row"><span>1</span><strong>Visit website pages</strong></div>
                    <div class="side-row"><span>2</span><strong>Check forms and headers</strong></div>
                    <div class="side-row"><span>3</span><strong>Create a clear report</strong></div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        if st.session_state.page in {"threat", "message", "url"}:
            st.markdown(
                """
                <div class="sidebar-card" style="margin-top:0.9rem;">
                    <div class="micro-label">What happens here</div>
                    <div class="side-row"><span>Text</span><strong>Check suspicious messages</strong></div>
                    <div class="side-row"><span>URL</span><strong>Check risky links</strong></div>
                    <div class="side-row"><span>Advice</span><strong>Show next steps</strong></div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        if BACKEND_IMPORT_ERRORS:
            with st.expander("Backend import details"):
                for name, message in BACKEND_IMPORT_ERRORS.items():
                    st.caption(f"{name}: {message}")


def render_section_header(kicker: str, title: str, subtitle: str) -> None:
    st.markdown(
        f"""
        <div class="hf-shell section-head">
            <div>
                <div class="section-kicker">{esc(kicker)}</div>
                <h1 class="section-title">{esc(title)}</h1>
                <div class="section-subtitle">{esc(subtitle)}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ==============================
# Page Renderers
# ==============================

def render_home() -> None:
    backend_online = len(BACKEND_IMPORT_ERRORS) == 0
    backend_text = "Ready" if backend_online else "Needs setup"
    ai_text = "Ready" if generate_ai_explanation is not None else "Report mode"
    backend_dot = "hf-dot" if backend_online else "hf-dot warn"
    ai_dot = "hf-dot" if generate_ai_explanation is not None else "hf-dot warn"

    st.markdown(
        f"""
        <div class="hf-shell hero-card">
            <div class="hero-inner">
                <div class="hero-kicker">Security assessment project</div>
                <div class="hero-title" aria-label="HackForge AI">
                    <span class="letter">H</span><span class="letter">A</span><span class="letter">C</span><span class="letter">K</span><span class="letter">F</span><span class="letter">O</span><span class="letter">R</span><span class="letter">G</span><span class="letter">E</span><span class="ai">AI</span>
                </div>
                <div class="hero-subtitle">Adaptive Cyber Tactical Assessment Console</div>
                <div class="hero-copy">
                    Choose what you want to test: a website, a suspicious message, or a link.
                    Each tool opens in its own workspace, so the screen stays focused and easy to explain.
                </div>
                <div class="status-grid">
                    <div class="status-strip">
                        <div><strong>Website Scanner</strong><span>Crawler, checks, report</span></div>
                        <div class="hf-status"><span class="{backend_dot}"></span>{backend_text}</div>
                    </div>
                    <div class="status-strip">
                        <div><strong>AI Summary</strong><span>Plain-English report help</span></div>
                        <div class="hf-status"><span class="{ai_dot}"></span>{ai_text}</div>
                    </div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="hf-shell" style="margin-top:1.25rem;">
            <div class="section-kicker">Start an assessment</div>
            <div class="launch-grid">
                <a class="launch-card" href="?page=web">
                    <div class="launch-icon">WV</div>
                    <h3>Web Vulnerability Assessment</h3>
                    <p>Scan a website, inspect forms and headers, validate likely issues, and generate a clean security report.</p>
                    <div class="launch-footer"><span>Open scanner</span><span>01</span></div>
                </a>
                <a class="launch-card" href="?page=message">
                    <div class="launch-icon">TI</div>
                    <h3>Message Threat Check</h3>
                    <p>Paste a suspicious email, SMS, or chat message and see the warning signs in plain language.</p>
                    <div class="launch-footer"><span>Open message check</span><span>02</span></div>
                </a>
                <a class="launch-card" href="?page=url">
                    <div class="launch-icon">URL</div>
                    <h3>Malicious URL Check</h3>
                    <p>Paste a suspicious link and review the domain, wording, and phishing patterns behind the verdict.</p>
                    <div class="launch-footer"><span>Open URL check</span><span>03</span></div>
                </a>
            </div>
            <a class="reference-band" href="?page=reference">
                <div>
                    <strong>Coverage reference</strong>
                    <span>A quick list of vulnerability and phishing checks supported by this project.</span>
                </div>
                <small>View when needed</small>
            </a>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_web_workspace() -> None:
    render_section_header(
        "Website scanner",
        "Web Vulnerability Assessment",
        "Enter a website URL, choose scan depth, and review the generated findings.",
    )

    st.markdown(
        """
        <div class="panel">
            <h3 class="panel-title">Scan Details</h3>
            <div class="panel-copy">
                Enter the website you are allowed to test, choose how deep the scanner should look,
                and start the assessment. The finished report opens automatically.
            </div>
            <div class="mission-grid">
                <div class="mission-chip"><span>Step 1</span><strong>Discover pages</strong></div>
                <div class="mission-chip"><span>Step 2</span><strong>Check weak spots</strong></div>
                <div class="mission-chip"><span>Step 3</span><strong>Validate findings</strong></div>
                <div class="mission-chip"><span>Step 4</span><strong>Build report</strong></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.write("")
    col_main, col_side = st.columns([1.7, 1], gap="large")

    with col_main:
        st.markdown('<div class="micro-label">Website</div>', unsafe_allow_html=True)
        target = st.text_input(
            "Target URL",
            value=st.session_state.web_target,
            placeholder="https://target.example.com",
            help="Use only assets you are authorized to test.",
        )
        st.session_state.web_target = target

        depth_col, page_col = st.columns(2)
        with depth_col:
            depth = st.slider("Crawl Depth", min_value=1, max_value=5, value=3)
        with page_col:
            pages = st.slider("Page Limit", min_value=5, max_value=100, value=50, step=5)

        active_testing = st.toggle("I have permission to test this website", value=True)
        if not active_testing:
            st.warning("Confirm permission before starting the scan.")

        run_disabled = not active_testing or not target.strip() or not backend_ready_for("web")
        run_web = st.button("Start Scan", disabled=run_disabled, use_container_width=True, type="primary")

        if run_web:
            try:
                validated_target = ensure_url(target)
                with st.spinner("HackForge AI is crawling, modeling, validating, and synthesizing findings..."):
                    result = run_web_assessment(validated_target, depth, pages)
                    store_web_result(result)
                    st.rerun()
            except Exception as exc:
                st.error(str(exc))

    with col_side:
        st.markdown(
            f"""
            <div class="panel">
                <h3 class="panel-title">Scan Setup</h3>
                <div class="panel-copy">Choose how much of the website should be checked before starting the scan.</div>
                <div class="detail-grid" style="grid-template-columns:1fr;">
                    <div class="detail-tile"><span>Scanner</span><strong>{'Ready' if backend_ready_for('web') else 'Needs setup'}</strong></div>
                    <div class="detail-tile"><span>Depth</span><strong>{depth}</strong></div>
                    <div class="detail-tile"><span>Page Limit</span><strong>{pages}</strong></div>
                    <div class="detail-tile"><span>Permission</span><strong>{'Yes' if active_testing else 'Needed'}</strong></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_threat_workspace() -> None:
    render_section_header(
        "Threat checks",
        "Threat Checks",
        "Choose the type of suspicious content you want to inspect.",
    )

    left, right = st.columns(2, gap="large")
    with left:
        st.markdown(
            """
            <div class="panel">
                <h3 class="panel-title">Communication Threat Analyzer</h3>
                <div class="panel-copy">Use this for emails, SMS messages, chat screenshots copied as text, or social media messages.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.button("Open Message Check", on_click=navigate, args=("message",), use_container_width=True)

    with right:
        st.markdown(
            """
            <div class="panel">
                <h3 class="panel-title">Malicious URL Analyzer</h3>
                <div class="panel-copy">Use this for suspicious links, login pages, payment links, and shortened or unusual URLs.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.button("Open URL Check", on_click=navigate, args=("url",), use_container_width=True)


def render_message_workspace() -> None:
    render_section_header(
        "Message Check",
        "Communication Threat Analyzer",
        "Paste a suspicious message and get a readable verdict with warning signs and next steps.",
    )

    st.markdown(
        """
        <div class="panel">
            <h3 class="panel-title">Suspicious Message</h3>
            <div class="panel-copy">This check looks for urgency, fake rewards, account pressure, payment language, and credential requests.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    message = st.text_area(
        "Message Text",
        placeholder="Paste the suspicious email, SMS, chat, or social message here...",
        height=280,
    )
    run_text = st.button(
        "Analyze Message",
        disabled=not backend_ready_for("threat_text"),
        use_container_width=True,
        type="primary",
    )
    if run_text:
        try:
            with st.spinner("Checking the message..."):
                result = run_text_assessment(message)
                store_threat_result(result)
                st.rerun()
        except Exception as exc:
            st.error(str(exc))


def render_url_workspace() -> None:
    render_section_header(
        "URL Check",
        "Malicious URL Analyzer",
        "Paste a suspicious link and get a verdict based on its structure and warning signs.",
    )

    st.markdown(
        """
        <div class="panel">
            <h3 class="panel-title">Suspicious Link</h3>
            <div class="panel-copy">This check looks for unsafe protocol use, deceptive symbols, suspicious domain endings, brand impersonation, and login bait.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    url = st.text_input(
        "Suspicious URL",
        placeholder="https://example-login-verify.xyz/account",
    )
    run_url = st.button(
        "Analyze URL",
        disabled=not backend_ready_for("threat_url"),
        use_container_width=True,
        type="primary",
    )
    if run_url:
        try:
            with st.spinner("Checking the URL..."):
                result = run_url_assessment(url)
                store_threat_result(result)
                st.rerun()
        except Exception as exc:
            st.error(str(exc))


def render_empty_results() -> None:
    st.markdown(
        """
        <div class="empty-state">
            <h3>No assessment results loaded</h3>
            <p>Run a website scan, message check, or URL check first. The report will appear here after the scan finishes.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    cols = st.columns(3)
    with cols[0]:
        st.button("Open Web Workspace", on_click=navigate, args=("web",))
    with cols[1]:
        st.button("Open Message Check", on_click=navigate, args=("message",))
    with cols[2]:
        st.button("Open URL Check", on_click=navigate, args=("url",))


def render_web_results(data: Dict[str, Any]) -> None:
    risk = data.get("risk_assessment", {})
    findings = data.get("validated_results", []) or []
    review_count = sum(1 for item in findings if is_ml_suspected_finding(item))
    confirmed_count = max(0, len(findings) - review_count)
    crawl = data.get("crawl_summary", {}) or {}
    report = data.get("report") or {}
    recommendations = report.get("recommendations", []) if report else []
    overview = data.get("ai_overview") or build_web_ai_overview(data, report)

    st.markdown(
        f"""
        <div class="report-brief">
            <h3>Report Summary</h3>
            <p>{esc(overview)}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.write("")
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Risk Score", f"{risk.get('risk_score', 0)}/100")
    m2.metric("Security Score", f"{risk.get('overall_score', 0)}/100")
    m3.metric("Critical", risk.get("critical_count", 0))
    m4.metric("High", risk.get("high_count", 0))
    m5.metric("Findings", len(findings))

    cvss_values = [float(f.get("cvss_score", 0) or 0) for f in findings]
    confidences = [normalize_confidence(f.get("confidence", 0)) for f in findings]
    avg_cvss = round(sum(cvss_values) / len(cvss_values), 1) if cvss_values else 0
    max_cvss = round(max(cvss_values), 1) if cvss_values else 0
    avg_conf = round(sum(confidences) / len(confidences), 1) if confidences else 0
    cwes = sorted({safe_text(f.get("cwe"), "N/A") for f in findings})

    st.markdown(
        f"""
        <div class="panel">
            <h3 class="panel-title">CVSS Style Metrics</h3>
            <div class="detail-grid">
                <div class="detail-tile"><span>Average CVSS</span><strong>{avg_cvss}</strong></div>
                <div class="detail-tile"><span>Maximum CVSS</span><strong>{max_cvss}</strong></div>
                <div class="detail-tile"><span>Avg Confidence</span><strong>{avg_conf}%</strong></div>
                <div class="detail-tile"><span>Pages</span><strong>{crawl.get('pages_discovered', 0)}</strong></div>
                <div class="detail-tile"><span>Forms</span><strong>{crawl.get('forms_discovered', 0)}</strong></div>
                <div class="detail-tile"><span>CWE Coverage</span><strong>{esc(', '.join(cwes[:4]) if cwes else 'N/A')}</strong></div>
                <div class="detail-tile"><span>Confirmed</span><strong>{confirmed_count}</strong></div>
                <div class="detail-tile"><span>Needs Review</span><strong>{review_count}</strong></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.write("")
    st.markdown('<div class="section-kicker">Findings Review</div>', unsafe_allow_html=True)

    if not findings:
        st.success("No findings were returned by the web vulnerability engine.")
    else:
        for idx, finding in enumerate(findings, start=1):
            title = finding.get("vulnerability_type") or finding.get("title") or f"Finding {idx}"
            severity = safe_text(finding.get("severity"), "low").lower()
            confidence = normalize_confidence(finding.get("confidence", 0))
            url = finding.get("url", "site-wide")
            cvss = finding.get("cvss_score", "N/A")
            cwe = finding.get("cwe", "N/A")
            review_label, review_class = finding_review_label(finding)
            details = finding.get("details", {})
            remediation = finding.get("remediation", {})
            reader_explanation = explain_finding_for_reader(finding)
            evidence_points = summarize_finding_details(details)

            st.markdown(
                f"""
                <div class="finding-card">
                    <div class="finding-head">
                        <h4>{idx:02d}. {esc(title)}</h4>
                        <div class="finding-badges">
                            <span class="status-pill {review_class}">{esc(review_label)}</span>
                            <span class="severity-pill {severity_class(severity)}">{esc(severity)}</span>
                        </div>
                    </div>
                    <div class="finding-meta">{esc(url)}</div>
                    <div style="height:0.75rem;"></div>
                    <div class="confidence-track"><div class="confidence-fill" style="width:{confidence}%;"></div></div>
                    <div class="detail-grid">
                        <div class="detail-tile"><span>Confidence</span><strong>{confidence}%</strong></div>
                        <div class="detail-tile"><span>CVSS</span><strong>{esc(cvss)}</strong></div>
                        <div class="detail-tile"><span>CWE</span><strong>{esc(cwe)}</strong></div>
                        <div class="detail-tile"><span>Review Status</span><strong>{esc(review_label)}</strong></div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            with st.expander(f"Explain this finding: {title}"):
                st.markdown("**What this means**")
                st.write(reader_explanation)
                if evidence_points:
                    st.markdown("**Evidence noticed by the scanner**")
                    for point in evidence_points:
                        st.write(f"- {point}")
                else:
                    st.write("The scanner returned this as a finding, but did not include extra evidence text.")
                if remediation:
                    st.markdown("**Suggested fix**")
                    st.write(remediation.get("summary", remediation))

    st.write("")
    st.markdown('<div class="section-kicker">Recommendations</div>', unsafe_allow_html=True)
    if recommendations:
        rec_html = ['<div class="indicator-grid">']
        for rec in recommendations[:6]:
            rec_html.append(
                f'<div class="indicator-card"><strong>{esc(rec.get("title"))}</strong>'
                f'<span>{esc(rec.get("description"))}</span></div>'
            )
        rec_html.append("</div>")
        st.markdown("".join(rec_html), unsafe_allow_html=True)
    else:
        st.markdown(
            '<div class="indicator-grid">'
            '<div class="indicator-card"><strong>Review strongest findings</strong><span>Confirm ML leads before calling them exploitable, then prioritize by severity and confidence.</span></div>'
            '<div class="indicator-card"><strong>Harden exposed surfaces</strong><span>Apply secure defaults, HTTP security headers, and input validation across affected endpoints.</span></div>'
            '<div class="indicator-card"><strong>Retest after remediation</strong><span>Run a fresh assessment after fixes to confirm exposure reduction.</span></div>'
            '</div>',
            unsafe_allow_html=True,
        )


def render_threat_results(data: Dict[str, Any]) -> None:
    result = data.get("result", {}) or {}
    status = safe_text(result.get("status"), "Unknown")
    confidence = normalize_confidence(result.get("confidence", 0))
    indicators = data.get("indicators", []) or []
    actions = data.get("actions", []) or []
    submitted = data.get("submitted", "")

    st.markdown(
        f"""
        <div class="report-brief">
            <h3>Advisory Summary</h3>
            <p>{esc(data.get('ai', 'No advisory generated.'))}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.write("")
    a, b, c, d = st.columns(4)
    a.metric("Threat Verdict", status)
    b.metric("Confidence", f"{confidence}%")
    c.metric("Indicators", len(indicators))
    d.metric("Analyzer", data.get("label", "Threat Intel"))

    st.markdown(
        f"""
        <div class="panel">
            <h3 class="panel-title">Submitted Artifact</h3>
            <div class="panel-copy">{esc(submitted)}</div>
            <div style="height:1rem;"></div>
            <div class="confidence-track"><div class="confidence-fill" style="width:{confidence}%;"></div></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.write("")
    st.markdown('<div class="section-kicker">Triggered Indicators</div>', unsafe_allow_html=True)
    if indicators:
        pieces = ['<div class="indicator-grid">']
        for indicator in indicators:
            pieces.append(
                f'<div class="indicator-card"><strong>Indicator</strong><span>{esc(indicator)}</span></div>'
            )
        pieces.append("</div>")
        st.markdown("".join(pieces), unsafe_allow_html=True)
    else:
        st.info("No explicit risk indicators were returned by the analyzer.")

    st.write("")
    st.markdown('<div class="section-kicker">Response Recommendation</div>', unsafe_allow_html=True)
    if actions:
        pieces = ['<div class="indicator-grid">']
        for action in actions:
            pieces.append(
                f'<div class="indicator-card"><strong>Action</strong><span>{esc(action)}</span></div>'
            )
        pieces.append("</div>")
        st.markdown("".join(pieces), unsafe_allow_html=True)


def render_results() -> None:
    render_section_header(
        "Report",
        "Results Center",
        "Review the latest website scan or threat check in one clear report.",
    )

    if st.session_state.last_result_type == "web" and st.session_state.scan_results:
        render_web_results(st.session_state.scan_results)
    elif st.session_state.last_result_type == "threat" and st.session_state.threat_results:
        render_threat_results(st.session_state.threat_results)
    else:
        render_empty_results()


def analytics_source() -> Optional[Dict[str, Any]]:
    if st.session_state.last_result_type == "web" and st.session_state.scan_results:
        return {"type": "web", "data": st.session_state.scan_results}
    if st.session_state.last_result_type == "threat" and st.session_state.threat_results:
        return {"type": "threat", "data": st.session_state.threat_results}
    return None


def render_web_analytics(data: Dict[str, Any]) -> None:
    findings = data.get("validated_results", []) or []
    counts = severity_counts(findings)
    risk = data.get("risk_assessment", {})
    risk_score = float(risk.get("risk_score", 0) or 0)
    crawl = data.get("crawl_summary", {}) or {}

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Risk Score", f"{risk_score}/100")
    m2.metric("Security Score", f"{risk.get('overall_score', 0)}/100")
    m3.metric("Pages", crawl.get("pages_discovered", 0))
    m4.metric("Forms", crawl.get("forms_discovered", 0))
    m5.metric("Findings", len(findings))

    sev_labels = ["Critical", "High", "Medium", "Low"]
    sev_values = [counts["critical"], counts["high"], counts["medium"], counts["low"]]
    donut = go.Figure(
        data=[
            go.Pie(
                labels=sev_labels,
                values=sev_values,
                hole=0.62,
                marker={"colors": ["#ff5577", "#ff914d", "#f7c948", "#31f58f"]},
                textinfo="label+value",
            )
        ]
    )
    donut = plot_layout(donut, "Severity Donut")

    confidences = [normalize_confidence(f.get("confidence", 0)) for f in findings]
    names = [
        safe_text(f.get("vulnerability_type") or f.get("title"), f"Finding {idx}")
        for idx, f in enumerate(findings, start=1)
    ]
    conf_bar = go.Figure(
        data=[
            go.Bar(
                x=names or ["No findings"],
                y=confidences or [0],
                marker={"color": "#31f58f"},
                hovertemplate="%{x}<br>Confidence %{y}%<extra></extra>",
            )
        ]
    )
    conf_bar.update_yaxes(range=[0, 100], gridcolor="rgba(148,170,205,0.11)")
    conf_bar.update_xaxes(gridcolor="rgba(148,170,205,0.06)")
    conf_bar = plot_layout(conf_bar, "Confidence Distribution")

    endpoint_counts = defaultdict(int)
    for finding in findings:
        endpoint_counts[safe_text(finding.get("url"), "site-wide")] += 1
    endpoint_bar = go.Figure(
        data=[
            go.Bar(
                x=list(endpoint_counts.keys()) or ["No endpoints"],
                y=list(endpoint_counts.values()) or [0],
                marker={"color": "#50d5ff"},
                hovertemplate="%{x}<br>Findings %{y}<extra></extra>",
            )
        ]
    )
    endpoint_bar.update_yaxes(gridcolor="rgba(148,170,205,0.11)")
    endpoint_bar.update_xaxes(gridcolor="rgba(148,170,205,0.06)")
    endpoint_bar = plot_layout(endpoint_bar, "Endpoint Finding Count")

    gauge = create_risk_gauge(risk_score, "Exposure Risk")

    top_left, top_right = st.columns([1, 1], gap="large")
    with top_left:
        st.markdown('<div class="chart-frame">', unsafe_allow_html=True)
        st.plotly_chart(donut, use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)
    with top_right:
        st.markdown('<div class="chart-frame">', unsafe_allow_html=True)
        st.plotly_chart(gauge, use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)

    lower_left, lower_right = st.columns([1.2, 1], gap="large")
    with lower_left:
        st.markdown('<div class="chart-frame">', unsafe_allow_html=True)
        st.plotly_chart(conf_bar, use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)
    with lower_right:
        st.markdown('<div class="chart-frame">', unsafe_allow_html=True)
        st.plotly_chart(endpoint_bar, use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)


def render_threat_analytics(data: Dict[str, Any]) -> None:
    result = data.get("result", {}) or {}
    confidence = normalize_confidence(result.get("confidence", 0))
    indicators = data.get("indicators", []) or []
    status = safe_text(result.get("status"), "Unknown")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Threat Verdict", status)
    m2.metric("Confidence", f"{confidence}%")
    m3.metric("Indicators", len(indicators))
    m4.metric("Analyzer", data.get("label", "Threat Intel"))

    confidence_fig = go.Figure(
        data=[
            go.Bar(
                x=["Threat Confidence", "Residual Uncertainty"],
                y=[confidence, max(0, 100 - confidence)],
                marker={"color": ["#31f58f", "rgba(148,170,205,0.25)"]},
                hovertemplate="%{x}<br>%{y}%<extra></extra>",
            )
        ]
    )
    confidence_fig.update_yaxes(range=[0, 100], gridcolor="rgba(148,170,205,0.11)")
    confidence_fig = plot_layout(confidence_fig, "Confidence Distribution")

    donut = go.Figure(
        data=[
            go.Pie(
                labels=["Triggered Indicators", "Remaining Review Surface"],
                values=[len(indicators), max(1, 8 - len(indicators))],
                hole=0.62,
                marker={"colors": ["#ff914d" if confidence >= 40 else "#31f58f", "rgba(148,170,205,0.25)"]},
                textinfo="label+value",
            )
        ]
    )
    donut = plot_layout(donut, "Indicator Donut")

    indicator_bar = go.Figure(
        data=[
            go.Bar(
                x=indicators or ["No explicit indicators"],
                y=[1 for _ in indicators] or [0],
                marker={"color": "#50d5ff"},
                hovertemplate="%{x}<extra></extra>",
            )
        ]
    )
    indicator_bar.update_yaxes(showticklabels=False, gridcolor="rgba(148,170,205,0.08)")
    indicator_bar = plot_layout(indicator_bar, "Indicator Count")

    gauge = create_risk_gauge(confidence, "Threat Confidence")

    top_left, top_right = st.columns(2, gap="large")
    with top_left:
        st.markdown('<div class="chart-frame">', unsafe_allow_html=True)
        st.plotly_chart(donut, use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)
    with top_right:
        st.markdown('<div class="chart-frame">', unsafe_allow_html=True)
        st.plotly_chart(gauge, use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)

    lower_left, lower_right = st.columns([1.2, 1], gap="large")
    with lower_left:
        st.markdown('<div class="chart-frame">', unsafe_allow_html=True)
        st.plotly_chart(confidence_fig, use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)
    with lower_right:
        st.markdown('<div class="chart-frame">', unsafe_allow_html=True)
        st.plotly_chart(indicator_bar, use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)


def render_analytics() -> None:
    render_section_header(
        "Page 04",
        "Analytics Center",
        "Operational visualizations generated from the latest session-state assessment results.",
    )

    source = analytics_source()
    if not source:
        render_empty_results()
        return

    if source["type"] == "web":
        render_web_analytics(source["data"])
    else:
        render_threat_analytics(source["data"])


def render_reference() -> None:
    render_section_header(
        "Page 05",
        "Security Coverage Reference",
        "A styled matrix of vulnerability classes, threat indicators, and intelligence behaviors currently supported by HackForge AI.",
    )

    coverage = [
        ("WEB", "SQL Injection", "CWE-89 style injection vectors, database error signals, and active SQL probing through form inputs."),
        ("WEB", "Cross Site Scripting", "Reflected script payload checks, XSS suspect modeling, browser-side injection impact, and CWE-79 mapping."),
        ("WEB", "Broken Auth", "Login form discovery, credential field recognition, weak session exposure cues, and authentication surface notes."),
        ("WEB", "Security Misconfiguration", "HTTP security headers, content protection posture, framework clues, and deployment hardening gaps."),
        ("WEB", "Potential CSRF", "POST forms without anti-CSRF controls and state-changing request exposure indicators."),
        ("WEB", "Cookie Security", "Secure and HttpOnly cookie flag review for session handling exposure."),
        ("INTEL", "Scam Language", "Urgency, reward bait, warning language, suspicious action requests, and persuasion markers."),
        ("INTEL", "Credential Harvesting", "Password, OTP, account update, KYC, payment, and bank-related social engineering cues."),
        ("INTEL", "Malicious URL Intelligence", "Non-HTTPS links, raw IP use, deceptive symbols, suspicious TLDs, long URLs, and phishing keywords."),
    ]

    cards = ['<div class="coverage-grid">']
    for domain, title, body in coverage:
        cards.append(
            f'<div class="coverage-card"><small>{esc(domain)}</small>'
            f'<strong>{esc(title)}</strong><span>{esc(body)}</span></div>'
        )
    cards.append("</div>")
    st.markdown("".join(cards), unsafe_allow_html=True)


# ==============================
# App Router
# ==============================

render_sidebar()
render_topbar()
render_main_navigation()

st.markdown('<div class="hf-shell">', unsafe_allow_html=True)

current_page = st.session_state.page
if current_page == "home":
    render_home()
elif current_page == "web":
    render_web_workspace()
elif current_page == "threat":
    render_threat_workspace()
elif current_page == "message":
    render_message_workspace()
elif current_page == "url":
    render_url_workspace()
elif current_page == "results":
    render_results()
elif current_page == "analytics":
    render_analytics()
elif current_page == "reference":
    render_reference()
else:
    navigate("home")
    st.rerun()

st.markdown(
    '<div class="footer-note">HackForge AI - Security assessment tool</div></div>',
    unsafe_allow_html=True,
)
