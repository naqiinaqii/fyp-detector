import json
import streamlit as st
import detector

st.set_page_config(
    page_title="Social Engineering Detector",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

:root {
    --bg: #0a0a0b;
    --surface: #121214;
    --surface-2: #17171a;
    --border: rgba(255,255,255,0.08);
    --border-soft: rgba(255,255,255,0.06);
    --text-primary: #f2f2f3;
    --text-secondary: #9a9aa2;
    --text-tertiary: #6b6b72;
    --accent: #6366f1;
    --accent-soft: rgba(99,102,241,0.12);
    --safe: #10b981;
    --suspicious: #f59e0b;
    --phishing: #ef4444;
    --radius-sm: 8px;
    --radius-md: 12px;
    --radius-lg: 16px;
}

html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
}

body, .stApp {
    background:
        radial-gradient(1100px 500px at 50% -12%, rgba(99,102,241,0.07), transparent 60%),
        var(--bg) !important;
}

.block-container {
    padding-top: 3rem;
    padding-bottom: 4rem;
    max-width: 960px;
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(4px); }
    to   { opacity: 1; transform: translateY(0); }
}

/* Header */
.app-header { display: flex; align-items: center; gap: 0.9rem; }
.logo-mark {
    width: 42px; height: 42px; border-radius: 11px;
    background: var(--accent-soft); color: var(--accent);
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0;
}
.main-title {
    font-size: 1.55rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    color: var(--text-primary) !important;
    margin: 0;
    line-height: 1.25;
}
.sub-title {
    color: var(--text-secondary) !important;
    font-size: 0.92rem;
    margin: 0.2rem 0 0 0;
}
.meta-row {
    display: flex; align-items: center; flex-wrap: wrap; gap: 0.55rem;
    color: var(--text-tertiary) !important;
    font-size: 0.82rem;
    margin: 1.4rem 0 2.25rem 0;
    padding-top: 1.1rem;
    border-top: 1px solid var(--border-soft);
}
.meta-item { display: inline-flex; align-items: center; gap: 0.4rem; color: var(--text-tertiary) !important; }
.meta-dot { opacity: 0.5; }

/* Result banner */
.result-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 3px solid var(--sev-color);
    border-radius: var(--radius-lg);
    padding: 1.4rem 1.6rem;
    margin-bottom: 1.5rem;
    display: flex;
    align-items: center;
    gap: 1.4rem;
    animation: fadeIn 0.3s ease both;
}
.gauge {
    width: 68px; height: 68px; border-radius: 50%; flex-shrink: 0;
    background: conic-gradient(var(--sev-color) calc(var(--score) * 1%), var(--border) 0);
    display: flex; align-items: center; justify-content: center;
}
.gauge-inner {
    width: 55px; height: 55px; border-radius: 50%; background: var(--surface);
    display: flex; flex-direction: column; align-items: center; justify-content: center;
}
.gauge-score { font-size: 1.1rem; font-weight: 700; color: var(--text-primary) !important; line-height: 1; }
.gauge-max { font-size: 0.58rem; color: var(--text-tertiary) !important; margin-top: 1px; }

.result-label {
    font-size: 1.1rem; font-weight: 600; color: var(--sev-color) !important;
    display: flex; align-items: center; gap: 0.5rem;
}
.result-sub { font-size: 0.86rem; color: var(--text-secondary) !important; margin-top: 0.3rem; }

/* Metric boxes */
.metric-box {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 1rem 1.1rem;
    animation: fadeIn 0.35s ease both;
}
.metric-label {
    color: var(--text-tertiary) !important;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}
.metric-value {
    font-size: 1.2rem;
    font-weight: 700;
    color: var(--text-primary) !important;
    margin: 0.3rem 0 0.65rem 0;
}
.metric-bar-track {
    height: 3px;
    border-radius: 999px;
    background: var(--border);
    overflow: hidden;
}
.metric-bar-fill { height: 100%; border-radius: 999px; background: var(--accent); opacity: 0.85; }

/* Content cards */
.section-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 1.3rem 1.5rem;
    margin-bottom: 1.25rem;
    animation: fadeIn 0.3s ease both;
}
.section-title {
    font-size: 0.92rem;
    font-weight: 600;
    color: var(--text-primary) !important;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.55rem;
}
.section-title svg { color: var(--text-tertiary); }
.item { display: flex; gap: 0.75rem; align-items: flex-start; margin-bottom: 0.7rem; }
.item:last-child { margin-bottom: 0; }
.item-index {
    color: var(--text-tertiary) !important;
    font-size: 0.72rem;
    font-weight: 600;
    min-width: 1.3rem;
    padding-top: 0.2rem;
    flex-shrink: 0;
}
.item-text { color: var(--text-secondary) !important; line-height: 1.6; font-size: 0.9rem; }

/* Pills */
.flag-pill {
    display: inline-flex;
    align-items: center;
    gap: 0.45rem;
    padding: 0.38rem 0.8rem;
    border-radius: 999px;
    border: 1px solid var(--border);
    background: var(--surface-2);
    color: var(--text-secondary) !important;
    margin: 0.2rem 0.4rem 0.2rem 0;
    font-size: 0.82rem;
    font-weight: 500;
}
.flag-dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }

/* Sidebar */
.sidebar-heading {
    font-weight: 600;
    font-size: 0.95rem;
    color: var(--text-primary) !important;
    display: flex; align-items: center; gap: 0.5rem;
    margin-bottom: 0.9rem;
}
.sidebar-footer {
    color: var(--text-tertiary) !important;
    font-size: 0.76rem;
    line-height: 1.6;
    margin-top: 1.75rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border-soft);
}

.footer-note {
    color: var(--text-tertiary) !important;
    font-size: 0.8rem;
    margin-top: 1.5rem;
}

/* Native widget refinement */
button:hover { border-color: var(--accent) !important; }
[data-testid="stTabs"] button[aria-selected="true"] { color: var(--accent) !important; }
[data-testid="stTabs"] [data-baseweb="tab-highlight"] { background-color: var(--accent) !important; }
</style>
""", unsafe_allow_html=True)


# ---------- Icon system (Feather-style inline SVG, no emoji) ----------
ICON_PATHS = {
    "shield":         '<path d="M12 2 3 6v6c0 5.25 3.75 9.99 9 11 5.25-1.01 9-5.75 9-11V6l-9-4Z"/>',
    "list":           '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>',
    "cpu":            '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/>',
    "zap":            '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
    "search":         '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
    "check-circle":   '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
    "flag":           '<path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/>',
    "bar-chart":      '<line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/>',
    "sliders":        '<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>',
    "info":           '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
    "clock":          '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
    "key":            '<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>',
    "link":           '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
    "globe":          '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
    "alert-triangle": '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    "gift":           '<polyline points="20 12 20 22 4 22 4 12"/><rect x="2" y="7" width="20" height="5"/><line x1="12" y1="22" x2="12" y2="7"/><path d="M12 7H7.5a2.5 2.5 0 0 1 0-5C11 2 12 7 12 7z"/><path d="M12 7h4.5a2.5 2.5 0 0 0 0-5C13 2 12 7 12 7z"/>',
    "help-circle":    '<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    "monitor":        '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>',
    "credit-card":    '<rect x="1" y="4" width="22" height="16" rx="2"/><line x1="1" y1="10" x2="23" y2="10"/>',
    "external-link":  '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>',
    "user-check":     '<path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/><polyline points="17 11 19 13 23 9"/>',
    "alert-octagon":  '<polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>',
    "file-text":      '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><line x1="10" y1="9" x2="8" y2="9"/>',
}


def svg_icon(name: str, size: int = 15, stroke_width: float = 1.75) -> str:
    inner = ICON_PATHS.get(name, "")
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
        f'stroke="currentColor" stroke-width="{stroke_width}" stroke-linecap="round" '
        f'stroke-linejoin="round" style="vertical-align:-3px;flex-shrink:0;">{inner}</svg>'
    )


# ---------- Style lookups ----------
FLAG_META = {
    "urgency":                 ("#f59e0b", "clock"),
    "authority_impersonation": ("#a78bfa", "user-check"),
    "credential_request":      ("#ef4444", "key"),
    "suspicious_link":         ("#ef4444", "link"),
    "spoofed_domain":          ("#ef4444", "globe"),
    "fear_tactic":             ("#ef4444", "alert-triangle"),
    "reward_bait":             ("#a78bfa", "gift"),
    "unknown_sender":          ("#6366f1", "help-circle"),
    "remote_access":           ("#ef4444", "monitor"),
    "payment_request":         ("#ef4444", "credit-card"),
    "off_platform":            ("#6366f1", "external-link"),
}
DEFAULT_FLAG_META = ("#6b6b72", "flag")

SEVERITY = {
    "SAFE":       {"color": "var(--safe)",       "icon": "check-circle"},
    "SUSPICIOUS": {"color": "var(--suspicious)", "icon": "alert-triangle"},
    "PHISHING":   {"color": "var(--phishing)",   "icon": "alert-octagon"},
}


# ---------- Helpers ----------
def severity_of(label: str) -> dict:
    return SEVERITY.get((label or "").upper(), SEVERITY["SAFE"])


def flag_pill_html(flag: str) -> str:
    color, icon_name = FLAG_META.get(flag, DEFAULT_FLAG_META)
    label = detector.FLAG_FRIENDLY.get(flag, flag.replace("_", " ").title())
    return (
        f'<span class="flag-pill">'
        f'<span class="flag-dot" style="background:{color};"></span>'
        f'{svg_icon(icon_name, 13)}{label}</span>'
    )


def render_section_card(title: str, items: list[str], icon: str = "list") -> None:
    if items:
        body = "".join(
            f"<div class='item'><span class='item-index'>{i+1:02d}</span>"
            f"<span class='item-text'>{item}</span></div>"
            for i, item in enumerate(items)
        )
    else:
        body = "<div class='item-text'>No information available.</div>"

    st.markdown(
        f"""
        <div class="section-card">
            <div class="section-title">{svg_icon(icon)}{title}</div>
            {body}
        </div>
        """,
        unsafe_allow_html=True
    )


def render_info_card(title: str, lines: list[str], icon: str = "file-text") -> None:
    body = "".join(
        f"<div class='item'><span class='item-text'>{line}</span></div>" for line in lines
    )

    st.markdown(
        f"""
        <div class="section-card">
            <div class="section-title">{svg_icon(icon)}{title}</div>
            {body}
        </div>
        """,
        unsafe_allow_html=True
    )


def render_metric_box(label: str, value: int) -> None:
    pct = max(0, min(100, int(value)))
    st.markdown(
        f"""
        <div class="metric-box">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
            <div class="metric-bar-track">
                <div class="metric-bar-fill" style="width:{pct}%;"></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


# ---------- Header ----------
st.markdown(
    f"""
    <div class="app-header">
        <div class="logo-mark">{svg_icon("shield", 21, 1.6)}</div>
        <div>
            <h1 class="main-title">AI-Based Social Engineering Detector</h1>
            <div class="sub-title">Hybrid detection combining rule-based analysis, machine learning, and local generative AI.</div>
        </div>
    </div>
    <div class="meta-row">
        <span class="meta-item">{svg_icon("list", 13)}Rule-Based</span>
        <span class="meta-dot">&middot;</span>
        <span class="meta-item">{svg_icon("cpu", 13)}Machine Learning</span>
        <span class="meta-dot">&middot;</span>
        <span class="meta-item">{svg_icon("zap", 13)}Local GenAI (Ollama)</span>
    </div>
    """,
    unsafe_allow_html=True
)

# ---------- Sidebar ----------
with st.sidebar:
    st.markdown(
        f'<div class="sidebar-heading">{svg_icon("sliders", 15)}Settings</div>',
        unsafe_allow_html=True
    )
    use_llm = st.toggle("Use GenAI (Ollama)", value=True)
    show_technical = st.toggle("Show technical details", value=True)

    st.markdown(
        """
        <div class="sidebar-footer">Hybrid Detection Engine<br>Rules + ML + Local GenAI</div>
        """,
        unsafe_allow_html=True
    )

# ---------- Input ----------
sample_1 = "I need your OTP code urgently or the system will delete your account."
sample_2 = "Congratulations! You won a free prize. Click now to claim your reward."
sample_3 = "https://paypal-login-security-alert.xyz/verify"


def clear_input():
    st.session_state["detector_input"] = ""


col_a, col_b, col_c = st.columns(3)
if col_a.button("Use OTP Sample", use_container_width=True):
    st.session_state["detector_input"] = sample_1
if col_b.button("Use Reward Sample", use_container_width=True):
    st.session_state["detector_input"] = sample_2
if col_c.button("Use URL Sample", use_container_width=True):
    st.session_state["detector_input"] = sample_3

user_input = st.text_area(
    "Enter message or URL",
    height=180,
    key="detector_input",
    placeholder="Paste suspicious message or URL here..."
)

action_col1, action_col2 = st.columns([3, 1])
analyze = action_col1.button("Analyze Input", use_container_width=True, type="primary")
action_col2.button("Clear", use_container_width=True, on_click=clear_input)

# ---------- Analysis ----------
if analyze:
    if not user_input.strip():
        st.warning("Please enter a message or URL first.")
        st.stop()

    with st.spinner("Running hybrid detection..."):
        result = detector.analyze_for_ui(user_input.strip(), use_llm=use_llm)

    final = result["final"]
    breakdown = result["breakdown"]
    sev = severity_of(final["label"])

    # Result card with risk gauge
    st.markdown(
        f"""
        <div class="result-card" style="--sev-color:{sev['color']}; --score:{final['score']};">
            <div class="gauge">
                <div class="gauge-inner">
                    <div class="gauge-score">{final['score']}</div>
                    <div class="gauge-max">/ 100</div>
                </div>
            </div>
            <div>
                <div class="result-label">{svg_icon(sev['icon'], 18)}{final['label']}</div>
                <div class="result-sub">Hybrid risk score — combining rule-based analysis, machine learning, and generative AI</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Metrics
    m1, m2, m3 = st.columns(3)
    with m1:
        render_metric_box("Rule Score", breakdown["rule_risk"])
    with m2:
        render_metric_box("ML Score", breakdown["ml_risk"])
    with m3:
        render_metric_box("LLM Score", breakdown["llm_score"])

    st.markdown("---")

    tab1, tab2 = st.tabs(["User View", "Technical View"])

    with tab1:
        left, right = st.columns([1.2, 1])

        with left:
            render_section_card("Why it was flagged", final["reasons"], icon="search")
            render_section_card("What you should do", final["advice"], icon="check-circle")

        with right:
            if final["red_flags"]:
                pills = "".join(flag_pill_html(flag) for flag in final["red_flags"])
            else:
                pills = "<div class='item-text'>No red flags.</div>"

            st.markdown(
                f"""
                <div class="section-card">
                    <div class="section-title">{svg_icon("flag")}Detected red flags</div>
                    {pills}
                </div>
                """,
                unsafe_allow_html=True
            )

            render_info_card(
                "Hybrid decision summary",
                [
                    f"Input Type: {result['input']['type']}",
                    f"Rule + ML Score: {breakdown['rule_ml_score']}/100",
                    f"LLM Score: {breakdown['llm_score']}/100",
                    f"Final Hybrid Score: {final['score']}/100",
                ],
                icon="bar-chart"
            )

    with tab2:
        render_info_card(
            "Technical Breakdown",
            [
                f"Rule Raw Score: {breakdown['rule_raw']}",
                f"Rule Normalized Score: {breakdown['rule_risk']}",
                f"ML Risk Score: {breakdown['ml_risk']}",
                f"Rule + ML Score: {breakdown['rule_ml_score']}",
                f"LLM Score: {breakdown['llm_score']}",
            ],
            icon="sliders"
        )

        if show_technical:
            st.markdown(
                f"""
                <div class="section-card">
                    <div class="section-title">{svg_icon("file-text")}Full JSON Output</div>
                </div>
                """,
                unsafe_allow_html=True
            )
            st.code(json.dumps(result, indent=2, ensure_ascii=False), language="json")

    st.markdown(
        '<div class="footer-note">This prototype is designed for offline/local demonstration using a hybrid AI architecture.</div>',
        unsafe_allow_html=True
    )
