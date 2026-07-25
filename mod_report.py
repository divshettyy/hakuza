"""
mod_report.py — Enhanced professional report generation for HAKUZA pentest platform.
Replaces the basic cmd_report with client-ready HTML reports featuring embedded
SVG charts, risk gauge, collapsible finding cards, and print-ready layout.

Divith D Shetty | CEH · CRTP · CAISP | Alvarez & Marsal
"""

import json
import math
import re
from datetime import datetime, timedelta
from pathlib import Path

import markdown2

# ---------------------------------------------------------------------------
# Imported from hakuza.py at runtime (available in merged namespace):
#   _require_engagement, get_client, get_client_or_none, stream_to_console
#   list_findings, get_finding_count, get_recon_summary
#   SYSTEM_PROMPT, HAKUZA_DIR, ENGAGEMENTS_DIR, VERSION
#   sev_badge, Console, Panel, Rule, Markdown, Progress, SpinnerColumn, TextColumn
#   datetime, json, re, math
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

_TESTER_NAME = "Divith D Shetty"
_TESTER_CREDS = "CEH · CRTP · CAISP | 4+ Years VAPT | Alvarez & Marsal"
_HAKUZA_VERSION = "2.0.0"

_SEV_HTML_COLORS = {
    "critical": "#f85149",
    "high":     "#d29922",
    "medium":   "#3fb950",
    "low":      "#58a6ff",
    "informational": "#8b949e",
    "info":     "#8b949e",
}

_SEV_HTML_BG = {
    "critical": "rgba(248,81,73,0.15)",
    "high":     "rgba(210,153,34,0.15)",
    "medium":   "rgba(63,185,80,0.15)",
    "low":      "rgba(88,166,255,0.15)",
    "informational": "rgba(139,148,158,0.15)",
    "info":     "rgba(139,148,158,0.15)",
}

_EFFORT_COLORS = {
    "immediate": "#f85149",
    "short-term": "#d29922",
    "long-term": "#3fb950",
}


# ---------------------------------------------------------------------------
# RISK SCORE
# ---------------------------------------------------------------------------

def _calc_risk_score(counts: dict) -> int:
    """Weighted risk score: crit×40 + high×20 + med×8 + low×2, capped at 100."""
    score = (
        counts.get("critical", 0) * 40 +
        counts.get("high", 0) * 20 +
        counts.get("medium", 0) * 8 +
        counts.get("low", 0) * 2
    )
    return min(100, score)


def _risk_label(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    elif score >= 45:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    else:
        return "LOW"


def _risk_color(score: int) -> str:
    if score >= 70:
        return "#f85149"
    elif score >= 45:
        return "#d29922"
    elif score >= 20:
        return "#ecc94b"
    else:
        return "#3fb950"


# ---------------------------------------------------------------------------
# CLAUDE PROMPT BUILDER
# ---------------------------------------------------------------------------

def _build_report_prompt(eng: dict, findings: list, counts: dict, score: int,
                         report_type: str, client_name: str) -> str:
    """Build the structured prompt sent to Claude for report generation."""
    now_str = datetime.now().strftime("%Y-%m-%d")
    tester = eng.get("tester", _TESTER_NAME)
    target = eng.get("target", "N/A")
    scope = eng.get("scope", "Full scope as agreed")
    eng_type = eng.get("type", "web")

    # Serialize findings into a compact block
    finding_lines = []
    for i, f in enumerate(findings, 1):
        sev = (f.get("severity") or "informational").upper()
        title = f.get("title", "Unknown")
        cvss = f"CVSS:{f['cvss_score']}" if f.get("cvss_score") else ""
        cwe = f"CWE:{f['cwe']}" if f.get("cwe") else ""
        owasp = f"OWASP:{f['owasp']}" if f.get("owasp") else ""
        url = f.get("url", "")
        status = f.get("status", "open")
        desc = (f.get("description") or "")[:300]
        impact = (f.get("impact") or "")[:200]
        remediation = (f.get("remediation") or "")[:200]
        evidence_snippet = (f.get("evidence") or "")[:150]
        meta = " | ".join(filter(None, [cvss, cwe, owasp]))
        finding_lines.append(
            f"\n### [{sev}] {f.get('short_id','F'+str(i))}: {title}\n"
            f"  URL: {url} | Status: {status} | {meta}\n"
            f"  Description: {desc}\n"
            f"  Impact: {impact}\n"
            f"  Evidence: {evidence_snippet}\n"
            f"  Remediation: {remediation}"
        )
    findings_block = "\n".join(finding_lines) if finding_lines else "  No findings recorded."

    severity_summary = (
        f"Critical: {counts.get('critical',0)} | High: {counts.get('high',0)} | "
        f"Medium: {counts.get('medium',0)} | Low: {counts.get('low',0)} | "
        f"Informational: {counts.get('informational',0)}"
    )
    total = sum(counts.values())

    box_type = {"web": "grey-box", "api": "grey-box", "network": "black-box",
                "mobile": "grey-box", "ad": "grey-box", "cloud": "grey-box",
                "red-team": "black-box"}.get(eng_type, "grey-box")

    return f"""Generate a complete, professional penetration testing report. Write every section in full — no truncation, no placeholders.

ENGAGEMENT DETAILS:
- Engagement Name: {eng['name']}
- Client: {client_name}
- Target: {target}
- Engagement Type: {eng_type} ({box_type} testing)
- Primary Tester: {tester} ({_TESTER_CREDS})
- Testing Period: {eng.get('start_date', now_str)} to {now_str}
- Scope: {scope}
- Report Type: {report_type}
- Report Date: {now_str}
- Risk Score: {score}/100 ({_risk_label(score)})

FINDINGS ({total} total):
{severity_summary}
{findings_block}

---

Write the complete report in this exact structure. Use proper Markdown. Be specific, technical, and client-ready.

# Penetration Test Report

## {client_name} — Confidential

---

## 1. Executive Summary
Write three substantive paragraphs for a C-suite audience (no technical background):
- Paragraph 1: Overall security posture, headline findings, risk score meaning in business terms
- Paragraph 2: Business impact — frame data breach risk, regulatory exposure (PCI-DSS, RBI, GDPR as applicable), financial and reputational consequences using real numbers where possible
- Paragraph 3: Top 3 recommendations with clear business justification (not just technical fixes)

## 2. Risk Dashboard
Provide:
- Overall risk rating: {_risk_label(score)} (Score: {score}/100)
- Severity breakdown table with counts and percentage
- Compliance posture summary: PCI-DSS, ISO 27001, OWASP relevance
- Key risk indicators

## 3. Methodology
- Testing approach: {box_type} ({eng_type} engagement)
- Standards followed: OWASP Testing Guide v4.2, PTES Technical Guidelines, OWASP API Top 10 2023, CVSS v3.1
- Tools employed: [list relevant tools based on engagement type]
- Testing period: {eng.get('start_date', now_str)} — {now_str}
- Limitations and assumptions

## 4. Attack Surface Summary
Based on the engagement scope and target:
- Scope tested (endpoints, assets, components)
- Entry points identified and their risk classification
- Technology stack observed
- Authentication mechanisms in place
- External exposure summary

## 5. Findings

For EACH of the {total} findings, write a complete section with this structure:

### [Finding ID]: [Title]
**Severity:** [Critical/High/Medium/Low/Informational]
**CVSS Score:** [score] | **CVSS Vector:** [vector if known]
**CWE:** [cwe] | **OWASP:** [category] | **Status:** [status]
**Affected URL / Component:** [url]

**Description**
[Full technical description — what the vulnerability is, how it was found]

**Business Impact**
[Specific impact in business terms — data at risk, compliance violation, exploitation scenario]

**Evidence**
```
[evidence snippet or description of proof]
```

**Remediation**
[Specific, actionable fix — include code example or configuration change where applicable]

**References**
- [OWASP link or CWE link]
- [Relevant CVE or advisory if applicable]

---

## 6. Attack Chains
Describe 2–3 realistic multi-step exploitation paths combining findings:
- **Chain name** and overall severity
- Step-by-step attack path with specific findings referenced
- Final impact if chain succeeds
- Likelihood (High/Medium/Low) with reasoning

## 7. Vulnerability Statistics
Provide:
- Findings by severity (table)
- Findings by status (table)
- Findings by OWASP category (if mappings available)
- Top 5 most critical findings by CVSS score

## 8. Remediation Roadmap
Provide a prioritised timeline table:

| Priority | Finding | Effort | Owner | Target Deadline |
|---|---|---|---|---|
[Immediate (0–7 days): Critical/High]
[Short-term (7–30 days): High/Medium]
[Long-term (30–90 days): Medium/Low hardening]

Add a brief paragraph on remediation ownership and verification process.

## 9. Conclusion
Two paragraphs:
- Overall security posture assessment and what it means for the organisation
- Path forward: recommended re-test timeline, ongoing security program suggestions

---
*Report generated by HAKUZA {_HAKUZA_VERSION} on {now_str}. Assessor: {tester} ({_TESTER_CREDS}). Classification: CONFIDENTIAL — Restricted Distribution.*"""


# ---------------------------------------------------------------------------
# SVG COMPONENTS
# ---------------------------------------------------------------------------

def _svg_gauge(score: int) -> str:
    """Generate an SVG semicircle risk gauge with animated fill."""
    color = _risk_color(score)
    label = _risk_label(score)
    # Arc circumference for a radius-80 semicircle = π × 80 ≈ 251.3
    arc_len = math.pi * 80
    # filled portion = (score/100) × arc_len; offset = arc_len - filled
    filled = (score / 100.0) * arc_len
    offset = arc_len - filled
    return f"""<svg viewBox="0 0 200 120" class="gauge-svg" aria-label="Risk gauge: {score}/100">
  <!-- background arc -->
  <path d="M 20 100 A 80 80 0 0 1 180 100"
        stroke="#30363d" stroke-width="18" fill="none"
        stroke-linecap="round"/>
  <!-- filled arc -->
  <path class="gauge-fill-path"
        d="M 20 100 A 80 80 0 0 1 180 100"
        stroke="{color}" stroke-width="18" fill="none"
        stroke-linecap="round"
        stroke-dasharray="{arc_len:.1f}"
        stroke-dashoffset="{arc_len:.1f}"
        data-offset-target="{offset:.1f}"/>
  <!-- score text -->
  <text x="100" y="88" text-anchor="middle"
        font-family="'Segoe UI',system-ui,sans-serif"
        font-size="28" font-weight="700" fill="{color}">{score}</text>
  <!-- /100 -->
  <text x="100" y="104" text-anchor="middle"
        font-family="'Segoe UI',system-ui,sans-serif"
        font-size="11" fill="#8b949e">/100 · {label}</text>
</svg>"""


def _svg_bar_chart(counts: dict) -> str:
    """Generate an SVG horizontal bar chart for severity counts."""
    sevs = [
        ("critical",     "#f85149"),
        ("high",         "#d29922"),
        ("medium",       "#3fb950"),
        ("low",          "#58a6ff"),
        ("informational","#8b949e"),
    ]
    total = max(1, max((counts.get(s, 0) for s, _ in sevs), default=1))
    max_bar_width = 260
    bar_h = 20
    row_gap = 34
    svg_height = len(sevs) * row_gap + 10
    rows = []
    for i, (sev, color) in enumerate(sevs):
        cnt = counts.get(sev, 0)
        bar_w = int((cnt / total) * max_bar_width) if cnt else 0
        y = i * row_gap + 8
        label = sev[:4].upper() if sev != "informational" else "INFO"
        rows.append(f"""  <!-- {sev} -->
  <text x="56" y="{y + bar_h - 5}" text-anchor="end"
        font-family="'Segoe UI',system-ui,sans-serif"
        font-size="11" fill="#8b949e">{label}</text>
  <rect x="62" y="{y}" width="{max_bar_width}" height="{bar_h}"
        rx="4" fill="#21262d"/>
  <rect x="62" y="{y}" width="{bar_w}" height="{bar_h}"
        rx="4" fill="{color}" opacity="0.85"/>
  <text x="{62 + bar_w + 6}" y="{y + bar_h - 5}"
        font-family="'Segoe UI',system-ui,sans-serif"
        font-size="11" fill="{color}">{cnt}</text>""")
    return f'<svg viewBox="0 0 400 {svg_height}" class="bar-chart-svg" aria-label="Severity bar chart">\n' + \
           "\n".join(rows) + "\n</svg>"


# ---------------------------------------------------------------------------
# FINDING CARD HTML
# ---------------------------------------------------------------------------

def _evidence_section(evidence: str) -> str:
    """Render an expandable evidence block."""
    if not evidence or not evidence.strip():
        return ""
    esc = (evidence[:2000]
           .replace("&", "&amp;")
           .replace("<", "&lt;")
           .replace(">", "&gt;"))
    return f"""<div class="evidence-wrapper">
  <button class="evidence-toggle" onclick="toggleEvidence(this)">
    &#9654; Show Evidence
  </button>
  <pre class="evidence-block" style="display:none"><code>{esc}</code></pre>
</div>"""


def _finding_card_html(f: dict, idx: int) -> str:
    """Render a single finding as a styled HTML card."""
    sev = (f.get("severity") or "informational").lower()
    color = _SEV_HTML_COLORS.get(sev, "#8b949e")
    bg = _SEV_HTML_BG.get(sev, "rgba(139,148,158,0.1)")
    short_id = f.get("short_id") or f"F{idx:03d}"
    title = (f.get("title") or "Untitled Finding").replace("<", "&lt;").replace(">", "&gt;")
    cvss = f.get("cvss_score")
    cvss_str = f"{cvss:.1f}" if cvss is not None else "N/A"
    cvss_color = ("#f85149" if (cvss or 0) >= 9.0 else
                  "#d29922" if (cvss or 0) >= 7.0 else
                  "#ecc94b" if (cvss or 0) >= 4.0 else
                  "#3fb950")
    cwe = (f.get("cwe") or "").replace("<", "&lt;")
    url = (f.get("url") or "").replace("<", "&lt;").replace(">", "&gt;")
    status = (f.get("status") or "open").capitalize()
    owasp = (f.get("owasp") or "").replace("<", "&lt;")
    mitre = (f.get("mitre") or "").replace("<", "&lt;")
    desc = (f.get("description") or "No description provided.")
    impact = (f.get("impact") or "Impact not specified.")
    remediation = (f.get("remediation") or "Remediation not specified.")
    refs = (f.get("refs") or "")

    meta_parts = []
    if cwe:
        meta_parts.append(f'<span class="meta-tag">CWE: {cwe}</span>')
    if owasp:
        meta_parts.append(f'<span class="meta-tag">OWASP: {owasp}</span>')
    if mitre:
        meta_parts.append(f'<span class="meta-tag">MITRE: {mitre}</span>')
    if url:
        meta_parts.append(f'<span class="meta-tag url-tag" title="{url}">URL: {url[:60]}{"…" if len(url)>60 else ""}</span>')
    meta_parts.append(f'<span class="meta-tag status-tag">{status}</span>')

    refs_html = ""
    if refs:
        refs_esc = refs.replace("<", "&lt;").replace(">", "&gt;")
        refs_html = f"<h4>References</h4><p class='refs-text'>{refs_esc}</p>"

    return f"""<div class="finding-card sev-{sev}" id="finding-{short_id}" style="border-left-color:{color};background:{bg}">
  <div class="finding-header">
    <span class="finding-id">{short_id}</span>
    <span class="finding-title">{title}</span>
    <span class="badge" style="background:{color}20;color:{color};border-color:{color}40">{sev.upper()}</span>
    <span class="cvss-score" style="color:{cvss_color}" title="CVSS Score">{cvss_str}</span>
  </div>
  <div class="finding-meta">{'  ·  '.join(meta_parts) if meta_parts else ''}</div>
  <div class="finding-body">
    <h4>Description</h4>
    <p>{desc}</p>
    <h4>Business Impact</h4>
    <p>{impact}</p>
    {_evidence_section(f.get("evidence"))}
    <h4>Remediation</h4>
    <p>{remediation}</p>
    {refs_html}
  </div>
</div>"""


# ---------------------------------------------------------------------------
# FULL HTML REPORT GENERATOR
# ---------------------------------------------------------------------------

def _generate_hakuza_html_report(
    markdown_content: str,
    eng: dict,
    findings: list,
    counts: dict,
    score: int,
) -> str:
    """
    Generate a complete standalone HTML pentest report.
    Returns full HTML as a string — no external dependencies.
    """
    now_str = datetime.now().strftime("%Y-%m-%d")
    now_long = datetime.now().strftime("%B %d, %Y")
    client_name = eng.get("client") or eng.get("client_name") or "Confidential Client"
    tester = eng.get("tester") or _TESTER_NAME
    target = eng.get("target") or eng.get("target_url") or "N/A"
    eng_type = (eng.get("type") or "web").upper()
    eng_name = eng.get("name") or "engagement"
    risk_label = _risk_label(score)
    risk_color = _risk_color(score)

    total = sum(counts.values())
    c_crit = counts.get("critical", 0)
    c_high = counts.get("high", 0)
    c_med  = counts.get("medium", 0)
    c_low  = counts.get("low", 0)
    c_info = counts.get("informational", 0)

    # Convert markdown body to HTML using markdown2
    md_html = markdown2.markdown(
        markdown_content or "",
        extras=["fenced-code-blocks", "tables", "header-ids",
                "break-on-newline", "strike", "code-friendly"],
    )

    # Build finding cards HTML
    finding_cards = "\n".join(
        _finding_card_html(f, i) for i, f in enumerate(findings, 1)
    ) if findings else "<p class='no-findings'>No findings recorded for this engagement.</p>"

    # SVG components
    gauge_svg = _svg_gauge(score)
    bar_svg = _svg_bar_chart(counts)

    # Navigation anchors from markdown headers
    nav_items = []
    for m in re.finditer(r'^## (\d+)\. (.+)$', markdown_content or "", re.MULTILINE):
        num, heading = m.group(1), m.group(2).strip()
        anchor = f"section-{num}"
        nav_items.append(f'<a href="#{anchor}" class="nav-item">{num}. {heading}</a>')
    nav_html = "\n".join(nav_items)

    # Inject section IDs into rendered markdown HTML
    def _add_section_id(match):
        num = re.search(r'^(\d+)\.', match.group(1))
        if num:
            return f'<h2 id="section-{num.group(1)}">{match.group(1)}</h2>'
        return match.group(0)
    md_html = re.sub(r'<h2>(.*?)</h2>', _add_section_id, md_html)

    # Gauge animation offset data
    arc_len = math.pi * 80
    filled = (score / 100.0) * arc_len
    offset_target = arc_len - filled

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Pentest Report — {client_name} — {now_str}</title>
  <style>
    /* ===================== RESET & BASE ===================== */
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    :root {{
      --bg:         #0d1117;
      --surface:    #161b22;
      --surface2:   #21262d;
      --border:     #30363d;
      --text:       #c9d1d9;
      --muted:      #8b949e;
      --accent:     #58a6ff;
      --critical:   #f85149;
      --high:       #d29922;
      --medium:     #3fb950;
      --low:        #58a6ff;
      --info:       #8b949e;
      --radius:     10px;
      --font:       'Segoe UI', system-ui, -apple-system, sans-serif;
    }}
    html {{ scroll-behavior: smooth; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: var(--font);
      font-size: 15px;
      line-height: 1.75;
    }}

    /* ===================== CONFIDENTIAL WATERMARK ===================== */
    body::before {{
      content: "CONFIDENTIAL";
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%) rotate(-35deg);
      font-size: 7rem;
      font-weight: 900;
      color: rgba(248, 81, 73, 0.04);
      pointer-events: none;
      z-index: 0;
      white-space: nowrap;
      letter-spacing: 0.2em;
      user-select: none;
    }}

    /* ===================== LAYOUT ===================== */
    .confidential-banner {{
      background: var(--critical);
      color: white;
      text-align: center;
      padding: 9px 16px;
      font-weight: 700;
      letter-spacing: 3px;
      font-size: 12px;
      position: sticky;
      top: 0;
      z-index: 200;
      text-transform: uppercase;
    }}
    .layout {{
      display: flex;
      max-width: 1300px;
      margin: 0 auto;
      padding: 0 16px;
      gap: 32px;
    }}
    .sidebar {{
      width: 220px;
      flex-shrink: 0;
      position: sticky;
      top: 40px;
      height: calc(100vh - 60px);
      overflow-y: auto;
      padding: 32px 0 32px 0;
    }}
    .main {{
      flex: 1;
      min-width: 0;
      padding: 40px 0 80px 0;
      position: relative;
      z-index: 1;
    }}

    /* ===================== SIDEBAR NAV ===================== */
    .sidebar-title {{
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 1.5px;
      color: var(--muted);
      font-weight: 600;
      margin-bottom: 12px;
      padding: 0 12px;
    }}
    .nav-item {{
      display: block;
      padding: 7px 12px;
      color: var(--muted);
      text-decoration: none;
      font-size: 13px;
      border-radius: 6px;
      margin-bottom: 2px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      transition: background 0.15s, color 0.15s;
    }}
    .nav-item:hover {{
      background: var(--surface2);
      color: var(--text);
    }}

    /* ===================== REPORT HEADER ===================== */
    .report-header {{
      margin-bottom: 40px;
      padding-bottom: 32px;
      border-bottom: 1px solid var(--border);
    }}
    .report-title {{
      font-size: 2rem;
      font-weight: 700;
      color: var(--accent);
      line-height: 1.2;
      margin-bottom: 6px;
    }}
    .report-subtitle {{
      color: var(--muted);
      font-size: 1rem;
      margin-bottom: 24px;
    }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-top: 20px;
    }}
    .meta-item {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 14px 16px;
    }}
    .meta-item .label {{
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 1.2px;
      color: var(--muted);
      font-weight: 600;
    }}
    .meta-item .value {{
      font-size: 14px;
      font-weight: 600;
      color: var(--text);
      margin-top: 4px;
      word-break: break-word;
    }}

    /* ===================== STATS ROW ===================== */
    .stats-row {{
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 10px;
      margin: 28px 0;
    }}
    .stat-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-top: 3px solid var(--border);
      border-radius: var(--radius);
      padding: 18px 12px;
      text-align: center;
    }}
    .stat-card.critical {{ border-top-color: var(--critical); }}
    .stat-card.high     {{ border-top-color: var(--high); }}
    .stat-card.medium   {{ border-top-color: var(--medium); }}
    .stat-card.low      {{ border-top-color: var(--low); }}
    .stat-card .number  {{
      font-size: 2.2rem;
      font-weight: 700;
      line-height: 1;
    }}
    .stat-card.critical .number {{ color: var(--critical); }}
    .stat-card.high     .number {{ color: var(--high); }}
    .stat-card.medium   .number {{ color: var(--medium); }}
    .stat-card.low      .number {{ color: var(--low); }}
    .stat-card .label   {{
      font-size: 11px;
      color: var(--muted);
      margin-top: 6px;
      text-transform: uppercase;
      letter-spacing: 0.8px;
    }}

    /* ===================== RISK DASHBOARD ===================== */
    .risk-dashboard {{
      display: grid;
      grid-template-columns: 220px 1fr;
      gap: 24px;
      align-items: center;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 24px 28px;
      margin: 28px 0;
    }}
    .gauge-svg {{ width: 200px; height: 120px; }}
    .gauge-info h3 {{
      font-size: 1.1rem;
      color: var(--text);
      margin-bottom: 6px;
      margin-top: 0;
    }}
    .gauge-info p {{
      color: var(--muted);
      font-size: 13.5px;
      margin: 0;
    }}
    .bar-chart-section {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 20px 24px;
      margin: 20px 0;
    }}
    .bar-chart-section h3 {{
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: var(--muted);
      margin-bottom: 14px;
    }}
    .bar-chart-svg {{ width: 100%; height: auto; display: block; }}

    /* ===================== MARKDOWN BODY ===================== */
    .report-body h1 {{
      font-size: 1.8rem;
      color: var(--accent);
      margin: 36px 0 14px;
      padding-bottom: 8px;
      border-bottom: 1px solid var(--border);
    }}
    .report-body h2 {{
      font-size: 1.35rem;
      color: var(--accent);
      margin: 36px 0 12px;
      padding-bottom: 8px;
      border-bottom: 1px solid var(--border);
    }}
    .report-body h3 {{
      font-size: 1.1rem;
      color: var(--text);
      margin: 24px 0 8px;
    }}
    .report-body h4 {{
      font-size: 0.95rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.8px;
      margin: 16px 0 6px;
    }}
    .report-body p {{ margin: 10px 0; color: var(--text); }}
    .report-body ul, .report-body ol {{ margin: 10px 0 10px 22px; }}
    .report-body li {{ margin: 4px 0; color: var(--text); }}
    .report-body code {{
      background: var(--surface2);
      color: #d2a8ff;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 0.88em;
      font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    }}
    .report-body pre {{
      background: var(--surface2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      overflow-x: auto;
      margin: 14px 0;
    }}
    .report-body pre code {{
      background: none;
      padding: 0;
      color: var(--text);
      font-size: 0.87em;
    }}
    .report-body strong {{ color: #f0f6fc; }}
    .report-body em {{ color: var(--muted); }}
    .report-body table {{
      width: 100%;
      border-collapse: collapse;
      margin: 16px 0;
      font-size: 14px;
    }}
    .report-body th {{
      background: var(--surface2);
      color: var(--muted);
      text-transform: uppercase;
      font-size: 11px;
      letter-spacing: 1px;
      padding: 10px 12px;
      text-align: left;
      border-bottom: 2px solid var(--border);
    }}
    .report-body td {{
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
    }}
    .report-body tr:hover td {{ background: var(--surface); }}
    .report-body hr {{
      border: none;
      border-top: 1px solid var(--border);
      margin: 28px 0;
    }}
    .report-body blockquote {{
      border-left: 3px solid var(--accent);
      padding: 8px 16px;
      color: var(--muted);
      background: var(--surface);
      border-radius: 0 6px 6px 0;
      margin: 14px 0;
    }}

    /* ===================== FINDING CARDS ===================== */
    .findings-section {{ margin-top: 32px; }}
    .findings-section-title {{
      font-size: 1.2rem;
      color: var(--accent);
      margin-bottom: 20px;
      font-weight: 700;
    }}
    .finding-card {{
      border: 1px solid var(--border);
      border-left: 4px solid var(--border);
      border-radius: var(--radius);
      margin-bottom: 20px;
      overflow: hidden;
      break-inside: avoid;
    }}
    .finding-header {{
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 14px 16px;
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      flex-wrap: wrap;
    }}
    .finding-id {{
      font-family: 'Cascadia Code', 'Fira Code', monospace;
      font-size: 12px;
      color: var(--muted);
      flex-shrink: 0;
      background: var(--surface2);
      padding: 2px 8px;
      border-radius: 4px;
    }}
    .finding-title {{
      font-size: 15px;
      font-weight: 600;
      color: var(--text);
      flex: 1;
    }}
    .badge {{
      font-size: 11px;
      font-weight: 700;
      padding: 3px 9px;
      border-radius: 20px;
      border: 1px solid transparent;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      flex-shrink: 0;
    }}
    .cvss-score {{
      font-size: 1.3rem;
      font-weight: 700;
      min-width: 42px;
      text-align: right;
      flex-shrink: 0;
    }}
    .finding-meta {{
      padding: 8px 16px;
      font-size: 12.5px;
      color: var(--muted);
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }}
    .meta-tag {{
      background: var(--surface2);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 2px 8px;
      font-size: 11.5px;
    }}
    .url-tag {{ max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .status-tag {{ text-transform: capitalize; }}
    .finding-body {{
      padding: 16px;
    }}
    .finding-body h4 {{
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: var(--muted);
      font-weight: 600;
      margin: 14px 0 6px;
    }}
    .finding-body h4:first-child {{ margin-top: 0; }}
    .finding-body p {{ margin: 0 0 4px; font-size: 14px; }}
    .refs-text {{ font-size: 13px; color: var(--muted); }}
    .no-findings {{ color: var(--muted); font-style: italic; padding: 20px 0; }}

    /* ===================== EVIDENCE EXPAND ===================== */
    .evidence-wrapper {{ margin: 10px 0; }}
    .evidence-toggle {{
      background: var(--surface2);
      color: var(--accent);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 5px 12px;
      font-size: 12.5px;
      cursor: pointer;
      font-family: var(--font);
      transition: background 0.15s;
    }}
    .evidence-toggle:hover {{ background: var(--border); }}
    .evidence-block {{
      background: var(--surface2);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px;
      margin-top: 8px;
      overflow-x: auto;
      font-family: 'Cascadia Code', 'Fira Code', monospace;
      font-size: 12.5px;
      line-height: 1.6;
      max-height: 320px;
      overflow-y: auto;
    }}
    .evidence-block code {{ background: none; padding: 0; color: var(--text); }}

    /* ===================== FOOTER ===================== */
    .report-footer {{
      margin-top: 60px;
      padding: 28px 0;
      border-top: 1px solid var(--border);
      text-align: center;
      color: var(--muted);
      font-size: 12.5px;
      line-height: 2;
    }}
    .report-footer .hakuza-badge {{
      display: inline-block;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 4px 12px;
      font-size: 11px;
      color: var(--accent);
      margin-top: 8px;
    }}

    /* ===================== PRINT STYLES ===================== */
    @media print {{
      body {{ background: #fff !important; color: #111 !important; }}
      body::before {{ display: none; }}
      :root {{
        --bg: #fff;
        --surface: #f6f8fa;
        --surface2: #eef1f4;
        --border: #d1d5da;
        --text: #111;
        --muted: #555;
        --accent: #0366d6;
      }}
      .confidential-banner {{
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        z-index: 9999;
      }}
      .sidebar {{ display: none; }}
      .layout {{ display: block; padding: 0 20px; }}
      .finding-card {{ break-inside: avoid; }}
      .evidence-block {{ display: block !important; max-height: none; }}
      .evidence-toggle {{ display: none; }}
      a {{ color: #0366d6; text-decoration: none; }}
      pre, code {{ background: #f6f8fa !important; color: #111 !important; }}
      .badge {{ border: 1px solid currentColor !important; }}
    }}

    /* ===================== RESPONSIVE ===================== */
    @media (max-width: 900px) {{
      .layout {{ flex-direction: column; gap: 0; }}
      .sidebar {{ width: 100%; position: static; height: auto; padding: 16px 0; border-bottom: 1px solid var(--border); }}
      .sidebar {{ display: flex; flex-wrap: wrap; gap: 4px; }}
      .nav-item {{ display: inline-block; padding: 4px 10px; }}
      .stats-row {{ grid-template-columns: repeat(3, 1fr); }}
      .risk-dashboard {{ grid-template-columns: 1fr; }}
      .meta-grid {{ grid-template-columns: repeat(2, 1fr); }}
    }}
    @media (max-width: 560px) {{
      .stats-row {{ grid-template-columns: repeat(2, 1fr); }}
      .report-title {{ font-size: 1.5rem; }}
      .meta-grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <div class="confidential-banner">
    &#x1F512; CONFIDENTIAL — RESTRICTED DISTRIBUTION — HAKUZA PENTEST PLATFORM
  </div>

  <div class="layout">
    <!-- SIDEBAR NAVIGATION -->
    <nav class="sidebar" aria-label="Report sections">
      <div class="sidebar-title">Contents</div>
      {nav_html if nav_html else '<span class="nav-item">Report</span>'}
    </nav>

    <!-- MAIN CONTENT -->
    <main class="main">
      <!-- REPORT HEADER -->
      <header class="report-header">
        <div class="report-title">Penetration Test Report</div>
        <div class="report-subtitle">{eng_name} &bull; {eng_type} Assessment &bull; {now_long}</div>
        <div class="meta-grid">
          <div class="meta-item">
            <div class="label">Client</div>
            <div class="value">{client_name}</div>
          </div>
          <div class="meta-item">
            <div class="label">Target</div>
            <div class="value" style="font-size:13px;word-break:break-all">{target}</div>
          </div>
          <div class="meta-item">
            <div class="label">Lead Assessor</div>
            <div class="value">{tester}</div>
          </div>
          <div class="meta-item">
            <div class="label">Report Date</div>
            <div class="value">{now_str}</div>
          </div>
          <div class="meta-item">
            <div class="label">Classification</div>
            <div class="value" style="color:var(--critical)">CONFIDENTIAL</div>
          </div>
          <div class="meta-item">
            <div class="label">Overall Risk</div>
            <div class="value" style="color:{risk_color}">{risk_label}</div>
          </div>
        </div>
      </header>

      <!-- STATS ROW -->
      <div class="stats-row">
        <div class="stat-card critical">
          <div class="number">{c_crit}</div>
          <div class="label">Critical</div>
        </div>
        <div class="stat-card high">
          <div class="number">{c_high}</div>
          <div class="label">High</div>
        </div>
        <div class="stat-card medium">
          <div class="number">{c_med}</div>
          <div class="label">Medium</div>
        </div>
        <div class="stat-card low">
          <div class="number">{c_low}</div>
          <div class="label">Low</div>
        </div>
        <div class="stat-card">
          <div class="number" style="color:var(--accent)">{total}</div>
          <div class="label">Total</div>
        </div>
      </div>

      <!-- RISK DASHBOARD: GAUGE + BAR CHART -->
      <div class="risk-dashboard">
        <div>
          {gauge_svg}
        </div>
        <div class="gauge-info">
          <h3>Overall Risk Score: <span style="color:{risk_color}">{risk_label}</span></h3>
          <p>
            Weighted composite score (Critical×40 + High×20 + Medium×8 + Low×2), capped at 100.
            A score of <strong style="color:{risk_color}">{score}/100</strong> indicates
            {risk_label.lower()} aggregate risk posture. Immediate remediation is
            {"strongly recommended" if score >= 70 else "recommended" if score >= 45 else "advised for high-severity items"}.
          </p>
        </div>
      </div>
      <div class="bar-chart-section">
        <h3>Severity Distribution</h3>
        {bar_svg}
      </div>

      <!-- MAIN REPORT BODY (Claude-generated markdown) -->
      <article class="report-body">
        {md_html}
      </article>

      <!-- FINDING CARDS -->
      {f'<div class="findings-section"><div class="findings-section-title">Interactive Finding Details</div>{finding_cards}</div>' if findings else ''}

      <!-- FOOTER -->
      <footer class="report-footer">
        <div>Generated by <strong>HAKUZA Pentest Platform v{_HAKUZA_VERSION}</strong> &bull; {now_str}</div>
        <div>{tester} &bull; {_TESTER_CREDS}</div>
        <div>Powered by Anthropic Claude AI</div>
        <div>This document is classified CONFIDENTIAL. Unauthorised distribution is prohibited.</div>
        <div class="hakuza-badge">HAKUZA v{_HAKUZA_VERSION}</div>
      </footer>
    </main>
  </div>

  <script>
    // ── Evidence expand/collapse ──────────────────────────────────────────
    function toggleEvidence(btn) {{
      var block = btn.nextElementSibling;
      if (!block) return;
      var hidden = block.style.display === 'none' || block.style.display === '';
      block.style.display = hidden ? 'block' : 'none';
      btn.textContent = hidden ? '▼ Hide Evidence' : '▶ Show Evidence';
    }}

    // ── Gauge fill animation ──────────────────────────────────────────────
    (function animateGauge() {{
      var path = document.querySelector('.gauge-fill-path');
      if (!path) return;
      var target = parseFloat(path.getAttribute('data-offset-target'));
      var start  = parseFloat(path.getAttribute('stroke-dasharray'));
      var duration = 1100; // ms
      var startTime = null;

      function ease(t) {{ return t < 0.5 ? 2*t*t : -1+(4-2*t)*t; }}

      function step(ts) {{
        if (!startTime) startTime = ts;
        var elapsed = ts - startTime;
        var progress = Math.min(elapsed / duration, 1);
        var eased = ease(progress);
        var current = start + (target - start) * eased;
        path.setAttribute('stroke-dashoffset', current.toFixed(2));
        if (progress < 1) requestAnimationFrame(step);
      }}
      requestAnimationFrame(step);
    }})();

    // ── Active nav highlighting on scroll ────────────────────────────────
    (function initNav() {{
      var sections = document.querySelectorAll('[id^="section-"]');
      var navLinks = document.querySelectorAll('.nav-item');
      if (!sections.length || !navLinks.length) return;

      function onScroll() {{
        var scrollY = window.scrollY + 80;
        var current = '';
        sections.forEach(function(sec) {{
          if (sec.offsetTop <= scrollY) current = sec.id;
        }});
        navLinks.forEach(function(link) {{
          var href = link.getAttribute('href');
          if (href && href === '#' + current) {{
            link.style.color = 'var(--accent)';
            link.style.background = 'var(--surface2)';
          }} else {{
            link.style.color = '';
            link.style.background = '';
          }}
        }});
      }}
      window.addEventListener('scroll', onScroll, {{passive: true}});
      onScroll();
    }})();
  </script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# DIFF REPORT
# ---------------------------------------------------------------------------

def cmd_diff_report(args, console) -> None:
    """
    hakuza diff-report --old <file> --new <file> [--output <file>]

    Compare two exported JSON finding lists and emit a delta report:
    - NEW findings (in new but not old)
    - FIXED findings (in old but not new, or status=remediated)
    - CHANGED findings (same short_id but different severity/status)
    """
    old_file = getattr(args, "old", None)
    new_file = getattr(args, "new", None)

    if not old_file or not new_file:
        console.print("[red]Usage: hakuza diff-report --old <old.json> --new <new.json>[/red]")
        return

    def _load(path: str) -> dict:
        p = Path(path)
        if not p.exists():
            console.print(f"[red]File not found: {path}[/red]")
            return {}
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return {(f.get("short_id") or f.get("id") or f.get("title", "")): f for f in data}
            return {}
        except (json.JSONDecodeError, OSError) as exc:
            console.print(f"[red]Failed to parse {path}: {exc}[/red]")
            return {}

    old_map = _load(old_file)
    new_map = _load(new_file)

    if not old_map and not new_map:
        console.print("[yellow]Could not load either file. Aborting.[/yellow]")
        return

    all_keys = set(old_map) | set(new_map)
    new_findings = []
    fixed_findings = []
    changed_findings = []
    unchanged = []

    for key in sorted(all_keys):
        in_old = key in old_map
        in_new = key in new_map

        if in_new and not in_old:
            new_findings.append(new_map[key])
        elif in_old and not in_new:
            fixed_findings.append(old_map[key])
        elif in_old and in_new:
            old_f = old_map[key]
            new_f = new_map[key]
            old_sev = (old_f.get("severity") or "").lower()
            new_sev = (new_f.get("severity") or "").lower()
            old_status = (old_f.get("status") or "").lower()
            new_status = (new_f.get("status") or "").lower()
            if new_status in ("remediated", "fp"):
                fixed_findings.append(new_f)
            elif old_sev != new_sev or old_status != new_status:
                changed_findings.append({"old": old_f, "new": new_f})
            else:
                unchanged.append(new_f)

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    console.print(Rule("[bold cyan]Finding Delta Report[/bold cyan]"))
    console.print(f"[dim]Old: {old_file}  |  New: {new_file}  |  Generated: {now_str}[/dim]\n")

    from rich.table import Table
    from rich import box as rbox

    def _sev_color(sev):
        return {"critical": "bold red", "high": "bold orange3",
                "medium": "bold yellow", "low": "bold green"}.get(sev.lower(), "white")

    if new_findings:
        console.print(f"[bold red]  NEW FINDINGS ({len(new_findings)})[/bold red]")
        t = Table(box=rbox.SIMPLE_HEAVY, show_header=True, header_style="bold")
        t.add_column("ID", width=16)
        t.add_column("Title")
        t.add_column("Severity", width=12)
        t.add_column("CVSS", width=7)
        for f in new_findings:
            sev = (f.get("severity") or "info").lower()
            t.add_row(
                f.get("short_id", "-"),
                (f.get("title") or "")[:60],
                f.get("severity", "info").upper(),
                str(f.get("cvss_score") or "-"),
                style=_sev_color(sev),
            )
        console.print(t)

    if fixed_findings:
        console.print(f"\n[bold green]  FIXED / REMEDIATED ({len(fixed_findings)})[/bold green]")
        t = Table(box=rbox.SIMPLE_HEAVY, show_header=True, header_style="bold")
        t.add_column("ID", width=16)
        t.add_column("Title")
        t.add_column("Previous Severity", width=16)
        for f in fixed_findings:
            t.add_row(
                f.get("short_id", "-"),
                (f.get("title") or "")[:60],
                (f.get("severity") or "").upper(),
                style="dim",
            )
        console.print(t)

    if changed_findings:
        console.print(f"\n[bold yellow]  CHANGED FINDINGS ({len(changed_findings)})[/bold yellow]")
        t = Table(box=rbox.SIMPLE_HEAVY, show_header=True, header_style="bold")
        t.add_column("ID", width=16)
        t.add_column("Title")
        t.add_column("Old Sev", width=10)
        t.add_column("New Sev", width=10)
        t.add_column("Old Status", width=12)
        t.add_column("New Status", width=12)
        for ch in changed_findings:
            t.add_row(
                ch["new"].get("short_id", "-"),
                (ch["new"].get("title") or "")[:50],
                (ch["old"].get("severity") or "").upper(),
                (ch["new"].get("severity") or "").upper(),
                (ch["old"].get("status") or "").lower(),
                (ch["new"].get("status") or "").lower(),
            )
        console.print(t)

    console.print(
        f"\n[dim]Summary: "
        f"[red]{len(new_findings)} new[/red]  |  "
        f"[green]{len(fixed_findings)} fixed[/green]  |  "
        f"[yellow]{len(changed_findings)} changed[/yellow]  |  "
        f"{len(unchanged)} unchanged[/dim]"
    )

    # Save delta JSON if output requested
    output_file = getattr(args, "output", None)
    if output_file:
        delta = {
            "generated": now_str,
            "old_file": old_file,
            "new_file": new_file,
            "summary": {
                "new": len(new_findings),
                "fixed": len(fixed_findings),
                "changed": len(changed_findings),
                "unchanged": len(unchanged),
            },
            "new_findings": new_findings,
            "fixed_findings": fixed_findings,
            "changed_findings": changed_findings,
        }
        try:
            Path(output_file).write_text(json.dumps(delta, indent=2), encoding="utf-8")
            console.print(f"\n[green]Delta report saved:[/green] {output_file}")
        except OSError as exc:
            console.print(f"[red]Failed to save delta report: {exc}[/red]")


# ---------------------------------------------------------------------------
# MAIN COMMAND
# ---------------------------------------------------------------------------

def cmd_report(args, console) -> None:
    """
    hakuza report [--html] [--output FILE] [--client NAME] [--type executive|technical|full]

    Generate a professional penetration test report for the current engagement.
    Streams Claude's analysis, then produces an optional standalone HTML file
    with SVG risk gauge, bar chart, and collapsible finding cards.
    """
    # Import from hakuza.py namespace (available at merge time)
    from hakuza import (
        _require_engagement, get_client, list_findings,
        get_finding_count, get_recon_summary, get_config_value,
        stream_to_console, print_engagement_header, ENGAGEMENTS_DIR,
    )

    eng = _require_engagement(console)
    ai_client = get_client()

    # ── Gather data ──────────────────────────────────────────────────────
    findings = list_findings(eng["id"])
    counts = get_finding_count(eng["id"])
    score = _calc_risk_score(counts)
    recon_summary = get_recon_summary(eng["id"])
    total = sum(counts.values())

    client_override = getattr(args, "client", None)
    client_name = (
        client_override
        or eng.get("client")
        or eng.get("client_name")
        or "Confidential Client"
    )
    report_type = getattr(args, "type", "full") or "full"
    gen_html = getattr(args, "html", False)
    output_file = getattr(args, "output", None)

    # ── Console header ───────────────────────────────────────────────────
    print_engagement_header(eng, console)
    console.print(Rule(f"[bold cyan]Generating {report_type.title()} Pentest Report[/bold cyan]"))
    console.print(
        f"[dim]  Findings: [red]{counts.get('critical',0)} Critical[/red]  "
        f"[yellow]{counts.get('high',0)} High[/yellow]  "
        f"[green]{counts.get('medium',0)} Medium[/green]  "
        f"[blue]{counts.get('low',0)} Low[/blue]  |  "
        f"Risk Score: {score}/100 ({_risk_label(score)})[/dim]\n"
    )
    if recon_summary:
        recon_items = ", ".join(f"{k}:{v}" for k, v in recon_summary.items())
        console.print(f"[dim]  Recon data: {recon_items}[/dim]\n")

    # ── Build and stream prompt ──────────────────────────────────────────
    prompt = _build_report_prompt(eng, findings, counts, score, report_type, client_name)
    messages = [{"role": "user", "content": prompt}]

    console.print(Rule("[dim]Claude Analysis[/dim]"))
    full_md = stream_to_console(ai_client, messages, max_tokens=8192, console=console)
    console.print(Rule())

    # ── Save markdown ────────────────────────────────────────────────────
    safe_name = re.sub(r"[^\w-]", "_", eng.get("name", "report"))
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_name = f"{safe_name}_{report_type}_report_{ts}"

    if output_file:
        out_md = Path(output_file).with_suffix(".md")
    else:
        eng_dir = ENGAGEMENTS_DIR / eng.get("name", "unknown")
        (eng_dir / "reports").mkdir(parents=True, exist_ok=True)
        out_md = eng_dir / "reports" / f"{default_name}.md"

    try:
        out_md.write_text(full_md or "", encoding="utf-8")
        console.print(f"[green]Markdown report saved:[/green] {out_md}")
    except OSError as exc:
        console.print(f"[yellow]Could not save markdown: {exc}[/yellow]")

    # ── Generate HTML ────────────────────────────────────────────────────
    if gen_html:
        console.print("\n[cyan]Generating HTML report...[/cyan]")
        try:
            html_content = _generate_hakuza_html_report(
                markdown_content=full_md or "",
                eng=eng,
                findings=findings,
                counts=counts,
                score=score,
            )
            out_html = out_md.with_suffix(".html")
            out_html.write_text(html_content, encoding="utf-8")
            console.print(f"[green]HTML report saved:[/green] {out_html}")
            console.print(f"[dim]  Open in browser: file://{out_html.resolve()}[/dim]")
        except Exception as exc:
            console.print(f"[red]HTML generation failed: {exc}[/red]")

    # ── Summary panel ────────────────────────────────────────────────────
    sev_line = (
        f"[red]{counts.get('critical',0)} Critical[/red]  |  "
        f"[orange3]{counts.get('high',0)} High[/orange3]  |  "
        f"[yellow]{counts.get('medium',0)} Medium[/yellow]  |  "
        f"[green]{counts.get('low',0)} Low[/green]  |  "
        f"[blue]{counts.get('informational',0)} Info[/blue]"
    )
    console.print(
        Panel(
            f"[bold]Engagement:[/bold] {eng.get('name','')} — {client_name}\n"
            f"[bold]Findings:[/bold] {total} total  ({sev_line})\n"
            f"[bold]Risk Score:[/bold] [bold]{score}/100[/bold]  ({_risk_label(score)})\n"
            f"[bold]Report (MD):[/bold] {out_md}\n"
            + (f"[bold]Report (HTML):[/bold] {out_md.with_suffix('.html')}\n" if gen_html else ""),
            title="[bold green]  Report Complete[/bold green]",
            border_style="green",
            expand=False,
        )
    )


# ---------------------------------------------------------------------------
# ARGPARSE + DISPATCH (for hakuza.py integration)
# ---------------------------------------------------------------------------
#
# In hakuza.py's argument parser, add:
#
#   report_parser = sub.add_parser("report", help="Generate pentest report")
#   report_parser.add_argument("--html",   action="store_true",
#                              help="Also generate standalone HTML report")
#   report_parser.add_argument("--output", metavar="FILE",
#                              help="Output file path (without extension)")
#   report_parser.add_argument("--client", metavar="NAME",
#                              help="Override client name in report")
#   report_parser.add_argument("--type",
#                              choices=["executive", "technical", "full"],
#                              default="full",
#                              help="Report type (default: full)")
#   report_parser.set_defaults(func=cmd_report)
#
#   diff_parser = sub.add_parser("diff-report", help="Compare two finding exports")
#   diff_parser.add_argument("--old",    required=True, metavar="FILE",
#                            help="Old findings JSON file")
#   diff_parser.add_argument("--new",    required=True, metavar="FILE",
#                            help="New findings JSON file")
#   diff_parser.add_argument("--output", metavar="FILE",
#                            help="Save delta as JSON")
#   diff_parser.set_defaults(func=cmd_diff_report)

# END mod_report.py
