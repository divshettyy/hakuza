"""
HAKUZA — browser-based web dashboard (Flask)
============================================

A read-mostly web UI over the same SQLite engagement database that the HAKUZA
CLI writes to (``~/.hakuza/hakuza.db``). It reuses hakuza.py's own DB helpers
and visual primitives (SVG risk gauge, severity bar chart, HTML report colours)
so the web view is visually consistent with the CLI-generated HTML report.

Security posture (see also run.py):
- Every template renders through Jinja2 with autoescaping ON. Finding-derived
  text (title/description/evidence/remediation/url) and engagement metadata
  (client/target/tester) can contain arbitrary attacker-influenced content
  (imported nuclei/Nessus findings, a pentester's literal ``<script>`` PoC),
  so it is NEVER passed through ``|safe`` or ``Markup()``.
- The only ``|safe`` values in the templates are the SVG gauge / bar-chart
  markup, which are generated in Python purely from an integer risk score and
  integer severity counts — never from user/finding text.
- The app is read-only against the DB. It performs no writes and exposes no
  state-changing endpoints, so there is no CSRF / SQL-write surface. All reads
  go through hakuza.py's parameterised query helpers.
"""

import sys
from pathlib import Path

# hakuza.py lives one directory up (the assembled, runnable core). Import it so
# we reuse its exact DB access + rendering helpers rather than re-implementing
# (and potentially diverging from) them.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import hakuza  # noqa: E402

from flask import (  # noqa: E402
    Flask,
    abort,
    render_template,
    redirect,
    send_file,
    url_for,
)

app = Flask(__name__)

# Severity display order for tables/legends.
_SEV_ORDER = ["critical", "high", "medium", "low", "informational"]


# --------------------------------------------------------------------------- #
# Data helpers — thin wrappers over hakuza.py's own DB layer
# --------------------------------------------------------------------------- #

def _normalize_sev(sev):
    """Fold hakuza's 'info' alias into 'informational' for display."""
    sev = (sev or "informational").lower()
    return "informational" if sev == "info" else sev


def _recon_counts(engagement_id):
    """
    Count real recon artifacts (subdomains/hosts/ports/urls) for an engagement.

    ``recon_data`` stores each artifact set as a single newline-joined blob, so
    the row count is not the item count — we sum non-empty lines across rows of
    each type. Uses hakuza's singleton DB connection with a parameterised query
    (never string-interpolated), matching the CLI's own access pattern.
    """
    conn = hakuza.get_db()
    rows = conn.execute(
        "SELECT data_type, content FROM recon_data WHERE engagement_id = ?",
        (engagement_id,),
    ).fetchall()
    tallies = {}
    for row in rows:
        dtype = row["data_type"]
        content = row["content"] or ""
        # 'ports' is stored as an nmap JSON blob, not line-per-host; count rows.
        if dtype == "ports":
            tallies[dtype] = tallies.get(dtype, 0) + 1
        else:
            n = len([ln for ln in content.splitlines() if ln.strip()])
            tallies[dtype] = tallies.get(dtype, 0) + n
    return tallies


def _engagement_summary(eng):
    """Build the per-engagement summary block used by the index and detail views."""
    counts = hakuza.get_finding_count(eng["id"])
    score = hakuza._calc_risk_score(counts)
    return {
        "eng": eng,
        "counts": counts,
        "total": sum(counts.values()),
        "score": score,
        "risk_label": hakuza._risk_label(score),
        "risk_color": hakuza._risk_color(score),
    }


def _latest_report(eng_name):
    """Return the newest generated HTML report path for an engagement, or None."""
    reports_dir = hakuza.ENGAGEMENTS_DIR / eng_name / "reports"
    if not reports_dir.is_dir():
        return None
    htmls = sorted(
        reports_dir.glob("*.html"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return htmls[0] if htmls else None


# --------------------------------------------------------------------------- #
# Template globals — expose hakuza's colour/severity constants to Jinja
# --------------------------------------------------------------------------- #

@app.context_processor
def _inject_globals():
    return {
        "SEV_COLORS": hakuza._SEV_HTML_COLORS,
        "SEV_BG": hakuza._SEV_HTML_BG,
        "SEV_ORDER": _SEV_ORDER,
        "normalize_sev": _normalize_sev,
    }


# --------------------------------------------------------------------------- #
# Routes (all GET / read-only)
# --------------------------------------------------------------------------- #

@app.route("/")
def index():
    engagements = hakuza.list_engagements()
    summaries = [_engagement_summary(e) for e in engagements]
    current = hakuza.get_config_value("current_engagement")
    return render_template(
        "index.html",
        summaries=summaries,
        current=current,
    )


@app.route("/engagement/<name>")
def engagement(name):
    eng = hakuza.get_engagement(name)
    if not eng:
        abort(404, description="No such engagement")

    summary = _engagement_summary(eng)
    findings = hakuza.list_findings(eng["id"])
    recon = _recon_counts(eng["id"])
    latest_report = _latest_report(name)

    # SVG markup generated from numeric score / counts only — safe to render raw.
    gauge_svg = hakuza._svg_gauge(summary["score"])
    bar_svg = hakuza._svg_bar_chart(summary["counts"])

    return render_template(
        "engagement.html",
        summary=summary,
        eng=eng,
        findings=findings,
        recon=recon,
        gauge_svg=gauge_svg,
        bar_svg=bar_svg,
        has_report=latest_report is not None,
    )


@app.route("/engagement/<name>/finding/<finding_id>")
def finding_detail(name, finding_id):
    eng = hakuza.get_engagement(name)
    if not eng:
        abort(404, description="No such engagement")

    conn = hakuza.get_db()
    row = conn.execute(
        "SELECT * FROM findings WHERE id = ? AND engagement_id = ?",
        (finding_id, eng["id"]),
    ).fetchone()
    if not row:
        abort(404, description="No such finding")

    return render_template(
        "finding.html",
        eng=eng,
        f=dict(row),
    )


@app.route("/engagement/<name>/report")
def open_report(name):
    """Serve the most recently generated HTML report for an engagement, if any."""
    eng = hakuza.get_engagement(name)
    if not eng:
        abort(404, description="No such engagement")
    report = _latest_report(name)
    if not report:
        abort(404, description="No HTML report generated yet — run `hakuza report --html`")
    # send_file streams the on-disk report the CLI already produced.
    return send_file(str(report))


@app.errorhandler(404)
def _not_found(err):
    return render_template("404.html", message=getattr(err, "description", "Not found")), 404


if __name__ == "__main__":
    # Direct execution defers to run.py's hardened launcher semantics.
    app.run(host="127.0.0.1", port=7373)
