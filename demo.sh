#!/usr/bin/env bash
# =============================================================================
#  HAKUZA — Live Interview Demo
#  Runs a real autopilot pass against scanme.nmap.org, nmap.org's own
#  public target explicitly maintained for scanning practice — no
#  authorization concerns, safe to run live in front of an interviewer.
#  Built by Divith D Shetty | CEH · CRTP · CAISP
# =============================================================================

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

_has_tput=false
command -v tput &>/dev/null && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]] && _has_tput=true

if $_has_tput; then
    BOLD="$(tput bold)"; DIM="$(tput dim)"; RESET="$(tput sgr0)"
    RED="$(tput setaf 1)"; GREEN="$(tput setaf 2)"; YELLOW="$(tput setaf 3)"
    BLUE="$(tput setaf 4)"; CYAN="$(tput setaf 6)"; WHITE="$(tput setaf 7)"
else
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
    BLUE=$'\033[0;34m'; CYAN=$'\033[0;36m'; WHITE=$'\033[0;37m'
fi

divider() { printf "${DIM}%s${RESET}\n" "$(printf '─%.0s' {1..72})"; }
pause() { printf "\n  ${DIM}${CYAN}[ Press Enter to continue... ]${RESET}"; read -r; printf "\n"; }
announce() { printf "  ${BOLD}${YELLOW}▶${RESET}  %s\n\n" "$*"; }
show_cmd() { printf "  ${BOLD}${GREEN}\$ %s${RESET}\n\n" "$1"; }

DEMO_ENGAGEMENT="hakuza-demo-$(date +%s)"

printf "\n"
divider
printf "  ${BOLD}${CYAN}HAKUZA${RESET} — Unified Penetration Testing Platform ${DIM}v2.0.0${RESET}\n"
printf "  ${DIM}Divith D Shetty | CEH · CRTP · CAISP | Powered by Claude${RESET}\n"
divider
printf "\n  This demo runs a real, live 'hakuza autopilot' pass against\n"
printf "  ${BOLD}scanme.nmap.org${RESET} — Nmap's own public target, explicitly kept\n"
printf "  online for scanning tools to test against. Nothing here is\n"
printf "  simulated: subfinder, httpx, waybackurls, katana, and nuclei all\n"
printf "  run for real, and every finding is persisted to a SQLite\n"
printf "  engagement database.\n"

if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    printf "\n  ${YELLOW}Note:${RESET} No ANTHROPIC_API_KEY set — recon/scan phases run at full\n"
    printf "  strength regardless; AI triage/report-narrative phases degrade to\n"
    printf "  a deterministic findings-only report instead of blocking.\n"
fi

pause

announce "Step 1 — Create the engagement and define scope"
show_cmd "hakuza init $DEMO_ENGAGEMENT --client 'Interview Demo' --target scanme.nmap.org --type web"
python3 hakuza.py init "$DEMO_ENGAGEMENT" --client "Interview Demo" --target scanme.nmap.org --type web
show_cmd "hakuza scope --add 'http://scanme.nmap.org/*'"
python3 hakuza.py scope --add "http://scanme.nmap.org/*"
pause

announce "Step 2 — Run the full autopilot pipeline, unattended"
printf "  recon -> takeover -> wayback -> secrets -> scan -> ${DIM}(AI triage/chain if a key is set)${RESET} -> report\n"
printf "  ${DIM}(takeover: subdomain-takeover scan, auto-saves confirmed findings — highest${RESET}\n"
printf "  ${DIM}value-per-effort bug class on bounty programs)${RESET}\n"
printf "  ${DIM}(real network I/O — typically 2-5 minutes end to end, mostly the katana crawl)${RESET}\n\n"
show_cmd "hakuza autopilot --profile quick"
python3 hakuza.py autopilot --profile quick
pause

announce "Step 3 — Review what it found"
show_cmd "hakuza findings"
python3 hakuza.py findings
pause

announce "Step 4 — The HTML report it just generated"
LATEST_HTML=$(find "$HOME/.hakuza/engagements/$DEMO_ENGAGEMENT/reports" -name "*.html" -print -quit 2>/dev/null || true)
if [[ -n "$LATEST_HTML" ]]; then
    printf "  Dark-themed report with an SVG risk gauge, generated deterministically\n"
    printf "  from the DB — no template engine, hand-built SVG + CSS:\n\n"
    printf "  ${BOLD}%s${RESET}\n" "$LATEST_HTML"
else
    printf "  ${DIM}(no report file found — check the autopilot output above)${RESET}\n"
fi
pause

announce "Step 5 — The web dashboard"
printf "  Same engagement, same findings, rendered live in a browser instead of\n"
printf "  a terminal — click-through engagement cards, risk gauge, findings table,\n"
printf "  finding detail. This one's worth showing in its own window rather than\n"
printf "  backgrounded off this script (cleaner to kill, no orphaned process to\n"
printf "  chase down afterward). In a second terminal, right now:\n\n"
show_cmd "hakuza serve"
printf "  Opens ${BOLD}http://127.0.0.1:7373${RESET} directly (add --no-browser to skip that).\n"
printf "  Engagement '${BOLD}%s${RESET}' will already be there — click into it.\n" "$DEMO_ENGAGEMENT"

printf "\n"
divider
printf "  ${GREEN}Demo complete.${RESET} Engagement '${BOLD}%s${RESET}' and its DB records live in\n" "$DEMO_ENGAGEMENT"
printf "  ~/.hakuza/ — clean up with: ${DIM}hakuza list${RESET} to find it, delete its row from\n"
printf "  ~/.hakuza/hakuza.db and rm -rf its engagement directory if desired.\n"
divider
printf "\n"
