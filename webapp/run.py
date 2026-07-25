"""
HAKUZA web dashboard launcher.

Run directly:   cd webapp && python3 run.py
Or via the CLI: hakuza serve   (see hakuza.py's cmd_serve)

Security note — debug mode is OFF by default. Flask/Werkzeug's debug mode
enables the interactive in-browser debugger, which permits arbitrary Python
execution (a well-known RCE vector). It is gated behind an explicit opt-in
env var and the server is always pinned to 127.0.0.1, never Flask's implicit
default host, so the dev server is not reachable off-box.
"""

import os
import sys

try:
    from app import app
except ImportError as exc:
    print(f"Import error: {exc}")
    print("Run this from the webapp/ directory with Flask installed:")
    print("  pip install -r ../requirements.txt")
    sys.exit(1)


def main():
    host = os.environ.get("HAKUZA_WEB_HOST", "127.0.0.1")
    port = int(os.environ.get("HAKUZA_WEB_PORT", "7373"))
    debug = os.environ.get("HAKUZA_WEB_DEBUG", "").lower() in ("1", "true", "yes")

    print("=" * 60)
    print("  HAKUZA — Web Dashboard")
    print(f"  http://{host}:{port}")
    if debug:
        print("  [!] Debug mode ON (HAKUZA_WEB_DEBUG set) — do NOT expose this")
        print("      process beyond localhost; the Werkzeug debugger is live.")
    print("=" * 60)

    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    main()
