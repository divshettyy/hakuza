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

    # threaded=False is load-bearing, not a default: hakuza.get_db() is a
    # process-wide singleton connection (by design, for the CLI's single-
    # threaded usage), and Python's sqlite3 module forbids using a connection
    # from any thread other than the one that created it. Werkzeug's dev
    # server can dispatch requests on different threads even with debug off,
    # which crashes every request that lands on a thread other than the one
    # that happened to create the cached connection (500:
    # "SQLite objects created in a thread can only be used in that same
    # thread" — reproduced live by hitting two different routes back to
    # back). Forcing single-threaded serving guarantees the singleton is only
    # ever touched by the one thread that created it.
    app.run(host=host, port=port, debug=debug, threaded=False)


if __name__ == "__main__":
    main()
