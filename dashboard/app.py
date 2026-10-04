"""
PolicyGuard compliance dashboard.

    python demo/simulate_violation.py --save   # scan your AWS account into the dashboard DB
    python dashboard/app.py                     # http://127.0.0.1:5000
"""
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from flask import Flask, jsonify, render_template

from dashboard.routes.audit_log import audit_log_bp
from dashboard.routes.compliance_score import compliance_score_bp
from dashboard.routes.violations import violations_bp


def create_app() -> Flask:
    app = Flask(__name__)
    app.register_blueprint(violations_bp)
    app.register_blueprint(compliance_score_bp)
    app.register_blueprint(audit_log_bp)

    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/audit")
    def audit():
        return render_template("audit_trail.html")

    @app.route("/api/scan", methods=["POST"])
    def scan_now():
        from db.schema import connect
        from dashboard.scanner import scan_and_save
        conn = connect()
        try:
            return jsonify(scan_and_save(conn))
        finally:
            conn.close()

    return app


# Live mode: re-scan the AWS account every N seconds (POLICYGUARD_SCAN_INTERVAL=0 disables)
SCAN_INTERVAL = int(os.environ.get("POLICYGUARD_SCAN_INTERVAL", "20"))

if __name__ == "__main__":
    if SCAN_INTERVAL > 0:
        from dashboard.scanner import start_background_scanner
        start_background_scanner(SCAN_INTERVAL)
        print(f"[SCAN] Live scanning AWS every {SCAN_INTERVAL}s")
    create_app().run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
