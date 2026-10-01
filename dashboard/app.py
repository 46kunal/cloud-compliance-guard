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

from flask import Flask, render_template

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

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
