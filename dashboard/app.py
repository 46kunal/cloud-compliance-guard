"""
PolicyGuard compliance dashboard.

    python demo/simulate_violation.py --save   # scan your AWS account into the dashboard DB
    python dashboard/app.py                     # http://127.0.0.1:5000

Environment (all optional):
    POLICYGUARD_BACKEND=sqlite|dynamodb   storage backend            (default sqlite)
    POLICYGUARD_PROFILE=baseline|india    which rules are enabled    (default baseline)
    POLICYGUARD_AUTH=off|local|cognito    login mode                 (default off)
    POLICYGUARD_SCANNER_FUNCTION=<name>   invoke this Lambda for "Scan now" instead of scanning in-process
"""
import json
import os
import sys

# The EC2 servers set AWS_REGION, but boto3 only reads AWS_DEFAULT_REGION. Without this, any AWS call that needs a
# region (KMS, Lambda, Cognito...) fails with "You must specify a region". Done before any other import reads it.
if not os.environ.get("AWS_DEFAULT_REGION") and os.environ.get("AWS_REGION"):
    os.environ["AWS_DEFAULT_REGION"] = os.environ["AWS_REGION"]

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from flask import Flask, jsonify, render_template

from dashboard.account import NoAccountConnected
from dashboard.auth import auth_mode, csrf_token, current_user, init_auth
from dashboard.instance import instance_info
from dashboard.routes.account import account_api
from dashboard.routes.audit_log import audit_log_bp
from dashboard.routes.compliance_score import compliance_score_bp
from dashboard.routes.insight import insight_bp
from dashboard.routes.monitored import monitored_bp
from dashboard.routes.process import process_bp
from dashboard.routes.users import users_bp
from dashboard.routes.violations import violations_bp


def _run_scan():
    function = os.environ.get("POLICYGUARD_SCANNER_FUNCTION")
    if function:
        import boto3
        response = boto3.client("lambda").invoke(FunctionName=function, InvocationType="RequestResponse", Payload=b"{}")
        payload = json.loads(response["Payload"].read() or b"{}")
        if response.get("FunctionError"):
            raise RuntimeError(payload.get("errorMessage", "scanner function failed"))
        return payload
    from db.store import connect
    from dashboard.scanner import scan_and_save
    conn = connect()
    try:
        return scan_and_save(conn)
    finally:
        conn.close()


def create_app() -> Flask:
    app = Flask(__name__)
    init_auth(app)
    app.register_blueprint(violations_bp)
    app.register_blueprint(compliance_score_bp)
    app.register_blueprint(audit_log_bp)
    app.register_blueprint(insight_bp)
    app.register_blueprint(monitored_bp)
    app.register_blueprint(process_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(account_api)

    @app.context_processor
    def shell_context():
        info = instance_info()
        return {"user": current_user(), "instance": info,
                "csrf_value": lambda: csrf_token() if auth_mode() != "off" else "",
                "profile": os.environ.get("POLICYGUARD_PROFILE", "baseline")}

    @app.route("/health")
    def health():
        return jsonify({"status": "ok"})

    def page(name, template, title):
        def view():
            return render_template(template, title=title, page=name)
        view.__name__ = name
        app.route("/" if name == "index" else f"/{name}")(view)

    page("index", "overview.html", "Overview")
    page("frameworks", "frameworks.html", "Frameworks")
    page("findings", "findings.html", "Findings")
    page("scans", "scans.html", "Scan history")
    page("infrastructure", "infrastructure.html", "Infrastructure")
    page("account", "account.html", "AWS account")
    page("reports", "reports.html", "Reports")
    page("accounts", "accounts.html", "Accounts")
    page("controls", "controls.html", "Controls")
    page("incidents", "incidents.html", "Incidents")
    page("users", "users.html", "Users")
    page("audit", "audit_trail.html", "Audit trail")

    @app.route("/api/scan", methods=["POST"])
    def scan_now():
        try:
            return jsonify(_run_scan())
        except NoAccountConnected as error:
            return jsonify({"error": "No AWS account connected", "detail": str(error)}), 409
        except Exception as error:
            app.logger.exception("scan failed")
            return jsonify({"error": "Scan failed", "detail": str(error)}), 500

    return app


# Live mode: re-scan the AWS account every N seconds (POLICYGUARD_SCAN_INTERVAL=0 disables).
# On AWS the scheduled Lambda does this, so the dashboard servers do not scan on their own.
_default_interval = "0" if os.environ.get("POLICYGUARD_BACKEND") == "dynamodb" else "20"
SCAN_INTERVAL = int(os.environ.get("POLICYGUARD_SCAN_INTERVAL", _default_interval))

if __name__ == "__main__":
    if SCAN_INTERVAL > 0:
        from dashboard.scanner import start_background_scanner
        start_background_scanner(SCAN_INTERVAL)
        print(f"[SCAN] Live scanning AWS every {SCAN_INTERVAL}s")
    create_app().run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)), debug=False)
