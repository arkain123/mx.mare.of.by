import logging
from flask import Flask, request, jsonify, render_template

from checkers import spf, dmarc, dkim, mx, blacklist, smtp, full, mailbox

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)


def _json_safe(obj):
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    return obj


def _get_payload():
    data = request.get_json(silent=True) or {}
    domain = (data.get("domain") or "").strip().lower().rstrip(".")
    if not domain:
        return None, (jsonify({"error": "Domain is required"}), 400)
    if len(domain) > 253 or " " in domain or "/" in domain:
        return None, (jsonify({"error": "Invalid domain"}), 400)
    return data, None


def _safe(fn):
    try:
        return jsonify(_json_safe(fn()))
    except Exception as e:
        logging.exception("checker error")
        return jsonify({"error": str(e)}), 500

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/spf", methods=["POST"])
def api_spf():
    data, err = _get_payload()
    if err:
        return err
    return _safe(lambda: spf.check(data["domain"].strip().lower().rstrip(".")))


@app.route("/api/dmarc", methods=["POST"])
def api_dmarc():
    data, err = _get_payload()
    if err:
        return err
    return _safe(lambda: dmarc.check(data["domain"].strip().lower().rstrip(".")))


@app.route("/api/dkim", methods=["POST"])
def api_dkim():
    data, err = _get_payload()
    if err:
        return err
    selector = (data.get("selector") or "").strip()
    return _safe(lambda: dkim.check(data["domain"].strip().lower().rstrip("."), selector))


@app.route("/api/mx", methods=["POST"])
def api_mx():
    data, err = _get_payload()
    if err:
        return err
    return _safe(lambda: mx.check(data["domain"].strip().lower().rstrip(".")))


@app.route("/api/blacklist", methods=["POST"])
def api_blacklist():
    data, err = _get_payload()
    if err:
        return err
    return _safe(lambda: blacklist.check(data["domain"].strip().lower().rstrip(".")))


@app.route("/api/smtp", methods=["POST"])
def api_smtp():
    data, err = _get_payload()
    if err:
        return err
    return _safe(lambda: smtp.check(data["domain"].strip().lower().rstrip(".")))


@app.route("/api/full", methods=["POST"])
def api_full():
    data = request.get_json(silent=True) or {}
    raw = (data.get("domain") or data.get("email") or "").strip()
    if not raw:
        return jsonify({"error": "Input is required"}), 400
    if len(raw) > 320:
        return jsonify({"error": "Input too long"}), 400
    return _safe(lambda: full.check(raw))


@app.route("/api/mailbox", methods=["POST"])
def api_mailbox():
    data = request.get_json(silent=True) or {}
    raw = (data.get("email") or data.get("domain") or "").strip()
    if not raw:
        return jsonify({"error": "Email is required"}), 400
    if len(raw) > 320:
        return jsonify({"error": "Input too long"}), 400
    server = (data.get("server") or "").strip() or None
    if server and len(server) > 253:
        return jsonify({"error": "Server hostname too long"}), 400
    return _safe(lambda: mailbox.check(raw, server=server))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
