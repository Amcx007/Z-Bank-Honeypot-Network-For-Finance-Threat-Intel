from flask import Flask, request, jsonify
import json
import uuid
from datetime import datetime

app = Flask(__name__)

def log_event(data):
    log_entry = json.dumps(data)
    with open("/logs/api.log", "a") as f:
        f.write(log_entry + "\n")
    print(f"[API HONEYPOT] Captured: {data['endpoint']} | {data['source_ip']}")

@app.route("/accounts", methods=["GET"])
def accounts():
    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "honeypot_service": "finance-api",
        "source_ip": request.remote_addr,
        "endpoint": "/accounts",
        "method": "GET",
        "headers": dict(request.headers),
        "protocol": "HTTP"
    }
    log_event(event)
    return jsonify({
        "accounts": [
            {"account_no": "ACC-4521-XXXX", "balance": 24350.00, "type": "savings"},
            {"account_no": "ACC-8873-XXXX", "balance": 8120.50, "type": "current"}
        ]
    })

@app.route("/transfer", methods=["POST"])
def transfer():
    data = request.get_json(silent=True) or {}
    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "honeypot_service": "finance-api",
        "source_ip": request.remote_addr,
        "endpoint": "/transfer",
        "method": "POST",
        "payload": data,
        "protocol": "HTTP"
    }
    log_event(event)
    return jsonify({
        "status": "success",
        "transaction_id": str(uuid.uuid4()),
        "message": "Transfer initiated successfully"
    })

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081, debug=False)