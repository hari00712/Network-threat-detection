from flask import Flask, render_template, jsonify, request
import threading
import time

from detection_engine import incidents, start_packet_capture
import mitigation
import logger

app = Flask(__name__)


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/incidents")
def get_incidents():
    return jsonify(incidents)


@app.route("/simulate")
def simulate():
    import random

    ip = f"192.168.1.{random.randint(2,254)}"

    incidents.append({
        "ip": ip,
        "attack_type": "Simulated Attack",
        "risk_score": 9,
        "severity": "Critical",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "blocked": False
    })

    logger.write_log(f"SIMULATION: {ip}")

    return jsonify({"status": "simulated", "ip": ip})


@app.route("/api/block", methods=["POST"])
def block():
    ip = request.json["ip"]

    mitigation.block_ip(ip)

    for i in incidents:
        if i["ip"] == ip:
            i["blocked"] = True

    logger.write_log(f"MANUAL BLOCK: {ip}")

    return jsonify({"status": "blocked", "ip": ip})


@app.route("/api/unblock", methods=["POST"])
def unblock():
    ip = request.json["ip"]

    mitigation.unblock_ip(ip)

    for i in incidents:
        if i["ip"] == ip:
            i["blocked"] = False

    logger.write_log(f"MANUAL UNBLOCK: {ip}")

    return jsonify({"status": "unblocked", "ip": ip})


def auto_block_monitor():
    while True:
        try:
            for incident in incidents:

                if (
                    incident["severity"] == "Critical"
                    and incident["risk_score"] >= 9
                    and not incident["blocked"]
                ):
                    mitigation.block_ip(incident["ip"])
                    incident["blocked"] = True

                    logger.write_log(f"AUTO BLOCK: {incident['ip']}")

        except Exception as e:
            logger.write_log(f"AUTO BLOCK ERROR: {e}")

        time.sleep(5)


if __name__ == "__main__":

    threading.Thread(target=start_packet_capture, daemon=True).start()
    threading.Thread(target=auto_block_monitor, daemon=True).start()

    logger.write_log("SYSTEM STARTED")

    app.run(debug=False, use_reloader=False)