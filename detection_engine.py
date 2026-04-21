from scapy.all import sniff, IP, TCP, get_if_list
import time
from logger import write_log

incidents = []
traffic_data = {}

PACKET_THRESHOLD = 5

TRUSTED_IPS = ["192.168.", "127.0.0.1"]


def calculate_risk(data):
    packet_rate = data["count"]
    port_spread = len(data["ports"])
    syn_ratio = data["syn_count"] / data["tcp_count"] if data["tcp_count"] else 0

    score = min(10, round(
        (packet_rate * 0.3) +
        (port_spread * 0.3) +
        (syn_ratio * 10 * 0.4)
    , 2))

    return score


def classify(score):
    if score >= 8:
        return "Critical"
    elif score >= 6:
        return "High"
    elif score >= 4:
        return "Medium"
    else:
        return "Low"


def detect(packet):
    if not packet.haslayer(IP):
        return

    ip = packet[IP].src

    if ip.startswith(tuple(TRUSTED_IPS)):
        return

    now = time.time()

    if ip not in traffic_data:
        traffic_data[ip] = {
            "count": 0,
            "ports": set(),
            "syn_count": 0,
            "tcp_count": 0,
            "start_time": now
        }

    data = traffic_data[ip]
    data["count"] += 1

    if packet.haslayer(TCP):
        data["tcp_count"] += 1
        if packet[TCP].flags == "S":
            data["syn_count"] += 1
        data["ports"].add(packet[TCP].dport)

    if data["count"] >= PACKET_THRESHOLD:

        risk_score = calculate_risk(data)
        severity = classify(risk_score)

        incident = {
            "ip": ip,
            "attack_type": "Anomalous Traffic",
            "risk_score": risk_score,
            "severity": severity,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "blocked": False
        }

        write_log(f"DETECTED: {ip} | Score={risk_score} | Severity={severity}")

        found = False
        for i in incidents:
            if i["ip"] == ip:
                i.update(incident)
                found = True
                break

        if not found:
            incidents.append(incident)

        traffic_data[ip]["count"] = 0


def start_packet_capture():
    iface = "Wi-Fi"

    write_log(f"Packet capture started on {iface}")

    sniff(
        prn=detect,
        store=False,
        iface=iface
    )