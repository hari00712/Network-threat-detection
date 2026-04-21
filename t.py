from scapy.all import IP, TCP, send
import random
import time

target_ip = "192.168.1.1"   # router (correct)

print("🚀 Simulating attack...")

while True:
    port = random.randint(1, 1000)

    # ✅ NO fake src IP
    packet = IP(dst=target_ip)/TCP(dport=port, flags="S")

    send(packet, verbose=0)

    print(f"⚡ SYN → Port {port}")

    time.sleep(0.05)