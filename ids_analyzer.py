from scapy.all import sniff, IP, TCP
from datetime import datetime

def detect_attack(packet):
    if packet.haslayer(IP):
        if packet.haslayer(TCP) and packet[TCP].flags == 'S':
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            alert_msg = f"[{timestamp}] ALERT: SYN Attack from {src_ip} on port {dst_port}"
            print(alert_msg)
            
            # Save the alert to a permanent log file
            with open("ids_log.txt", "a") as f:
                f.write(alert_msg + "\n")
        else:
            print(f"Monitoring traffic from: {packet[IP].src}")

print("--- IDS Analyzer Final Version: Logging Enabled ---")
sniff(iface="enp0s3", prn=detect_attack, store=0)
