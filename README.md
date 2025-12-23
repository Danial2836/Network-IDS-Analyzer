Project Overview
This project is a functional Signature-Based Intrusion Detection System developed to identify and log TCP SYN Flood attacks in a virtualized network environment. By analyzing raw network packets, the system provides real-time alerts and maintains a permanent forensic log of security incidents.

Key Features
Real-Time Packet Sniffing: Utilizes the Scapy library to monitor traffic on a specific network interface (enp0s3).

Signature Detection: Specifically identifies TCP SYN attacks by monitoring packet flags and identifying incomplete 3-way handshakes.

Automated Logging: Generates a timestamped ids_log.txt file for every detected threat, facilitating security auditing.

Robust Engine: Implements layer validation (haslayer(IP)) to ensure stability when processing diverse network traffic.

System Architecture
The project was implemented using a dual-VM lab environment to safely simulate attack and defense scenarios:

Attacker Node: Kali Linux (IP: 10.0.2.20) running a custom SYN flood script.

IDS Node: Ubuntu 24.04 (IP: 10.0.2.15) running the Python analyzer.

Network: VirtualBox Internal Network (intnet) with Promiscuous Mode enabled.

