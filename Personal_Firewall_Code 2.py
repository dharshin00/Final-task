from scapy.all import sniff, IP
import logging

logging.basicConfig(filename='firewall_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

block_list = ['192.168.1.100', '10.0.0.10']

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        if ip_src in block_list:
            logging.info(f"Blocked packet from {ip_src}")
        else:
            print(f"Allowed packet from {ip_src}")

print("Personal Firewall is running...")
sniff(prn=packet_callback, store=0)