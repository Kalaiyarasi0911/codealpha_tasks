from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print("\n[+] Packet Captured:")
        print(f" Source IP : {ip_layer.src}")
        print(f" Destination IP : {ip_layer.dst}")
        print(f" Protocol : {ip_layer.proto}")

    if TCP in packet:
        print("    Type           : TCP")
        print(f"    Source Port    : {packet[TCP].sport}")
        print(f"    Destination Port: {packet[TCP].dport}")
    elif UDP in packet:
        print("    Type           : UDP")
        print(f"    Source Port    : {packet[UDP].sport}")
        print(f"    Destination Port: {packet[UDP].dport}")
    
    print(f"    Payload        : {bytes(packet.payload)[:100]}")  # Limit to first 100 bytes

print("Starting network sniffing... (Press Ctrl+C to stop)")
sniff(prn=process_packet, count=10)