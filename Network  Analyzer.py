#Network Packet Analyzer
import scapy.all as scapy
def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        print(f"Source IP: {ip_src}, Destination: {ip_dst}, Protocol: {protocol}")
        if packet.haslayer(scapy.TCP):
            try:
                playload=packet[scapy.Raw].load
                decoded_payload=playload.decode('utf-8','ignore')
                print(f"TCP Payload :{decoded_payload[:50]}")
            except (IndexError,UnicodeDecodeError):
                print("Unable to decode TCP payload.")
        elif packet.haslayer(scapy.UDP):
            try:
                playload=packet[scapy.Raw].load
                decoded_payload=playload.decode('utf-8','ignore')
                print(f"UDP Payload :{decoded_payload[:50]}")
            except (IndexError,UnicodeDecodeError):
                print("Unable to decode UDP payload.")
def start_sniffing():
    scapy.sniff(store=False,prn=packet_callback) 
start_sniffing()  
