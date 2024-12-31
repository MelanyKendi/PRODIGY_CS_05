from scapy.all import sniff

def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        protocol = packet["IP"].proto
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}")

# Start capturing packets
print("Starting packet capture...")
sniff(prn=packet_callback, store=False)
