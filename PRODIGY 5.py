from scapy.all import sniff

def packet_callback(packet):
    # Print source and destination IP addresses
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")

    # Print source and destination ports if the packet is TCP or UDP
    if packet.haslayer('TCP'):
        src_port = packet['TCP'].sport
        dst_port = packet['TCP'].dport
        print(f"Source Port: {src_port}, Destination Port: {dst_port}, Protocol: TCP")
    elif packet.haslayer('UDP'):
        src_port = packet['UDP'].sport
        dst_port = packet['UDP'].dport
        print(f"Source Port: {src_port}, Destination Port: {dst_port}, Protocol: UDP")

    # Print the payload data
    payload = packet.payload
    if payload:
        print("Payload data:")
        print(payload)

# Sniff packets and call packet_callback for each packet captured
print("Sniffing started...")
sniff(prn=packet_callback, store=0)
