from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP

PACKET_LOG_FILE = "captured_packets.pcap"

def packet_callback(packet):
    """Processes each captured packet, prints its summary, and saves it to a file."""
    if IP in packet:
        protocol = "Other"
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        
        print(f"[{protocol}] {packet[IP].src} → {packet[IP].dst}")
        wrpcap(PACKET_LOG_FILE, packet, append=True)  # Append packet to PCAP file

def start_sniffing(interface, protocol_filter="ip", packet_count=10):
    """
    Captures packets on a specified network interface with filtering and logging.
    
    :param interface: Network interface to sniff on.
    :param protocol_filter: BPF filter for packet type ('tcp', 'udp', 'icmp', 'ip').
    :param packet_count: Number of packets to capture.
    """
    print(f"Sniffing {protocol_filter.upper()} packets on {interface}... Press Ctrl+C to stop.")
    print(f"Packets will be saved to {PACKET_LOG_FILE}")
    
    sniff(iface=interface, filter=protocol_filter, prn=packet_callback, count=packet_count)

if __name__ == "__main__":
    INTERFACE = "\\Device\\NPF_{37C70009-0AE6-4EE4-9555-70534BFAA788}"  # Replace with your interface ID
    PACKET_COUNT = 10  # Number of packets to capture
    PROTOCOL_FILTER = "tcp"  # Change to 'udp', 'icmp', or 'ip' for all packets
    
    start_sniffing(INTERFACE, PROTOCOL_FILTER, PACKET_COUNT)
