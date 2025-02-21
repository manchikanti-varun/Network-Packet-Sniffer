from scapy.all import sniff

def packet_callback(packet):
    """Callback function to process each captured packet."""
    print(packet.summary())  # Prints a short summary of each packet

def start_sniffing(interface, packet_count=10):
    """
    Captures packets on the specified network interface.
    
    :param interface: Network interface to sniff on.
    :param packet_count: Number of packets to capture (default: 10).
    """
    print(f"Sniffing packets on {interface}... Press Ctrl+C to stop.")
    sniff(iface=interface, prn=packet_callback, count=packet_count)

if __name__ == "__main__":
    INTERFACE = "\\Device\\NPF_{37C70009-0AE6-4EE4-9555-70534BFAA788}"  # Your actual interface ID
    PACKET_COUNT = 10  # Change this to capture more or fewer packets
    start_sniffing(INTERFACE, PACKET_COUNT)
