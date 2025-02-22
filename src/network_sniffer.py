import threading
import time
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from scapy.all import sniff, get_if_list, wrpcap
from collections import defaultdict

# Global variables
traffic_data = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
last_update_time = time.time()
captured_packets = []
pcap_filename = "captured_packets.pcap"

# Function to list available network interfaces
def list_interfaces():
    """Lists all available network interfaces and validates user selection."""
    interfaces = get_if_list()
    print("\nAvailable Network Interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"[{i}] {iface}")

    # Validate user input
    while True:
        try:
            choice = int(input("\nEnter the interface number to sniff: "))
            if 0 <= choice < len(interfaces):
                return interfaces[choice]
            else:
                print("❌ Invalid choice! Please enter a number from the list.")
        except ValueError:
            print("❌ Invalid input! Please enter a valid number.")


# Packet callback function
def packet_callback(packet):
    """Processes packets for live stats & saves them to a PCAP file."""
    global last_update_time
    current_time = time.time()
    
    if packet.haslayer("IP"):
        proto = packet["IP"].proto
        pkt_size = len(packet)

        if proto == 6:  # TCP
            traffic_data["TCP"] += pkt_size
        elif proto == 17:  # UDP
            traffic_data["UDP"] += pkt_size
        elif proto == 1:  # ICMP
            traffic_data["ICMP"] += pkt_size
        else:
            traffic_data["Other"] += pkt_size

        # Store packet for PCAP file
        captured_packets.append(packet)

        # Reset every second
        if current_time - last_update_time >= 1:
            for key in traffic_data:
                traffic_data[key] = (traffic_data[key] * 8) / 1_000_000  # Convert bytes to Mbps
            last_update_time = current_time

# Function to update the graph dynamically
def update_graph(frame):
    plt.cla()
    protocols = list(traffic_data.keys())
    bandwidth = list(traffic_data.values())

    plt.bar(protocols, bandwidth, color=["blue", "green", "red", "gray"])
    plt.xlabel("Protocol")
    plt.ylabel("Bandwidth (Mbps)")
    plt.title("Live Network Traffic (Mbps)")
    plt.ylim(0, max(traffic_data.values(), default=1) * 1.2)
    plt.xticks(rotation=45)
    plt.tight_layout()

# Start sniffing packets
def start_sniffing(interface):
    """Starts capturing packets on the selected interface."""
    print(f"\nSniffing packets on {interface}... Press Ctrl+C to stop.")
    sniff(iface=interface, prn=packet_callback, store=False)

# Save captured packets to a PCAP file
def save_pcap():
    while True:
        time.sleep(10)  # Save every 10 seconds
        if captured_packets:
            wrpcap(pcap_filename, captured_packets)
            print(f"\n💾 Saved {len(captured_packets)} packets to {pcap_filename}")
            captured_packets.clear()

# Main Execution
if __name__ == "__main__":
    INTERFACE = list_interfaces()

    # Start Sniffing in a Thread
    sniff_thread = threading.Thread(target=start_sniffing, args=(INTERFACE,), daemon=True)
    sniff_thread.start()

    # Start PCAP Saving in a Thread
    save_thread = threading.Thread(target=save_pcap, daemon=True)
    save_thread.start()

    # Start Live Graph
    fig = plt.figure()
    ani = FuncAnimation(fig, update_graph, interval=1000)
    plt.show()
