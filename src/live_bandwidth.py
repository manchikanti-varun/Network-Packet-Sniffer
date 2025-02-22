import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from scapy.all import sniff
from collections import defaultdict
import time

# Track bytes received per protocol
traffic_data = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
last_update_time = time.time()

# Callback function to process packets
def packet_callback(packet):
    """Updates bandwidth usage for TCP, UDP, and ICMP."""
    global last_update_time
    current_time = time.time()
    
    if packet.haslayer("IP"):
        proto = packet["IP"].proto
        pkt_size = len(packet)  # Get packet size in bytes
        
        if proto == 6:  # TCP
            traffic_data["TCP"] += pkt_size
        elif proto == 17:  # UDP
            traffic_data["UDP"] += pkt_size
        elif proto == 1:  # ICMP
            traffic_data["ICMP"] += pkt_size
        else:
            traffic_data["Other"] += pkt_size

        # Reset every second
        if current_time - last_update_time >= 1:
            for key in traffic_data:
                traffic_data[key] = traffic_data[key] * 8 / 1_000_000  # Convert bytes to Mbps
            last_update_time = current_time

# Function to update the graph dynamically
def update_graph(frame):
    plt.cla()  # Clear previous frame
    protocols = list(traffic_data.keys())
    bandwidth = list(traffic_data.values())

    plt.bar(protocols, bandwidth, color=["blue", "green", "red", "gray"])
    plt.xlabel("Protocol")
    plt.ylabel("Bandwidth (Mbps)")
    plt.title("Live Network Traffic (Mbps)")
    plt.ylim(0, max(traffic_data.values(), default=1) * 1.2)  # Adjust max scale
    plt.xticks(rotation=45)
    plt.tight_layout()

# Start capturing packets
def start_sniffing(interface):
    """Starts sniffing on the given interface in a separate thread."""
    sniff(iface=interface, prn=packet_callback, store=False)

# Select your network interface
INTERFACE = "\\Device\\NPF_{37C70009-0AE6-4EE4-9555-70534BFAA788}"  # Change this!

# Start packet sniffing in the background
import threading
threading.Thread(target=start_sniffing, args=(INTERFACE,), daemon=True).start()

# Start the Matplotlib animation
fig = plt.figure()
ani = FuncAnimation(fig, update_graph, interval=1000)  # Update every second
plt.show()
