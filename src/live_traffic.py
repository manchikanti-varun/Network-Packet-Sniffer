import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from scapy.all import sniff
from collections import defaultdict

# Dictionary to store packet counts
protocol_counts = defaultdict(int)

# Callback function to process packets
def packet_callback(packet):
    """Updates protocol count for live graph."""
    if packet.haslayer("IP"):
        proto = packet["IP"].proto
        protocol_counts[proto] += 1

# Function to update the graph dynamically
def update_graph(frame):
    plt.cla()  # Clear previous frame
    protocols = list(protocol_counts.keys())
    counts = list(protocol_counts.values())

    plt.bar(protocols, counts, color="skyblue")
    plt.xlabel("Protocol Number")
    plt.ylabel("Packet Count")
    plt.title("Live Network Traffic")
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
