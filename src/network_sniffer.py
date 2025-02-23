import threading
import time
import requests
import logging
import pytz
import matplotlib.pyplot as plt
from datetime import datetime
from matplotlib.animation import FuncAnimation
from scapy.all import sniff, get_if_list, wrpcap, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw

# Setup Logging
logging.basicConfig(
    filename="logs/packet_sniffer.log",
    level=logging.INFO,
    format="%(message)s"
)

def get_ist_time():
    """Returns the current timestamp in IST (Indian Standard Time)."""
    return datetime.now(pytz.timezone("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S IST")

# Global variables
traffic_data = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
last_update_time = time.time()
captured_packets = []
pcap_filename = "src/captured_packets.pcap"

def list_interfaces():
    interfaces = get_if_list()
    print("\nAvailable Network Interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"[{i}] {iface}")
    while True:
        try:
            choice = int(input("\nEnter the interface number to sniff: "))
            if 0 <= choice < len(interfaces):
                return interfaces[choice]
            else:
                print("❌ Invalid choice! Please enter a number from the list.")
        except ValueError:
            print("❌ Invalid input! Please enter a valid number.")

def get_ip_geolocation(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}").json()
        if response["status"] == "success":
            return f"{response['city']}, {response['country']} ({response['isp']})"
    except Exception:
        return "Unknown"
    return "Unknown"

def analyze_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        ist_time = get_ist_time()
        
        if not src_ip.startswith("192.") and not src_ip.startswith("10."):
            location = get_ip_geolocation(src_ip)
            log_entry = f"[{ist_time}] 🌍 Geolocation: {src_ip} -> {location}"
            print(log_entry)
            logging.info(log_entry)
        
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors="ignore")
            if "HTTP" in payload:
                log_entry = f"[{ist_time}] 📡 HTTP Request: {payload[:100]}..."
                print(log_entry)
                logging.info(log_entry)
        
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns_query = packet[DNSQR].qname.decode()
            log_entry = f"[{ist_time}] 🔍 DNS Query: {dns_query}"
            print(log_entry)
            logging.info(log_entry)

def packet_callback(packet):
    global last_update_time
    current_time = time.time()
    ist_time = get_ist_time()
    
    if packet.haslayer(IP):
        proto = packet[IP].proto
        pkt_size = len(packet)

        if proto == 6:
            traffic_data["TCP"] += pkt_size
        elif proto == 17:
            traffic_data["UDP"] += pkt_size
        elif proto == 1:
            traffic_data["ICMP"] += pkt_size
        else:
            traffic_data["Other"] += pkt_size

        captured_packets.append(packet)
        analyze_packet(packet)

        if current_time - last_update_time >= 1:
            log_entry = (f"\n[{ist_time}] 📊 Live Traffic Statistics (Updated Every 1s)\n"
                         "--------------------------------------------\n"
                         "Protocol    | Bandwidth (Mbps)\n"
                         "------------------------------\n")
            for key in traffic_data:
                traffic_data[key] = (traffic_data[key] * 8) / 1_000_000
                log_entry += f"{key:<12} | {traffic_data[key]:.2f} Mbps\n"
            print(log_entry)
            logging.info(log_entry)
            last_update_time = current_time

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

def start_sniffing(interface):
    print(f"\nSniffing packets on {interface}... Press Ctrl+C to stop.")
    sniff(iface=interface, prn=packet_callback, store=False)

def save_pcap():
    while True:
        time.sleep(10)
        ist_time = get_ist_time()
        if captured_packets:
            wrpcap(pcap_filename, captured_packets)
            log_entry = f"\n[{ist_time}] 💾 Saved {len(captured_packets)} packets to {pcap_filename}"
            print(log_entry)
            logging.info(log_entry)
            captured_packets.clear()

if __name__ == "__main__":
    print("============================================")
    print("🌐 Network Packet Sniffer - Live Capture")
    print("============================================")
    INTERFACE = list_interfaces()
    print(f"\n🔍 Selected Interface: {INTERFACE}")
    print("📡 Sniffing packets... Press Ctrl+C to stop.")
    
    sniff_thread = threading.Thread(target=start_sniffing, args=(INTERFACE,), daemon=True)
    sniff_thread.start()

    save_thread = threading.Thread(target=save_pcap, daemon=True)
    save_thread.start()

    fig = plt.figure()
    ani = FuncAnimation(fig, update_graph, interval=1000)
    plt.show()
