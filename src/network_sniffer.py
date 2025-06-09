import threading
import time
import json
import requests
import logging
import pytz
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, get_if_list, wrpcap, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
import configparser
import os
from matplotlib.animation import FuncAnimation

# Load configuration
config = configparser.ConfigParser()
config.read('sniffer_config.ini')

# Setup logging
try:
    os.makedirs('logs', exist_ok=True)
    logging.basicConfig(
        filename=config.get('Settings', 'log_file', fallback='logs/packet_sniffer.log'),
        level=logging.INFO,
        format="%(message)s"
    )
except Exception as e:
    print(f"❌ Error setting up logging: {e}")
    exit(1)

# Configuration settings
PCAP_FILE = config.get('Settings', 'pcap_file', fallback='src/captured_packets.pcap')
UPDATE_INTERVAL = config.getfloat('Settings', 'update_interval', fallback=1.0)
SAVE_INTERVAL = config.getint('Settings', 'save_interval', fallback=10)
PLOT_STYLE = config.get('Settings', 'plot_style', fallback='default')
MAX_PACKETS = config.getint('Settings', 'max_packets', fallback=10000)

# Global variables
traffic_data = defaultdict(float)
packet_sizes = []
captured_packets = []
stats_history = []
last_update_time = time.time()

def get_ist_time():
    """Returns the current timestamp in IST."""
    return datetime.now(pytz.timezone("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S IST")

def load_config():
    """Create default config if not exists."""
    if not os.path.exists('sniffer_config.ini'):
        try:
            config['Settings'] = {
                'log_file': 'logs/packet_sniffer.log',
                'pcap_file': 'src/captured_packets.pcap',
                'update_interval': '1.0',
                'save_interval': '10',
                'plot_style': 'default',
                'max_packets': '10000'
            }
            with open('sniffer_config.ini', 'w') as configfile:
                config.write(configfile)
            logging.info(f"[{get_ist_time()}] Created default sniffer_config.ini")
        except Exception as e:
            logging.error(f"[{get_ist_time()}] Failed to create config file: {e}")
            print(f"❌ Failed to create config file: {e}")
            exit(1)

def validate_plot_style(style):
    """Validate and return a valid matplotlib style, default to 'default' if invalid."""
    try:
        available_styles = plt.style.available
        if style in available_styles:
            return style
        logging.warning(f"[{get_ist_time()}] Invalid plot style '{style}'. Falling back to 'default'.")
        print(f"⚠️ Invalid plot style '{style}'. Falling back to 'default'.")
        return 'default'
    except Exception as e:
        logging.error(f"[{get_ist_time()}] Error validating plot style: {e}")
        return 'default'

def list_interfaces():
    """List available network interfaces and get user selection."""
    try:
        interfaces = get_if_list()
        if not interfaces:
            print("❌ No network interfaces found. Ensure you have Npcap installed and run as administrator.")
            logging.error(f"[{get_ist_time()}] No network interfaces found.")
            exit(1)
        print("\nAvailable Network Interfaces:")
        for i, iface in enumerate(interfaces):
            print(f"[{i}] {iface}")
        while True:
            try:
                choice = int(input("\nEnter the interface number to sniff: "))
                if 0 <= choice < len(interfaces):
                    return interfaces[choice]
                print("❌ Invalid choice! Please enter a number from the list.")
            except ValueError:
                print("❌ Invalid input! Please enter a valid number.")
    except Exception as e:
        logging.error(f"[{get_ist_time()}] Error listing interfaces: {e}")
        print(f"❌ Error listing interfaces: {e}")
        exit(1)

def get_ip_geolocation(ip):
    """Fetch geolocation data for an IP address."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if response.get("status") == "success":
            return f"{response['city']}, {response['country']} ({response['isp']})"
    except Exception:
        return "Unknown"
    return "Unknown"

def analyze_packet(packet):
    """Analyze packet details and log relevant information."""
    if not packet.haslayer(IP):
        return None
    
    try:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        pkt_size = len(packet)
        ist_time = get_ist_time()

        # Geolocation for non-private IPs
        if not src_ip.startswith(("192.", "10.", "172.")):
            location = get_ip_geolocation(src_ip)
            log_entry = f"[{ist_time}] 🌍 Geolocation: {src_ip} -> {location}"
            print(log_entry)
            logging.info(log_entry)

        # Protocol-specific analysis
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode(errors="ignore")
                if "HTTP" in payload:
                    log_entry = f"[{ist_time}] 📡 HTTP Request: {payload[:100]}..."
                    print(log_entry)
                    logging.info(log_entry)
            except:
                pass

        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns_query = packet[DNSQR].qname.decode(errors="ignore")
            log_entry = f"[{ist_time}] 🔍 DNS Query: {dns_query}"
            print(log_entry)
            logging.info(log_entry)

        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            log_entry = f"[{ist_time}] 🚩 TCP Flags: {flags}"
            print(log_entry)
            logging.info(log_entry)

        return protocol, pkt_size
    except Exception as e:
        logging.error(f"[{get_ist_time()}] Error analyzing packet: {e}")
        return None

def packet_callback(packet):
    """Process each captured packet."""
    global last_update_time
    try:
        current_time = time.time()
        ist_time = get_ist_time()

        if len(captured_packets) >= MAX_PACKETS:
            captured_packets.pop(0)

        result = analyze_packet(packet)
        if result:
            proto, pkt_size = result
            proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"Other_{proto}")
            traffic_data[proto_name] += pkt_size
            packet_sizes.append(pkt_size)
            captured_packets.append(packet)

            if current_time - last_update_time >= UPDATE_INTERVAL:
                log_entry = (f"\n[{ist_time}] 📊 Live Traffic Statistics (Updated Every {UPDATE_INTERVAL}s)\n"
                             "--------------------------------------------\n"
                             "Protocol    | Bandwidth (Mbps) | Packet Count\n"
                             "--------------------------------------------\n")
                for key in traffic_data:
                    bandwidth = (traffic_data[key] * 8) / 1_000_000
                    proto_value = int(key.split('_')[-1]) if key.startswith('Other') else {'TCP': 6, 'UDP': 17, 'ICMP': 1}.get(key, 0)
                    packet_count = len([p for p in captured_packets if p.haslayer(IP) and p[IP].proto == proto_value])
                    log_entry += f"{key:<12} | {bandwidth:.2f} Mbps | {packet_count:>5}\n"
                print(log_entry)
                logging.info(log_entry)
                stats_history.append({key: (traffic_data[key] * 8) / 1_000_000 for key in traffic_data})
                last_update_time = current_time
    except Exception as e:
        logging.error(f"[{get_ist_time()}] Error in packet callback: {e}")

def update_graph(frame):
    """Update the live traffic and packet size distribution plots with a table."""
    try:
        plt.clf()
        plt.style.use(validate_plot_style(PLOT_STYLE))

        # Create a grid layout: 2 rows, 2 columns (left for plots, right for table)
        fig = plt.gcf()
        fig.set_size_inches(12, 8)

        # Subplot 1: Bandwidth by Protocol (top left)
        ax1 = plt.subplot2grid((2, 2), (0, 0))
        protocols = list(traffic_data.keys())
        bandwidth = [(traffic_data[key] * 8) / 1_000_000 for key in protocols]
        sns.barplot(x=protocols, y=bandwidth, palette="viridis", ax=ax1)
        ax1.set_xlabel("Protocol")
        ax1.set_ylabel("Bandwidth (Mbps)")
        ax1.set_title("Live Network Traffic (Mbps)")
        ax1.tick_params(axis='x', rotation=45)
        ax1.set_ylim(0, max(bandwidth, default=1) * 1.2)

        # Subplot 2: Packet Size Distribution (bottom left)
        ax2 = plt.subplot2grid((2, 2), (1, 0))
        if packet_sizes:
            sns.histplot(packet_sizes[-1000:], bins=30, kde=True, color="purple", ax=ax2)
            ax2.set_xlabel("Packet Size (Bytes)")
            ax2.set_ylabel("Count")
            ax2.set_title("Packet Size Distribution (Last 1000 Packets)")

        # Table: Packet Statistics (right side, spanning both rows)
        ax3 = plt.subplot2grid((2, 2), (0, 1), rowspan=2)
        ax3.axis('off')  # Hide axes for table
        table_data = [
            ["Protocol", "Bandwidth (Mbps)", "Packet Count"]
        ]
        for key in traffic_data:
            bandwidth = (traffic_data[key] * 8) / 1_000_000
            proto_value = int(key.split('_')[-1]) if key.startswith('Other') else {'TCP': 6, 'UDP': 17, 'ICMP': 1}.get(key, 0)
            packet_count = len([p for p in captured_packets if p.haslayer(IP) and p[IP].proto == proto_value])
            table_data.append([key, f"{bandwidth:.2f}", f"{packet_count}"])
        
        table = ax3.table(
            cellText=table_data,
            cellLoc='center',
            loc='center',
            colWidths=[0.4, 0.3, 0.3]
        )
        table.auto_set_font_size(False)
        table.set_fontsize(10)
        table.scale(1, 1.5)  # Adjust table size
        ax3.set_title("Packet Statistics")

        plt.tight_layout()
    except Exception as e:
        logging.error(f"[{get_ist_time()}] Error updating graph: {e}")

def save_pcap():
    """Periodically save captured packets to PCAP file."""
    while True:
        try:
            time.sleep(SAVE_INTERVAL)
            ist_time = get_ist_time()
            if captured_packets:
                wrpcap(PCAP_FILE, captured_packets)
                log_entry = f"\n[{ist_time}] 💾 Saved {len(captured_packets)} packets to {PCAP_FILE}"
                print(log_entry)
                logging.info(log_entry)
        except Exception as e:
            logging.error(f"[{get_ist_time()}] Error saving PCAP: {e}")

def generate_report():
    """Generate a JSON report of traffic statistics."""
    try:
        report = {
            "timestamp": get_ist_time(),
            "total_packets": len(captured_packets),
            "traffic_summary": {key: (traffic_data[key] * 8) / 1_000_000 for key in traffic_data},
            "packet_size_stats": {
                "mean": float(np.mean(packet_sizes)) if packet_sizes else 0,
                "max": float(max(packet_sizes, default=0)),
                "min": float(min(packet_sizes, default=0)),
                "std": float(np.std(packet_sizes)) if packet_sizes else 0
            },
            "history": stats_history[-10:]
        }
        with open('traffic_report.json', 'w') as f:
            json.dump(report, f, indent=4)
        log_entry = f"[{get_ist_time()}] 📄 Generated traffic report: traffic_report.json"
        print(log_entry)
        logging.info(log_entry)
    except Exception as e:
        logging.error(f"[{get_ist_time()}] Error generating report: {e}")

def start_sniffing(interface):
    """Start sniffing packets on the specified interface."""
    try:
        print(f"\nSniffing packets on {interface}... Press Ctrl+C to stop.")
        sniff(iface=interface, prn=packet_callback, store=False)
    except Exception as e:
        logging.error(f"[{get_ist_time()}] Error sniffing packets: {e}")
        print(f"❌ Error sniffing packets: {e}")
        exit(1)

if __name__ == "__main__":
    try:
        load_config()
        os.makedirs('src', exist_ok=True)
        print("============================================")
        print("🌐 Advanced Network Packet Sniffer")
        print("============================================")
        INTERFACE = list_interfaces()
        print(f"\n🔍 Selected Interface: {INTERFACE}")
        print("📡 Sniffing packets... Press Ctrl+C to stop.")

        sniff_thread = threading.Thread(target=start_sniffing, args=(INTERFACE,), daemon=True)
        sniff_thread.start()

        save_thread = threading.Thread(target=save_pcap, daemon=True)
        save_thread.start()

        report_thread = threading.Thread(target=lambda: [time.sleep(30), generate_report()], daemon=True)
        report_thread.start()

        plt.style.use(validate_plot_style(PLOT_STYLE))
        fig = plt.figure(figsize=(12, 8))
        ani = FuncAnimation(fig, update_graph, interval=UPDATE_INTERVAL * 1000)
        plt.show()
    except KeyboardInterrupt:
        print("\n🛑 Sniffing stopped by user.")
        logging.info(f"[{get_ist_time()}] Sniffing stopped by user.")
    except Exception as e:
        logging.error(f"[{get_ist_time()}] Fatal error: {e}")
        print(f"❌ Fatal error: {e}")
        exit(1)