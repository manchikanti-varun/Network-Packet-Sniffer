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
from collections import defaultdict, Counter
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
traffic_data = defaultdict(float)  # Total bytes per protocol
packet_sizes_by_proto = defaultdict(list)  # Packet sizes per protocol
source_ips = defaultdict(Counter)  # Source IPs per protocol
packet_types = defaultdict(Counter)  # Packet types per protocol
domains_by_proto = defaultdict(Counter)  # Domains per protocol
data_transferred = defaultdict(Counter)  # Data transferred (URLs, payloads, etc.) per protocol
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

def extract_tls_sni(packet):
    """Extract Server Name Indication (SNI) from TLS Client Hello."""
    try:
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            # Check for TLS Client Hello (handshake type 0x01)
            if payload[0:1] == b'\x16' and payload[5:6] == b'\x01':
                # Skip to extensions (complex parsing simplified)
                offset = 43  # Skip fixed-length headers (handshake, session ID, etc.)
                if len(payload) > offset:
                    ext_len = int.from_bytes(payload[offset:offset+2], 'big')
                    offset += 2
                    while offset < len(payload) - 2:
                        ext_type = int.from_bytes(payload[offset:offset+2], 'big')
                        ext_len = int.from_bytes(payload[offset+2:offset+4], 'big')
                        if ext_type == 0:  # SNI extension
                            sni_offset = offset + 9  # Skip extension headers
                            sni = payload[sni_offset:sni_offset+ext_len-5].decode(errors='ignore')
                            return sni
                        offset += 4 + ext_len
    except:
        pass
    return None

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
        pkt_type = "Other"
        domain = None
        transferred_data = None

        # Determine packet type and extract domain/data
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            pkt_type = "DNS Query"
            try:
                domain = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                transferred_data = f"DNS Query: {domain}"
            except:
                domain = "Unknown"
                transferred_data = "DNS Query"
        elif packet.haslayer(TCP):
            # Check for HTTPS (TLS) via port or SNI
            if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                sni = extract_tls_sni(packet)
                if sni:
                    domain = sni
                    transferred_data = f"HTTPS TLS: {sni}"
                    pkt_type = "TLS"
            # Check for HTTP
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    if "HTTP" in payload:
                        pkt_type = "HTTP"
                        # Extract HTTP details
                        headers = {}
                        url = None
                        content_type = None
                        for line in payload.split('\n'):
                            if line.startswith(('GET ', 'POST ')):
                                parts = line.split()
                                if len(parts) > 1:
                                    url_path = parts[1]
                                    for h in payload.split('\n'):
                                        if h.lower().startswith('host:'):
                                            host = h.split(':', 1)[1].strip()
                                            url = f"http://{host}{url_path}"
                                            domain = host
                                            break
                            elif ': ' in line:
                                key, value = line.split(': ', 1)
                                headers[key.lower()] = value.strip()
                                if key.lower() == 'content-type':
                                    content_type = value.strip()
                        # Summarize transferred data
                        if url:
                            transferred_data = f"URL: {url}"
                            if content_type:
                                transferred_data += f", Type: {content_type}"
                        elif content_type:
                            transferred_data = f"Content-Type: {content_type}"
                        elif payload.strip():
                            # Truncate payload for display
                            snippet = ''.join(c for c in payload[:50] if c.isprintable())
                            transferred_data = f"Payload: {snippet}..."
                except:
                    pass
            elif pkt_type != "TLS":
                pkt_type = f"TCP Flags: {packet[TCP].flags}"
                if packet.haslayer(Raw):
                    try:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        if payload.strip():
                            snippet = ''.join(c for c in payload[:50] if c.isprintable())
                            transferred_data = f"Payload: {snippet}..."
                    except:
                        pass
        elif packet.haslayer(UDP) and not packet.haslayer(DNS):
            pkt_type = "UDP"
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    if payload.strip():
                        snippet = ''.join(c for c in payload[:50] if c.isprintable())
                        transferred_data = f"Payload: {snippet}..."
                except:
                    pass
        elif packet.haslayer(ICMP):
            pkt_type = "ICMP"
            transferred_data = f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}"

        # Geolocation for non-private IPs
        if not src_ip.startswith(("192.", "10.", "172.")):
            location = get_ip_geolocation(src_ip)
            log_entry = f"[{ist_time}] 🌍 Geolocation: {src_ip} -> {location}"
            print(log_entry)
            logging.info(log_entry)

        # Log packet details
        if domain:
            log_entry = f"[{ist_time}] 🌐 Domain: {domain}"
            print(log_entry)
            logging.info(log_entry)
        if transferred_data:
            log_entry = f"[{ist_time}] 📦 {transferred_data}"
            print(log_entry)
            logging.info(log_entry)
        if pkt_type == "DNS Query":
            log_entry = f"[{ist_time}] 🔍 {transferred_data}"
            print(log_entry)
            logging.info(log_entry)
        elif pkt_type == "HTTP":
            log_entry = f"[{ist_time}] 📡 HTTP Request: {payload[:100] if 'payload' in locals() else 'Unknown'}..."
            print(log_entry)
            logging.info(log_entry)
        elif pkt_type.startswith("TCP Flags") or pkt_type == "TLS":
            log_entry = f"[{ist_time}] 🚩 {pkt_type}"
            print(log_entry)
            logging.info(log_entry)

        return protocol, pkt_size, src_ip, pkt_type, domain, transferred_data
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
            proto, pkt_size, src_ip, pkt_type, domain, transferred_data = result
            proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"Other_{proto}")
            traffic_data[proto_name] += pkt_size
            packet_sizes_by_proto[proto_name].append(pkt_size)
            source_ips[proto_name][src_ip] += 1
            packet_types[proto_name][pkt_type] += 1
            if domain:
                domains_by_proto[proto_name][domain] += 1
            if transferred_data:
                data_transferred[proto_name][transferred_data] += 1
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
        fig.set_size_inches(16, 8)  # Increased width for extra column

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
        if packet_sizes_by_proto:
            all_sizes = [size for sizes in packet_sizes_by_proto.values() for size in sizes[-1000:]]
            if all_sizes:
                sns.histplot(all_sizes, bins=30, kde=True, color="purple", ax=ax2)
                ax2.set_xlabel("Packet Size (Bytes)")
                ax2.set_ylabel("Count")
                ax2.set_title("Packet Size Distribution (Last 1000 Packets)")

        # Table: Packet Statistics (right side, spanning both rows)
        ax3 = plt.subplot2grid((2, 2), (0, 1), rowspan=2)
        ax3.axis('off')  # Hide axes for table
        table_data = [
            ["Protocol", "Bandwidth (Mbps)", "Packet Count", "Source IP", "Avg Size", "Packet Type", "Domain/URL", "Data Transferred"]
        ]
        for key in traffic_data:
            bandwidth = (traffic_data[key] * 8) / 1_000_000
            proto_value = int(key.split('_')[-1]) if key.startswith('Other') else {'TCP': 6, 'UDP': 17, 'ICMP': 1}.get(key, 0)
            packet_count = len([p for p in captured_packets if p.haslayer(IP) and p[IP].proto == proto_value])
            avg_size = np.mean(packet_sizes_by_proto[key]) if packet_sizes_by_proto[key] else 0
            top_ip = source_ips[key].most_common(1)[0][0] if source_ips[key] else "Unknown"
            top_type = packet_types[key].most_common(1)[0][0] if packet_types[key] else "Unknown"
            top_domain = domains_by_proto[key].most_common(1)[0][0] if domains_by_proto[key] else "N/A"
            top_data = data_transferred[key].most_common(1)[0][0] if data_transferred[key] else "N/A"
            table_data.append([key, f"{bandwidth:.2f}", f"{packet_count}", top_ip, f"{avg_size:.1f}", top_type, top_domain, top_data])
        
        table = ax3.table(
            cellText=table_data,
            cellLoc='center',
            loc='center',
            colWidths=[0.1, 0.12, 0.08, 0.12, 0.08, 0.12, 0.15, 0.23]
        )
        table.auto_set_font_size(False)
        table.set_fontsize(8)
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
        ist_time = get_ist_time()  # Define ist_time
        report = {
            "timestamp": ist_time,
            "total_packets": len(captured_packets),
            "traffic_summary": {key: (traffic_data[key] * 8) / 1_000_000 for key in traffic_data},
            "packet_size_stats": {
                "mean": float(np.mean([size for sizes in packet_sizes_by_proto.values() for size in sizes])) if packet_sizes_by_proto else 0,
                "max": float(max([size for sizes in packet_sizes_by_proto.values() for size in sizes], default=0)),
                "min": float(min([size for sizes in packet_sizes_by_proto.values() for size in sizes], default=0)),
                "std": float(np.std([size for sizes in packet_sizes_by_proto.values() for size in sizes])) if packet_sizes_by_proto else 0
            },
            "history": stats_history[-10:],
            "top_domains": {key: dict(domains_by_proto[key].most_common(3)) for key in domains_by_proto},
            "top_data_transferred": {key: dict(data_transferred[key].most_common(3)) for key in data_transferred}
        }
        with open('traffic_report.json', 'w') as f:
            json.dump(report, f, indent=4)
        log_entry = f"[{ist_time}] 📄 Generated traffic report: traffic_report.json"
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
        fig = plt.figure(figsize=(16, 8))
        ani = FuncAnimation(fig, update_graph, interval=UPDATE_INTERVAL * 1000)
        plt.show()
    except KeyboardInterrupt:
        print("\n🛑 Sniffing stopped by user.")
        logging.info(f"[{get_ist_time()}] Sniffing stopped by user.")
    except Exception as e:
        logging.error(f"[{get_ist_time()}] Fatal error: {e}")
        print(f"❌ Fatal error: {e}")
        exit(1)