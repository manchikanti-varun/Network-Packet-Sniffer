# Network Packet Sniffer

A powerful and lightweight network packet sniffer built using **Python** and **Scapy**. This tool allows real-time packet capturing, filtering, and analysis across multiple interfaces. It is useful for **network monitoring, security analysis, and learning about network protocols**.

## 🚀 Features

✔️ Capture packets on a selected network interface  
✔️ Capture packets on **all** interfaces simultaneously  
✔️ Filter packets based on protocols (**TCP, UDP, ICMP, etc.**)  
✔️ Display packet details in a readable format  
✔️ Save captured packets to a **PCAP file** for further analysis  
✔️ **Live bandwidth monitoring** (Kbps/Mbps)  
✔️ **Traffic statistics** with protocol breakdown  
✔️ Supports both **Windows & Linux** (with WinPcap/Npcap installed on Windows)  

## 📌 Requirements

🔹 **Python 3.8+**  
🔹 **Virtual Environment (venv) [Recommended]**  
🔹 **Required Python Modules:** Install using:
```sh
pip install -r requirements.txt
```

## 📂 Project Structure

```
📦 Network Packet Sniffer
├── 📁 network-packet-sniffer/       # Virtual environment (optional)
├── 📄 .gitignore                   # Git ignore file
├── 📄 README.md                    # Project documentation
├── 📄 requirements.txt             # Python dependencies
├── 📂 src/                         # Source code folder
│   ├── 📄 find_interfaces.py       # List available network interfaces
│   ├── 📄 sniff_packets.py         # Capture and analyze network packets
│   ├── 📄 live_bandwidth.py        # Monitor live bandwidth usage
│   ├── 📄 live_traffic.py          # Show real-time traffic stats
│   ├── 📄 network_sniffer.py       # Unified script to run all components
└── 📄 captured_packets.pcap        # Saved packet captures (optional)
```

## 🛠 Setup & Usage

### 1️⃣ Clone the Repository
```sh
git clone https://github.com/manchikanti-varun/Network-Packet-Sniffer.git
cd Network-Packet-Sniffer
```

### 2️⃣ Create & Activate Virtual Environment (Recommended)
```sh
# Create virtual environment
python -m venv network-sniffer

# Activate venv (Windows)
network-sniffer\Scripts\activate  

# Activate venv (Linux/Mac)
source network-sniffer/bin/activate  
```

### 3️⃣ Install Dependencies
```sh
pip install -r requirements.txt
```

### 4️⃣ Run the Sniffer

#### List Available Network Interfaces:
```sh
python src/find_interfaces.py
```

#### Start Packet Capture on a Specific Interface:
```sh
python src/sniff_packets.py --iface <INTERFACE_NAME>
```

#### Capture on All Interfaces:
```sh
python src/sniff_packets.py --all
```

#### Run Bandwidth Monitoring:
```sh
python src/live_bandwidth.py
```

#### Run Traffic Statistics:
```sh
python src/live_traffic.py
```

#### Run Everything Together:
```sh
python src/network_sniffer.py
```

## 🎯 Example Output

```
Available Network Interfaces:
[0] \Device\NPF_{XYZ123}
[1] \Device\NPF_{ABC456}

Enter the interface number to sniff: 0

Sniffing packets on \Device\NPF_{XYZ123}... Press Ctrl+C to stop.
Ether / IP / TCP 192.168.1.5:50000 > 93.184.216.34:443
Ether / IPv6 / ICMPv6 Echo Request
Ether / IP / UDP 10.0.0.2:68 > 10.0.0.1:67 DHCP
```

## 🔒 Disclaimer
This tool is intended for **educational and ethical purposes only**. Unauthorized packet sniffing on networks you do not own or have permission to monitor is **illegal** and can result in severe consequences. Use responsibly!

