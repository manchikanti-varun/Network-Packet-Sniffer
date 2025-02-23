# 🌐 Network Packet Sniffer  

A powerful and lightweight **network packet sniffer** built using **Python** and **Scapy**. This tool enables real-time **packet capturing, filtering, and deep packet analysis** across multiple interfaces. It is useful for **network monitoring, security analysis, and understanding network protocols**.  

---

## 🚀 Features  

🔀 Capture packets on a **selected network interface**  
🔀 Capture packets on **all interfaces simultaneously**  
🔀 **Filter packets** based on protocols (**TCP, UDP, ICMP, DNS, etc.**)  
🔀 Extract **HTTP requests, DNS queries, and MAC addresses**  
🔀 Display **real-time download/upload speeds** (Kbps/Mbps)  
🔀 **Live bandwidth monitoring** with protocol breakdown  
🔀 **Geolocation lookup** for external IPs  
🔀 **Save captured packets** to a **PCAP** file for further analysis  
🔀 Supports **both Windows & Linux** (Requires **WinPcap/Npcap** on Windows)  

---

## 📌 Requirements  

🔹 **Python** 3.8+  
🔹 **Virtual Environment (venv) [Recommended]**  
🔹 Required Python Modules (Install using:)  
```bash
pip install -r requirements.txt
```  

---

## 📚 Project Structure  

```
📺 Network-Packet-Sniffer
📝 venv/                      # Virtual environment (optional)
📝 .gitignore                 # Git ignore file
📝 README.md                  # Project documentation
📝 requirements.txt            # Python dependencies
📂 src/                        # Source code folder
    📝 find_interfaces.py       # List available network interfaces
    📝 sniff_packets.py         # Capture and analyze network packets
    📝 live_bandwidth.py        # Monitor live bandwidth usage
    📝 live_traffic.py          # Show real-time traffic stats
    📝 network_sniffer.py       # Unified script to run all components
    📝 captured_packets.pcap    # Saved packet captures
```

---

## 🛠 Setup & Usage  

### 1⃣ Clone the Repository  

```bash
git clone https://github.com/manchikanti-varun/Network-Packet-Sniffer.git
cd Network-Packet-Sniffer
```  

### 2⃣ Create & Activate Virtual Environment (Recommended)  

```bash
# Create virtual environment
python -m venv network-sniffer

# Activate venv (Windows)
network-sniffer\Scripts\activate  

# Activate venv (Linux/Mac)
source network-sniffer/bin/activate  
```  

### 3⃣ Install Dependencies  

```bash
pip install -r requirements.txt
```  

### 4⃣ Run the Sniffer  

#### ✅ List Available Network Interfaces  
```bash
python src/find_interfaces.py
```  

#### ✅ Start Packet Capture on a Specific Interface  
```bash
python src/sniff_packets.py --iface <INTERFACE_NAME>
```  

#### ✅ Capture on All Interfaces  
```bash
python src/sniff_packets.py --all
```  

#### ✅ Run Bandwidth Monitoring  
```bash
python src/live_bandwidth.py
```  

#### ✅ Run Traffic Statistics  
```bash
python src/live_traffic.py
```  

#### ✅ Run Everything Together  
```bash
python src/network_sniffer.py
```  

---

## 🎯 Example Output  

```bash
Available Network Interfaces:
[0] \Device\NPF_{XYZ123}
[1] \Device\NPF_{ABC456}

Enter the interface number to sniff: 0

Sniffing packets on \Device\NPF_{XYZ123}... Press Ctrl+C to stop.

[12:30:45] 🌍 Geolocation: 192.168.1.5 -> Bangalore, India (ISP: XYZ Networks)
[12:30:46] 📱 HTTP Request: GET /index.html Host: example.com...
[12:30:47] 🔍 DNS Query: google.com
[12:30:48] 📊 Live Traffic Statistics (Updated Every 1s)
--------------------------------------------
Protocol    | Bandwidth (Mbps)
------------------------------
TCP         | 1.23 Mbps
UDP         | 0.67 Mbps
ICMP        | 0.05 Mbps
Other       | 0.01 Mbps
--------------------------------------------
```  

---

## 🔒 Disclaimer  

This tool is intended for **educational and ethical purposes only**. **Unauthorized packet sniffing** on networks you **do not own or have permission to monitor** is **illegal** and can result in **severe consequences**. **Use responsibly!**  

---

