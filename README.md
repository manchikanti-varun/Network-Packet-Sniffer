**Network Packet Sniffer**
A simple network packet sniffer built with Python and Scapy. It captures and analyzes network packets in real-time across multiple interfaces. Useful for network monitoring, security analysis, and learning network protocols.

**🚀 Features**
✔️ Capture packets on a selected network interface  
✔️ Capture packets on all interfaces simultaneously  
✔️ Filter packets based on protocols (TCP, UDP, ICMP, etc.)  
✔️ Display packet details in a readable format  

**📌 Requirements**
🔹 Python 3.8+  
🔹 Virtual Environment (venv)  
🔹 Required Python modules:  
```sh
pip install -r requirements.txt
```

**📚 Project Structure**
```
💾 Network Packet Sniffer
│── 📁 network-packet-sniffer/         # Virtual environment (optional)
│── 📄 .gitignore               # Git ignore file
│── 📄 README.md                # Project documentation
│── 📄 requirements.txt         # Python dependencies
│── 📄 find_interfaces.py       # List available network interfaces
│── 📄 sniff_packets.py         # Capture and analyze network packets
```

**🛠 Setup & Usage**
**1️⃣ Clone the Repository**  
```sh
git clone https://github.com/YOUR_USERNAME/network-packet-sniffer.git
cd network-packet-sniffer
```

**2️⃣ Create & Activate Virtual Environment**  
```sh
python -m venv network-sniffer
# Activate venv (Windows)
network-sniffer\Scripts\activate  
# Activate venv (Linux/Mac)
source network-sniffer/bin/activate  
```

**3️⃣ Install Dependencies**  
```sh
pip install -r requirements.txt
```

**4️⃣ Run the Sniffer**  
**List Available Network Interfaces:**  
```sh
python find_interfaces.py
```

**Start Packet Capture on a Specific Interface:**  
```sh
python sniff_packets.py --iface <INTERFACE_NAME>
```

**Capture on All Interfaces:**  
```sh
python sniff_packets.py --all
```

**🎯 Example Output**
```
Sniffing packets on \Device\NPF_{XYZ123}... Press Ctrl+C to stop.
Ether / IP / TCP 192.168.1.5:50000 > 93.184.216.34:443
Ether / IPv6 / ICMPv6 Echo Request
Ether / IP / UDP 10.0.0.2:68 > 10.0.0.1:67 DHCP
```

**🔒 Disclaimer**
This tool is intended for educational and ethical purposes **only**. Unauthorized packet sniffing on networks you do not own or have permission to monitor **is illegal**.

**🐝 License**
This project is **open-source** and available under the **MIT License**.

