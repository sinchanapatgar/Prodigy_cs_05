📡 PRODIGY_CS_05 – Network Packet Analyzer
Prodigy Infotech Cybersecurity Internship – Task 05
📌 Overview
A Python GUI application that captures and analyzes live network packets in real time. It displays source and destination IP addresses, protocols, ports, and payload data — useful for learning how network traffic works.
⚠️ Ethical Notice: Use this tool only on your own network. Capturing packets on a network without authorization is illegal. This project is strictly for educational purposes.
🖥️ Features
📡 Live packet capture using raw sockets
Displays: Source IP, Destination IP, Protocol, Ports, Packet size, Timestamp
Supports TCP, UDP, ICMP protocol parsing
Protocol filter (ALL / TCP / UDP / ICMP)
Packet detail view with hex payload and decoded text
Well-known port identification (HTTP, HTTPS, DNS, SSH, FTP, etc.)
Start / Stop / Clear controls
Dark-themed GUI built with Tkinter
🧠 How It Works
The program opens a raw socket to intercept network packets at the IP layer. For each packet it:
Parses the IPv4 header (source IP, destination IP, protocol, TTL)
Parses the transport layer (TCP flags & ports, UDP length & ports, ICMP type & code)
Extracts and displays the payload
Maps ports to known services (port 80 → HTTP, port 443 → HTTPS, etc.)
Supported Protocols
Protocol
Details Shown
TCP
Src/Dst ports, flags (SYN, ACK, FIN, RST, PSH, URG)
UDP
Src/Dst ports, packet length
ICMP
Type, code, checksum
Known Port Mappings
Port
Service
80
HTTP
443
HTTPS
22
SSH
21
FTP
53
DNS
25
SMTP
3306
MySQL
3389
RDP
🚀 How to Run
Prerequisites
Python 3.8+
No extra libraries needed (uses built-in socket, struct, tkinter)
Admin / Root privileges required
Run the Program
Windows — Run as Administrator:
python PRODIGY_CS_05.py
Linux / Mac:
sudo python3 PRODIGY_CS_05.py
🖼️ Usage
Launch the application (as admin/root)
Select a protocol filter if needed (default: ALL)
Click ▶ START CAPTURE to begin
Watch packets appear in the table in real time
Click any row to see the full packet detail and payload
Click ⏹ STOP to end capture
Click 🗑 CLEAR to reset the table
📁 File Structure
PRODIGY_CS_05/
├── PRODIGY_CS_05.py   # Main program
└── README.md          # Documentation
🛠️ Tech Stack
Tool
Purpose
Python 3
Core language
tkinter + ttk
GUI framework
socket
Raw packet capture
struct
Binary packet parsing
threading
Non-blocking capture loop
⚠️ Legal & Ethical Disclaimer
Analyze only your own network traffic
Never use on public, corporate, or shared networks without authorization
Unauthorized packet sniffing violates computer fraud and privacy laws
This project is for learning network fundamentals only
