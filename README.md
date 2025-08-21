NetGuard:
NetGuard is a high-performance Network Intrusion Detection System (NIDS) implemented in modern C++ with CMake. It provides real-time network traffic analysis, multi-layer protocol parsing, custom rule-based detection, and a threat alerting system. Designed for extensibility, NetGuard aims to evolve into a Network Intrusion Prevention System (NIPS) with active mitigation capabilities.

Features
Core Capabilities

Packet Processing:

Ethernet frame parsing

IPv4 and IPv6 support

TCP, UDP, and ICMP analysis

Full HTTP request and response parsing with all standard headers

Detection Engine:

Signature-based detection

Protocol anomaly detection

Stateful pattern matching

Custom rule support

Performance:

Multi-threaded processing

Zero-copy parsing

Rule optimization

Supported Protocols

Ethernet

IP (v4)

ARP

TCP

UDP

ICMP

HTTP

Future Protocol Support
NetGuard/
├── config/            # Network interface configuration
│   └── interface.cfg
├── docs/              # Project documentation
│   └── design.md
├── include/           # Header files
│   ├── config/
│   ├── parsing/
│   ├── rules/
│   └── utils/
├── rules/             
│   ├── exploits/
│   └── protocols/
├── src/               
│   ├── config/
│   ├── parsing/
│   ├── rules/
│   └── utils/
├── tests/
└── CMakeLists.txt

Dependencies:

C++17 compiler (GCC 9+, Clang 10+, MSVC 2019+)

CMake 3.14+

libpcap 1.9.0+ (Linux/macOS) or npcap (Windows)

Installation:
Linux/macOS
sudo apt-get install libpcap-dev cmake g++
git clone https://github.com/out-sec/NetGuard.git
cd NetGuard
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
Windows

Install npcap from https://npcap.com

Install CMake from https://cmake.org/download/

Install a C++ compiler (Visual Studio 2019+ with C++ tools)

Clone the repository and build with CMake

Usage
1. Configure the Network Interface

Edit:
config/interface.cfg
Example:
interface=ens33
2. Run NetGuard (Live Capture Mode)
sudo ./build/netguard
Root privileges are required for packet capture.

3. Test with a .pcap File

You can replay captured traffic into the monitored interface:
sudo apt install tcpreplay
sudo tcpreplay --intf1=ens33 sample.pcap
Or modify the source code to read .pcap files directly for offline analysis.

Contributing

We welcome contributions! See CONTRIBUTION.md for guidelines.

License

MIT License — see LICENSE.

