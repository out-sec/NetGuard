# NetGuard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C++](https://img.shields.io/badge/C%2B%2B-%2300599C?style=for-the-badge&logo=cplusplus&logoColor=white)](https://isocpp.org/)

NetGuard is a high-performance Network Intrusion Detection System (NIDS) implemented in modern C++ with CMake. It provides real-time network traffic analysis, multi-layer protocol parsing, custom rule-based detection, and a threat alerting system. Designed for extensibility, NetGuard aims to evolve into a Network Intrusion Prevention System (NIPS) with active mitigation capabilities.

## Features

### Core Capabilities
- **Packet Processing**:
  - Ethernet frame parsing
  - IPv4 and IPv6 support
  - TCP, UDP, and ICMP analysis
  - HTTP header inspection
- **Detection Engine**:
  - Signature-based detection
  - Protocol anomaly detection
  - Stateful pattern matching
  - Custom rule support
- **Performance**:
  - Multi-threaded processing
  - Zero-copy parsing
  - Rule optimization

### Supported Protocols
- Ethernet
- IP (v4)
- ARP 
- TCP
- UDP
- ICMP
- HTTP

### Future Protocol Support
To enhance detection capabilities, we plan to add support for the following protocols:
- [ ] DNS
- [ ] FTP
- [ ] SMTP
- [ ] SSH
- [ ] TLS/SSL
- [ ] SMB
- [ ] RDP

## Project Structure

```
NetGuard/
├── config/            # Network interface configuration
│   └── interface.cfg
├── docs/             # Project documentation
│   └── design.md
├── include/          # Header files
│   ├── config/       # Interface configuration
│   ├── parsing/      # Packet parsing headers
│   ├── rules/        # Rule processing headers
│   └── utils/        # Utility functions
├── rules/            # Rule definition files
│   ├── exploits/     # Exploit-specific rules
│   └── protocols/    # Protocol-specific rules
├── src/              # Source code
│   ├── config/       # Interface configuration implementation
│   ├── parsing/      # Packet parsing implementation
│   ├── rules/        # Rule engine implementation
│   └── utils/        # Utility implementations
├── tests/            # Unit and integration tests
└── CMakeLists.txt    # Build configuration
```

## Dependencies
- C++17 compiler (e.g., GCC 9+, Clang 10+, MSVC 2019+)
- CMake 3.14+
- libpcap 1.9.0+ (for Linux/macOS) or npcap (for Windows)

## Installation

### Linux/macOS
1. Install dependencies:
   ```
   sudo apt-get install libpcap-dev cmake g++
   ```
2. Clone the repository:
   ```
   git clone https://github.com/out-sec/NetGuard.git
   cd NetGuard
   ```
3. Build the project:
   ```
   mkdir build
   cd build
   cmake -DCMAKE_BUILD_TYPE=Release ..
   make -j$(nproc)
   ```

### Windows
1. Install npcap from [https://npcap.com](https://npcap.com)
2. Install CMake from [https://cmake.org/download/](https://cmake.org/download/)
3. Install a C++ compiler (e.g., Visual Studio 2019+ with C++ tools)
4. Clone the repository and build using CMake GUI or command line.

## Usage
1. **Configure the Network Interface**:
   Edit `config/interface.cfg` to specify the network interface to monitor (e.g., `eth0`).
2. **Define Detection Rules**:
   Create or modify rule files in `rules/protocols/` or `rules/exploits/`. Refer to [Rule Syntax Guide](docs/rule_syntax.md) for details.
3. **Run NetGuard**:
   ```
   sudo ./build/netguard
   ```
   Note: Running as root is required to capture packets.

## Contributing
We welcome contributions! Please read our [Contribution Guidelines](CONTRIBUTION.md) for detailed instructions on how to contribute, including setting up the development environment and submitting pull requests.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact
For questions or feedback, please contact us at [contact@out-sec.org](mailto:contact@out-sec.org) or open an issue on [GitHub](https://github.com/out-sec/NetGuard/issues).

## Contributors
We extend our gratitude to all contributors who have helped shape NetGuard. View the full list of contributors [here](https://github.com/out-sec/NetGuard/graphs/contributors).
