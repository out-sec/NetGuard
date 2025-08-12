# NetGuard - Network Intrusion Detection System (NIDS)

## Overview
NetGuard is a simple C++ NIDS that captures network traffic on a specified interface and detects HTTP requests in real time.

## Features
- Captures ARP and IPv4/TCP packets (via libpcap/raw sockets)
- Parses HTTP requests and prints basic info (method, URI, Host, User-Agent)
- Real-time packet logging for demo

## Requirements
- Linux (tested on Ubuntu)
- `g++`, `cmake`
- `libpcap-dev`

## Build
```bash
cd ~/NetGuard
mkdir -p build && cd build
cmake ..
make -j$(nproc)


## How To Run
```bash
cd ~/NetGuard
sudo ./build/nids