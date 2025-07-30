#include "parsers/ethernet.h"
#include "utils/bytes.h"
#include "utils/decEthernet.h"
#include "config/interface.h"
#include "parsers/ipv4.h"

#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>

namespace parsers {

// std::string EthernetHeader::to_string() const {
//     std::ostringstream oss;
//     oss << "Ethernet Frame:\n"
//         << "  Destination MAC: " << utils::mac_to_string(dest_mac) << "\n"
//         << "  Source MAC:      " << utils::mac_to_string(src_mac) << "\n"
//         << "  EtherType:       0x" << std::hex << ntohs(eth_type);
//     return oss.str();
// }

std::string EthernetHeader::to_string() const {
    std::ostringstream oss;
    oss << "Ethernet Frame:\n"
        << "  Destination MAC: " << dest_mac_str << "\n"
        << "  Source MAC:      " << src_mac_str << "\n"
        << "  EtherType:       " << eth_type_str << " (" << eth_proto << ")";
    return oss.str();
}

EthernetHeader parse_ethernet_header(const uint8_t* buffer, ssize_t length) {
    EthernetHeader eth;

    if (!utils::is_valid_ethernet_frame(buffer, length))
        return eth;

    // Reconstruct the EthernetHeader
    std::memcpy(eth.dest_mac, buffer, 6);         // First 6 bytes: dest MAC
    std::memcpy(eth.src_mac, buffer + 6, 6);      // Next 6 bytes: source MAC
    eth.eth_type = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 12));  // EtherType (2 bytes)

    eth.payload = buffer + 14;
    eth.payload_len = length - 14;

    // Assign readable strings for display/logging/debugging
    eth.dest_mac_str = utils::mac_to_string(eth.dest_mac);
    eth.src_mac_str  = utils::mac_to_string(eth.src_mac);
    eth.eth_type_str = "0x" + utils::to_hex(eth.eth_type, 4);

    switch (eth.eth_type) {
        case 0x0800:
            eth.eth_proto = "IPv4";
            break;
        case 0x0806:
            eth.eth_proto = "ARP";
            break;
        case 0x86DD:
            eth.eth_proto = "IPv6";
            break;
        default:
            eth.eth_proto = "Unknown";
            break;
    }

    return eth;
}


int create_raw_socket() {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1) {
        perror("Socket creation failed");
        return -1;
    }

    // Load interface from config
    config::Interface iface;
    std::string iface_name = iface.get_interface();

    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, iface_name.c_str(), iface_name.length()) < 0) {
        perror(("Binding to interface failed: " + iface_name).c_str());
        close(sock);
        return -1;
    }

    std::cout << "[+] Bound to interface: " << iface_name << "\n";
    return sock;
}


bool parse_ethernet_frame(const uint8_t* buffer, ssize_t length) {
    EthernetHeader eth = parse_ethernet_header(buffer, length);
    if (eth.eth_proto == "Unknown") return false;

    std::cout << eth.to_string() << '\n';

    if (eth.eth_proto == "IPv4") {
        std::cout << "  Ethernet Protocol: IPv4\n";
        // parsers::parse_ipv4_packet(eth.payload, eth.payload_len);
    } else if (eth.eth_proto == "ARP") {
        std::cout << "  Ethernet Protocol: ARP\n";
    } else if (eth.eth_proto == "IPv6") {
        std::cout << "  Ethernet Protocol: IPv6\n";
    }

    return true;

    // if (eth.payload_len > 0)
    //     std::cout << eth.payload_as_hex() << "\n";
    // else
    //     std::cout << "Empty Payload\n";

    // Return true to indicate successful parsing
    std::cout << "\n";
    return true;
}

std::string EthernetHeader::payload_as_hex() const {
    std::ostringstream oss;
    oss << "  Payload (" << payload_len << " bytes):\n    ";

    for (int i = 0; i < payload_len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(payload[i]) << " ";
        if ((i + 1) % 16 == 0) oss << "\n    ";
    }

    return oss.str();
}

} // namespace parsers
