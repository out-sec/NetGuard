#ifndef PARSERS_ARP_H
#define PARSERS_ARP_H

#include <cstdint>
#include <string>
#include <vector>
#include <sstream>
#include <stdexcept>

namespace parsers {

    struct ARPHeader {
        uint16_t hardware_type;      // Hardware type (e.g., Ethernet)
        uint16_t protocol_type;      // Protocol type (e.g., IPv4)
        uint8_t hardware_size;       // Length of hardware address
        uint8_t protocol_size;       // Length of protocol address
        uint16_t operation;          // Operation code (1 for request, 2 for reply)
        std::vector<uint8_t> sender_mac;  // Sender's MAC address
        std::string sender_ip;       // Sender's IP address
        std::vector<uint8_t> target_mac;  // Target's MAC address
        std::string target_ip;       // Target's IP address

    };

    // Parser Function to extract ARP Header from a buffer
    ARPHeader parse_arp_header(const uint8_t* buffer, ssize_t length);

} // namespace parsers


#endif // PARSERS_ARP_H