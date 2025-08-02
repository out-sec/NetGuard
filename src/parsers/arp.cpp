#include "parsers/arp.h"

#include <arpa/inet.h>
#include <cstring>
#include <iomanip>

namespace parsers {

    ARPHeader parse_arp_header(const uint8_t* buffer, ssize_t length) {
        ARPHeader header;

        if (length < 28) {
            throw std::runtime_error("ARP packet too short");
        }

        // Extract fixed fields
        header.hardware_type = ntohs(*reinterpret_cast<const uint16_t*>(buffer));
        header.protocol_type = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 2));
        header.hardware_size = *(buffer + 4);
        header.protocol_size = *(buffer + 5);
        header.operation     = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 6));

        // Set string versions
        header.hardware_type_str = hardware_type_to_string(header.hardware_type);
        header.protocol_type_str = protocol_type_to_string(header.protocol_type);

        // Extract addresses
        const uint8_t* ptr = buffer + 8;
        header.sender_mac.assign(ptr, ptr + 6);
        ptr += 6;

        char ip_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, ptr, ip_buf, INET_ADDRSTRLEN);
        header.sender_ip = std::string(ip_buf);
        ptr += 4;

        header.target_mac.assign(ptr, ptr + 6);
        ptr += 6;

        inet_ntop(AF_INET, ptr, ip_buf, INET_ADDRSTRLEN);
        header.target_ip = std::string(ip_buf);

        return header;
    }

    std::string hardware_type_to_string(uint16_t type) {
        switch (type) {
            case 1: return "Ethernet (1)";
            default: return "Unknown (" + std::to_string(type) + ")";
        }
    }

    std::string protocol_type_to_string(uint16_t proto) {
        std::ostringstream oss;
        oss << "0x" << std::hex << std::setw(4) << std::setfill('0') << proto;
        if (proto == 0x0800) {
            oss << " (IPv4)";
        } else if (proto == 0x86DD) {
            oss << " (IPv6)";
        } else if (proto == 0x0806) {
            oss << " (ARP)";
        }
        return oss.str();
    }

} // namespace parsers
