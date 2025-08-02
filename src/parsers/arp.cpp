#include "parsers/arp.h"
#include <arpa/inet.h>
#include <cstring>

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

        // Extract addresses
        const uint8_t* ptr = buffer + 8;
        header.sender_mac.assign(ptr, ptr + 6);
        ptr += 6;

        char ip_buf[INET_ADDRSTRLEN];
        std::memcpy(ip_buf, ptr, 4);
        header.sender_ip = inet_ntoa(*reinterpret_cast<const in_addr*>(ptr));
        ptr += 4;

        header.target_mac.assign(ptr, ptr + 6);
        ptr += 6;

        std::memcpy(ip_buf, ptr, 4);
        header.target_ip = inet_ntoa(*reinterpret_cast<const in_addr*>(ptr));

        return header;
    }

} // namespace parsers
