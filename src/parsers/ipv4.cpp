#include "parsers/ipv4.h"
#include <iostream>
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>

namespace parsers {

std::string ipv4_to_string(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    return std::string(inet_ntoa(addr));
}

bool parse_ipv4_packet(const uint8_t* buffer, ssize_t length) {
    if (length < 20) {
        std::cerr << "Invalid IPv4 packet: too short\n";
        return false;
    }

    IPv4Header ipv4;
    ipv4.version = (buffer[0] >> 4);
    ipv4.ihl = (buffer[0] & 0x0F);
    ipv4.tos = buffer[1];
    ipv4.total_length = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 2));
    ipv4.identification = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 4));
    ipv4.flags_fragment_offset = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 6));
    ipv4.ttl = buffer[8];
    ipv4.protocol = buffer[9];
    ipv4.header_checksum = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 10));
    ipv4.src_ip = *reinterpret_cast<const uint32_t*>(buffer + 12);
    ipv4.dest_ip = *reinterpret_cast<const uint32_t*>(buffer + 16);

    uint16_t header_len_bytes = ipv4.ihl * 4;
    if (length < header_len_bytes) {
        std::cerr << "Invalid IPv4 packet: header length too large\n";
        return false;
    }

    ipv4.payload = buffer + header_len_bytes;
    ipv4.payload_length = ipv4.total_length - header_len_bytes;

    std::cout << ipv4.to_string() << "\n";

    return true;
}

std::string IPv4Header::to_string() const {
    std::ostringstream oss;
    oss << "  IPv4 Packet:\n"
        << "    Version: " << static_cast<int>(version) << "\n"
        << "    Header Length: " << static_cast<int>(ihl) * 4 << " bytes\n"
        << "    TOS: 0x" << std::hex << static_cast<int>(tos) << std::dec << "\n"
        << "    Total Length: " << total_length << "\n"
        << "    Identification: 0x" << std::hex << identification << std::dec << "\n"
        << "    TTL: " << static_cast<int>(ttl) << "\n"
        << "    Protocol: " << static_cast<int>(protocol) << "\n"
        << "    Source IP: " << ipv4_to_string(src_ip) << "\n"
        << "    Destination IP: " << ipv4_to_string(dest_ip) << "\n";

    if (payload_length > 0) {
        oss << "    Payload (" << payload_length << " bytes):\n      ";
        for (int i = 0; i < payload_length && i < 64; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(payload[i]) << " ";
            if ((i + 1) % 16 == 0) oss << "\n      ";
        }
    } else {
        oss << "    No Payload\n";
    }

    return oss.str();
}

} // namespace parsers
