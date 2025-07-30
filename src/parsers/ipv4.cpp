#include "parsers/ipv4.h"
#include <iostream>
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace parsers {

std::string ipv4_to_string(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    return std::string(inet_ntoa(addr));
}

std::string protocol_to_string(uint8_t protocol) {
    switch (protocol) {
        case 1:  return "ICMP";
        case 2:  return "IGMP";
        case 6:  return "TCP";
        case 17: return "UDP";
        case 89: return "OSPF";
        default: return "Unknown";
    }
}

IPv4Header parse_ipv4_header(const uint8_t* buffer, ssize_t length) {
    IPv4Header ipv4{};
    if (length < 20) return ipv4;

    ipv4.version = (buffer[0] >> 4);
    ipv4.ihl = (buffer[0] & 0x0F);
    ipv4.tos = buffer[1];
    ipv4.total_length = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 2));
    ipv4.identification = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 4));
    ipv4.flags_fragment_offset = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 6));
    ipv4.ttl = buffer[8];
    ipv4.protocol = buffer[9];
    ipv4.header_checksum = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 10));
    std::memcpy(&ipv4.src_ip, buffer + 12, sizeof(uint32_t));
    std::memcpy(&ipv4.dest_ip, buffer + 16, sizeof(uint32_t));

    uint16_t header_len_bytes = ipv4.ihl * 4;
    if (length < header_len_bytes) return ipv4;

    ipv4.payload = buffer + header_len_bytes;
    ipv4.payload_length = (ipv4.total_length > header_len_bytes) ? ipv4.total_length - header_len_bytes : 0;

    return ipv4;
}

bool parse_ipv4_packet(const uint8_t* buffer, ssize_t length) {
    IPv4Header ipv4 = parse_ipv4_header(buffer, length);

    if (ipv4.version != 4 || ipv4.ihl < 5) {
        std::cerr << "Invalid IPv4 header version or IHL\n";
        return false;
    }

    std::cout << ipv4.to_string() << "\n";
    return true;
}

std::string IPv4Header::to_string() const {
    std::ostringstream oss;
    uint16_t flags = (flags_fragment_offset & 0xE000) >> 13;
    uint16_t fragment_offset = (flags_fragment_offset & 0x1FFF);

    oss << "  IPv4 Packet:\n"
        << "    Version: " << static_cast<int>(version) << "\n"
        << "    Header Length: " << static_cast<int>(ihl) * 4 << " bytes\n"
        << "    TOS: 0x" << std::hex << static_cast<int>(tos) << std::dec << "\n"
        << "    Total Length: " << total_length << "\n"
        << "    Identification: 0x" << std::hex << identification << std::dec << "\n"
        << "    Flags: 0x" << std::hex << flags << " | Frag Offset: " << std::dec << fragment_offset << "\n"
        << "    TTL: " << static_cast<int>(ttl) << "\n"
        << "    Protocol: " << static_cast<int>(protocol) << " (" << protocol_to_string(protocol) << ")\n"
        << "    Header Checksum: 0x" << std::hex << header_checksum << std::dec << "\n"
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
