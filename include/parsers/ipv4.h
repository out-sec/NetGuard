#ifndef PARSERS_IPV4_H
#define PARSERS_IPV4_H

#include <cstdint>
#include <string>

namespace parsers {

struct IPv4Header {
    uint8_t version;
    uint8_t ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t src_ip;
    uint32_t dest_ip;

    const uint8_t* payload = nullptr;
    uint16_t payload_length = 0;

    std::string to_string() const;
};

// Converts 32-bit IP to dotted decimal string
std::string ipv4_to_string(uint32_t ip);

// Converts protocol number to readable name (e.g., 6 → TCP)
std::string protocol_to_string(uint8_t protocol);

// Parses and prints an IPv4 packet from raw buffer
bool parse_ipv4_packet(const uint8_t* buffer, ssize_t length);

// Parses raw buffer into structured IPv4Header
IPv4Header parse_ipv4_header(const uint8_t* buffer, ssize_t length);

} // namespace parsers

#endif // PARSERS_IPV4_H
