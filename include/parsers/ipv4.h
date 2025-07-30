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

    const uint8_t* payload;
    uint16_t payload_length;

    std::string to_string() const;
};

// Parse and print IPv4 header
bool parse_ipv4_packet(const uint8_t* buffer, ssize_t length);

} // namespace parsers

#endif // PARSERS_IPV4_H
