#ifndef UTILS_DEC_ETHERNET_H
#define UTILS_DEC_ETHERNET_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <optional>
#include <netinet/in.h>

namespace utils {

struct EthernetHeader {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type; // In network byte order (big endian)

    // Accessor functions (optional convenience)
    uint16_t get_ethertype() const {
        return ntohs(eth_type);
    }
};

// Parses raw Ethernet frame buffer into EthernetHeader
std::optional<EthernetHeader> decode_ethernet(const uint8_t* buffer, size_t length);

} // namespace utils

#endif