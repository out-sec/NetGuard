#ifndef UTILS_DEC_ETHERNET_H
#define UTILS_DEC_ETHERNET_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <optional>

namespace utils {

// Validates minimum Ethernet header length
bool is_valid_ethernet_frame(const uint8_t* buffer, size_t length);

// Extract destination MAC address
std::optional<std::string> get_dest_mac(const uint8_t* buffer, size_t length);

// Extract source MAC address
std::optional<std::string> get_src_mac(const uint8_t* buffer, size_t length);

// Extract EtherType (returns in host byte order)
std::optional<uint16_t> get_ethertype(const uint8_t* buffer, size_t length);

} // namespace utils

#endif
