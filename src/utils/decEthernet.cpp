#include "utils/decEthernet.h"
#include "utils/bytes.h"
#include <cstring>
#include <netinet/in.h>

namespace utils {

bool is_valid_ethernet_frame(const uint8_t* buffer, size_t length) {
    return buffer && length >= 14;
}

std::optional<std::string> get_dest_mac(const uint8_t* buffer, size_t length) {
    if (!is_valid_ethernet_frame(buffer, length)) return std::nullopt;
    return mac_to_string(buffer);
}

std::optional<std::string> get_src_mac(const uint8_t* buffer, size_t length) {
    if (!is_valid_ethernet_frame(buffer, length)) return std::nullopt;
    return mac_to_string(buffer + 6);
}

std::optional<uint16_t> get_ethertype(const uint8_t* buffer, size_t length) {
    if (!is_valid_ethernet_frame(buffer, length)) return std::nullopt;

    uint16_t eth_type;
    std::memcpy(&eth_type, buffer + 12, 2);
    return ntohs(eth_type);
}

} // namespace utils
