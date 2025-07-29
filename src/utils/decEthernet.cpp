#include "utils/decEthernet.h"
#include <netinet/in.h> // For ntohs

namespace utils {

std::optional<EthernetHeader> decode_ethernet(const uint8_t* buffer, size_t length) {
    if (length < 14) return std::nullopt;

    EthernetHeader header;
    std::memcpy(header.dest_mac, buffer, 6);
    std::memcpy(header.src_mac, buffer + 6, 6);
    std::memcpy(&header.eth_type, buffer + 12, 2);

    return header;
}

} // namespace utils
