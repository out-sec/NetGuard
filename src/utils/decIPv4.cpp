#include "utils/decIPv4.h"
#include <sstream>
#include <iomanip>
#include <arpa/inet.h>

namespace decoders {

std::string version_to_string(uint8_t version) {
    return std::to_string(version) + " (IPv4)";
}

std::string ihl_to_string(uint8_t ihl) {
    return std::to_string(ihl * 4) + " bytes";
}

std::string tos_to_string(uint8_t tos) {
    uint8_t dscp = (tos & 0xFC) >> 2;
    uint8_t ecn = tos & 0x03;
    std::ostringstream oss;
    oss << "0x" << std::hex << static_cast<int>(tos)
        << " (DSCP: " << std::dec << static_cast<int>(dscp)
        << ", ECN: " << static_cast<int>(ecn) << ")";
    return oss.str();
}

std::string total_length_to_string(uint16_t total_length) {
    return std::to_string(total_length) + " bytes";
}

std::string identification_to_string(uint16_t id) {
    std::ostringstream oss;
    oss << "0x" << std::hex << id;
    return oss.str();
}

std::string flags_to_string(uint16_t flags_fragment_offset) {
    uint8_t flags = (flags_fragment_offset & 0xE000) >> 13;
    std::string result;

    if (flags & 0b100) result += "Reserved | ";
    if (flags & 0b010) result += "Don't Fragment | ";
    if (flags & 0b001) result += "More Fragments";
    if (result.empty()) result = "No flags set";
    else if (result.size() >= 3 && result.compare(result.size() - 3, 3, " | ") == 0)
    result.erase(result.size() - 3);

    return result;
}

std::string fragment_offset_to_string(uint16_t flags_fragment_offset) {
    uint16_t offset = flags_fragment_offset & 0x1FFF;
    return std::to_string(offset * 8) + " bytes";
}

std::string ttl_to_string(uint8_t ttl) {
    return std::to_string(ttl);
}

std::string protocol_to_string(uint8_t protocol) {
    using namespace parsers;
    return std::to_string(protocol) + " (" + parsers::protocol_to_string(protocol) + ")";
}

std::string checksum_to_string(uint16_t checksum) {
    std::ostringstream oss;
    oss << "0x" << std::hex << checksum << " (Not verified)";
    return oss.str();
}

std::string ip_to_string(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    return std::string(inet_ntoa(addr));
}

} // namespace decoders
