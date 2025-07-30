#ifndef UTILS_BYTES_H
#define UTILS_BYTES_H

#include <cstdint>
#include <string>
#include <sstream>
#include <iomanip>

namespace utils {

inline uint16_t to_uint16(const uint8_t* data) {
    return (data[0] << 8) | data[1];
}

inline uint32_t to_uint32(const uint8_t* data) {
    return (data[0] << 24) | (data[1] << 16) |
           (data[2] << 8) | data[3];
}

inline std::string mac_to_string(const uint8_t* mac) {
    std::ostringstream oss;
    for (int i = 0; i < 6; ++i) {
        if (i) oss << ":";
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(mac[i]);
    }
    return oss.str();
}

inline std::string to_hex(uint32_t value, int width = 4) {
    std::ostringstream oss;
    oss << std::hex << std::setw(width) << std::setfill('0') << std::uppercase << value;
    return oss.str();
}

} // namespace utils

#endif
