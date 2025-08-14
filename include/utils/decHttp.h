#ifndef UTILS_DEC_HTTP_H
#define UTILS_DEC_HTTP_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <map>
#include <optional>

namespace utils {

struct HTTPDecodedData {
    bool is_http = false;
    bool is_request = false;

    std::string method;
    std::string path;
    std::string version;

    int status_code = 0;
    std::string reason_phrase;

    std::map<std::string, std::string> headers;
};

// Detects and decodes HTTP message from raw buffer
std::optional<HTTPDecodedData> decode_http(const uint8_t* buffer, size_t length);

} // namespace utils

#endif // UTILS_DEC_HTTP_H
