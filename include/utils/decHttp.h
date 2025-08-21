#ifndef NETGUARD_UTILS_DEC_HTTP_H
#define NETGUARD_UTILS_DEC_HTTP_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <map>
#include <optional>

namespace utils {

struct HTTPDecodedData {
    bool is_http = false;
    bool is_request = false;
    bool complete = false;

    // Start line
    std::string method;
    std::string path;
    std::string version;
    int         status_code = 0;
    std::string reason_phrase;

    // Headers
    std::map<std::string, std::string> headers;
    size_t header_bytes = 0;

    // Body
    std::string body;
    size_t body_bytes = 0;
    size_t content_length = 0;
    bool chunked = false;

    // Helpers
    std::map<std::string, std::string> form_fields;
    std::string json_pretty; // left empty (no JSON library)
};

std::optional<HTTPDecodedData> decode_http(const uint8_t* buffer, size_t length);

} // namespace utils

#endif // NETGUARD_UTILS_DEC_HTTP_H
