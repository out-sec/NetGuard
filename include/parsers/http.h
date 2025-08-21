#ifndef PARSERS_HTTP_H
#define PARSERS_HTTP_H

#include <string>
#include <map>
#include <cstdint>
#include <cstddef>
#include <optional>

#include "utils/decHttp.h"

namespace parsers {

struct HTTPHeader {
    bool is_http = false;
    bool is_request = false;
    bool complete = false;

    // Start-line
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
    std::string json_pretty;

    std::string to_string() const;
};

HTTPHeader parse_http_header(const uint8_t* buffer, size_t length);

std::optional<utils::HTTPDecodedData>
decode_http(const unsigned char* buffer, unsigned long length);
} // namespace parsers

#endif
