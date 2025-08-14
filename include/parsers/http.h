#ifndef PARSERS_HTTP_H
#define PARSERS_HTTP_H

#include <string>
#include <map>
#include <cstdint>
#include <cstddef>

namespace parsers {

struct HTTPHeader {
    bool is_http = false;
    bool is_request = false;

    std::string method;     // GET, POST, etc.
    std::string path;       // /index.html
    std::string version;    // HTTP/1.1

    int status_code = 0;    // 200, 404, etc.
    std::string reason_phrase;

    std::map<std::string, std::string> headers;

    std::string to_string() const;
};

HTTPHeader parse_http_header(const uint8_t* buffer, size_t length);

} // namespace parsers

#endif
