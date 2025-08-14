#include "utils/decHttp.h"
#include <sstream>
#include <algorithm>

namespace {

std::string trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    size_t end   = str.find_last_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    return str.substr(start, end - start + 1);
}

} // namespace

namespace utils {

std::optional<HTTPDecodedData> decode_http(const uint8_t* buffer, size_t length) {
    if (!buffer || length == 0) return std::nullopt;

    std::string payload(reinterpret_cast<const char*>(buffer), length);

    // Detect request
    static const std::string methods[] = {
        "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"
    };
    bool is_request = false;
    for (const auto& m : methods) {
        if (payload.rfind(m + " ", 0) == 0) {
            is_request = true;
            break;
        }
    }
    bool is_response = payload.rfind("HTTP/", 0) == 0;

    if (!is_request && !is_response) return std::nullopt;

    HTTPDecodedData data;
    data.is_http = true;
    data.is_request = is_request;

    std::istringstream stream(payload);
    std::string line;

    // Start line
    if (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::istringstream first_line(line);

        if (is_request) {
            first_line >> data.method >> data.path >> data.version;
        } else {
            first_line >> data.version >> data.status_code;
            std::getline(first_line, data.reason_phrase);
            data.reason_phrase = trim(data.reason_phrase);
        }
    }

    // Headers
    while (std::getline(stream, line) && !line.empty() && line != "\r") {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        auto pos = line.find(':');
        if (pos != std::string::npos) {
            std::string key = trim(line.substr(0, pos));
            std::string value = trim(line.substr(pos + 1));
            data.headers[key] = value;
        }
    }

    return data;
}

} // namespace utils

