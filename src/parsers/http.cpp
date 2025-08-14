#include "parsers/http.h"
#include <sstream>
#include <algorithm>

using namespace parsers;

static std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    auto end = s.find_last_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    return s.substr(start, end - start + 1);
}

HTTPHeader parsers::parse_http_header(const uint8_t* buffer, size_t length) {
    HTTPHeader header;
    std::string data(reinterpret_cast<const char*>(buffer), length);

    std::istringstream stream(data);
    std::string line;

    if (!std::getline(stream, line)) return header;

    if (line.rfind("HTTP/", 0) == 0) {
        header.is_http = true;
        header.is_request = false;
        std::istringstream status_line(line);
        std::string version;
        status_line >> version >> header.status_code;
        std::getline(status_line, header.reason_phrase);
        header.version = version;
        header.reason_phrase = trim(header.reason_phrase);
    }
    else {
        header.is_http = true;
        header.is_request = true;
        std::istringstream request_line(line);
        request_line >> header.method >> header.path >> header.version;
    }

    while (std::getline(stream, line) && line != "\r") {
        auto colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = trim(line.substr(0, colon));
            std::string value = trim(line.substr(colon + 1));
            header.headers[key] = value;
        }
    }

    return header;
}

std::string HTTPHeader::to_string() const {
    std::ostringstream out;
    if (is_request) {
        out << method << " " << path << " " << version << "\n";
    } else {
        out << version << " " << status_code << " " << reason_phrase << "\n";
    }
    for (const auto& h : headers) {
        out << h.first << ": " << h.second << "\n";
    }
    return out.str();
}
