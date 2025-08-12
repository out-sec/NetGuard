#include "parsing/http_parser.h"
#include <iostream>
#include <sstream>
#include <string>
#include <algorithm>`



namespace parsing {

void HTTPParser::parse(const std::string& payload) {
    // Only handle if it's an HTTP request (simple check)
    if (payload.rfind("GET ", 0) != 0 &&
        payload.rfind("POST ", 0) != 0 &&
        payload.rfind("HEAD ", 0) != 0 &&
        payload.rfind("PUT ", 0) != 0 &&
        payload.rfind("DELETE ", 0) != 0) {
        return; // Not an HTTP request we care about
    }

    std::istringstream stream(payload);
    std::string line;

    // First line: Request method + path + HTTP version
    if (std::getline(stream, line)) {
        std::cout << "[HTTP] Request: " << line << "\n";
    }

    // Parse headers
    std::string host, userAgent;
    while (std::getline(stream, line) && line != "\r") {
        if (line.find("Host:") == 0) {
            host = line.substr(6);
            host.erase(host.find_last_not_of("\r\n") + 1);
        }
        else if (line.find("User-Agent:") == 0) {
            userAgent = line.substr(12);
            userAgent.erase(userAgent.find_last_not_of("\r\n") + 1);
        }
    }

    if (!host.empty()) {
        std::cout << "       Host: " << host << "\n";
    }
    if (!userAgent.empty()) {
        std::cout << "       User-Agent: " << userAgent << "\n";
    }
    std::cout << "--------------------------------------------\n";
}

} // namespace parsing
