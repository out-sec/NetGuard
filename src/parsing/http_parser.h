#pragma once
#include <string>

namespace parsing {

class HTTPParser {
public:
    void parse(const std::string& payload);
};

} // namespace parsing
