#include "config/interface.h"
#include <fstream>
#include <iostream>
#include <string>
#include <algorithm>

namespace config {

Interface::Interface(const std::string& config_path) {
    load_config(config_path);
}

void Interface::load_config(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        std::cerr << "Config file not found: " << path << "\n";
        interface_name = "eth0"; // Default
        return;
    }

    std::string line;
    if (std::getline(file, line)) {
        // Trim whitespace
        line.erase(line.begin(), std::find_if(line.begin(), line.end(), [](unsigned char ch) {
            return !std::isspace(ch);
        }));
        line.erase(std::find_if(line.rbegin(), line.rend(), [](unsigned char ch) {
            return !std::isspace(ch);
        }).base(), line.end());

        if (!line.empty()) {
            interface_name = line;
            return;
        }
    }

    // Default if file empty or invalid
    interface_name = "eth0";
}

std::string Interface::get_interface() const {
    return interface_name;
}

} // namespace config
