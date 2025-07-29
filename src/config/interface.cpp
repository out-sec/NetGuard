#include "config/interface.h"
#include <fstream>
#include <sstream>
#include <iostream>

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
    while (std::getline(file, line)) {
        if (line.find("interface=") == 0) {
            interface_name = line.substr(10); // length of "interface="
            return;
        }
    }

    // Default if not found
    interface_name = "eth0";
}

std::string Interface::get_interface() const {
    return interface_name;
}

} // namespace config
