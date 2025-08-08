#include "config/interface.h"
#include <fstream>
#include <iostream>
#include <filesystem>
#include <unistd.h> // readlink on Linux

namespace config {

// Helper: get directory where the executable resides
static std::string get_executable_dir() {
    char buf[1024];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len != -1) {
        buf[len] = '\0';
        return std::filesystem::path(buf).parent_path().string();
    }
    return ".";
}

// Default constructor - load from build/config/interface.cfg
Interface::Interface() {
    std::string default_path = get_executable_dir() + "/config/interface.cfg";
    load_config(default_path);
}

// Constructor with a custom config path
Interface::Interface(const std::string& config_path) {
    load_config(config_path);
}

// Internal config loader
void Interface::load_config(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        std::cerr << "[-] Config file not found: " << path << "\n";
        interface_name = "eth0"; // fallback
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.find("interface=") == 0) {
            interface_name = line.substr(10); // after "interface="
            return;
        }
    }

    // If no valid line found
    interface_name = "eth0";
}

std::string Interface::get_interface() const {
    return interface_name;
}

} // namespace config
