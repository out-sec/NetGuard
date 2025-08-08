#ifndef CONFIG_INTERFACE_H
#define CONFIG_INTERFACE_H

#include <string>

namespace config {

class Interface {
public:
    // Default constructor: loads config from build/config/interface.cfg
    Interface();

    // Constructor: load config from a specific file path
    explicit Interface(const std::string &config_path);

    // Returns the interface name selected by the user
    std::string get_interface() const;

private:
    std::string interface_name;
    void load_config(const std::string& path);
};

} // namespace config

#endif // CONFIG_INTERFACE_H
