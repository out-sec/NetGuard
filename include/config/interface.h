#ifndef CONFIG_INTERFACE_H
#define CONFIG_INTERFACE_H

#include <string>

namespace config {

class Interface {
public:
    explicit Interface(const std::string& config_path = "config/interface.cfg");

    // Returns the interface name selected by user
    std::string get_interface() const;

private:
    std::string interface_name;
    void load_config(const std::string& path);
};

} // namespace config

#endif // CONFIG_INTERFACE_H
