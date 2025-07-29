#include "parsers/ethernet.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

namespace parsers {

std::string mac_to_string(const uint8_t* mac) {
    std::ostringstream oss;
    for (int i = 0; i < 6; ++i) {
        if (i) oss << ":";
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
    }
    return oss.str();
}

std::string EthernetHeader::to_string() const {
    std::ostringstream oss;
    oss << "Ethernet Frame:\n"
        << "  Destination MAC: " << mac_to_string(dest_mac) << "\n"
        << "  Source MAC:      " << mac_to_string(src_mac) << "\n"
        << "  EtherType:       0x" << std::hex << ntohs(eth_type);
    return oss.str();
}

int create_raw_socket() {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1) {
        perror("Socket creation failed");
        return -1;
    }
    return sock;
}

bool parse_ethernet_frame(const uint8_t* buffer, ssize_t length) {
    if (length < sizeof(EthernetHeader)) return false;

    EthernetHeader eth;
    std::memcpy(&eth.dest_mac, buffer, 6);
    std::memcpy(&eth.src_mac, buffer + 6, 6);
    std::memcpy(&eth.eth_type, buffer + 12, 2);

    std::cout << eth.to_string() << "\n\n";
    return true;
}

} // namespace parsers
