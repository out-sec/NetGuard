#include "parsers/ethernet.h"
#include "utils/bytes.h"
#include "utils/decEthernet.h"
#include "config/interface.h"

#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>

namespace parsers {

std::string EthernetHeader::to_string() const {
    std::ostringstream oss;
    oss << "Ethernet Frame:\n"
        << "  Destination MAC: " << utils::mac_to_string(dest_mac) << "\n"
        << "  Source MAC:      " << utils::mac_to_string(src_mac) << "\n"
        << "  EtherType:       0x" << std::hex << ntohs(eth_type);
    return oss.str();
}

int create_raw_socket() {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1) {
        perror("Socket creation failed");
        return -1;
    }

    // Load interface from config
    config::Interface iface;
    std::string iface_name = iface.get_interface();

    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, iface_name.c_str(), iface_name.length()) < 0) {
        perror(("Binding to interface failed: " + iface_name).c_str());
        close(sock);
        return -1;
    }

    std::cout << "[+] Bound to interface: " << iface_name << "\n";
    return sock;
}


bool parse_ethernet_frame(const uint8_t* buffer, ssize_t length) {
    if (!utils::is_valid_ethernet_frame(buffer, length))
        return false;

    EthernetHeader eth;

    // Use utility functions to extract fields
    auto dest_mac_str = utils::get_dest_mac(buffer, length);
    auto src_mac_str  = utils::get_src_mac(buffer, length);
    auto eth_type_opt = utils::get_ethertype(buffer, length);

    if (!dest_mac_str || !src_mac_str || !eth_type_opt)
        return false;

    // Reconstruct the EthernetHeader
    std::memcpy(eth.dest_mac, buffer, 6);
    std::memcpy(eth.src_mac, buffer + 6, 6);
    eth.eth_type = htons(*eth_type_opt); // Store in network byte order

    eth.payload = buffer + 14;
    eth.payload_len = length - 14;

    std::cout << eth.to_string() << '\n';
    // std::cout << eth.payload_as_hex() << "\n";

    uint16_t eth_type = ntohs(eth.eth_type);



    switch (eth_type) {
        case 0x0800: // IPv4
            std::cout << "  Ethernet Protocol: IPv4\n";
            // TODO: parse_ipv4(payload, payload_len);
            break;
        case 0x0806: // ARP
            std::cout << "  Ethernet Protocol: ARP\n";
            break;
        case 0x86DD: // IPv6
            std::cout << "  Ethernet Protocol: IPv6\n";
            break;
        default:
            std::cout << "  Unknown or unsupported EtherType\n";
            break;
    }

    if (eth.payload_len > 0)
        std::cout << eth.payload_as_hex() << "\n";
    else
        std::cout << "Empty Payload\n";

    // Return true to indicate successful parsing
    std::cout << "\n";
    return true;
}

std::string EthernetHeader::payload_as_hex() const {
    std::ostringstream oss;
    oss << "  Payload (" << payload_len << " bytes):\n    ";

    for (int i = 0; i < payload_len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(payload[i]) << " ";
        if ((i + 1) % 16 == 0) oss << "\n    ";
    }

    return oss.str();
}

} // namespace parsers
