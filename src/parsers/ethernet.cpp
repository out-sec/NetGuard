#include "parsers/ethernet.h"
#include "utils/bytes.h"
#include "utils/decEthernet.h"

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

    std::cout << eth.to_string() << "\n\n";

    uint16_t eth_type = ntohs(eth.eth_type);
    const uint8_t* payload = buffer + 14;
    ssize_t payload_len = length - 14;

    switch (eth_type) {
        case 0x0800: // IPv4
            std::cout << "Ethernet Protocol: IPv4\n\n";
            // TODO: parse_ipv4(payload, payload_len);
            break;
        case 0x0806: // ARP
            std::cout << "Ethernet Protocol: ARP\n\n";
            break;
        case 0x86DD: // IPv6
            std::cout << "Ethernet Protocol: IPv6\n\n";
            break;
        default:
            std::cout << "  -> Unknown or unsupported EtherType\n\n";
            break;
    }

    return true;
}

} // namespace parsers
