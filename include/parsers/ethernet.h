#ifndef ETHERNET_H
#define ETHERNET_H

#include <cstdint>
#include <string>
#include <netinet/if_ether.h> // For ETH_P_ALL
#include <netinet/in.h>
#include <sys/socket.h>

namespace parsers {

struct EthernetHeader {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;

    std::string to_string() const;
};

// Initializes and returns a raw socket for capturing Ethernet frames
int create_raw_socket();

// Parses and prints the Ethernet frame
bool parse_ethernet_frame(const uint8_t* buffer, ssize_t length);

} // namespace parsers

#endif // ETHERNET_H
