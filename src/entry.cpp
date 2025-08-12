#include "config/interface.h"
#include "parsers/ethernet.h"
#include "parsers/ipv4.h"
#include "parsing/http_parser.h"
#include "utils/decIPv4.h"
#include "parsers/arp.h"
#include "utils/decEthernet.h"

#include <iostream>
#include <unistd.h>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <iomanip>

#pragma pack(push, 1)
struct TCPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset; // upper 4 bits = header length
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
};
#pragma pack(pop)

int run_entry() {
    // Step 1: Create and bind socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("[-] Failed to create socket");
        return 1;
    }

    config::Interface iface;
    std::string iface_name = iface.get_interface();

    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, iface_name.c_str(), iface_name.length()) < 0) {
        perror(("[-] Failed to bind to interface: " + iface_name).c_str());
        close(sock);
        return 1;
    }

    std::cout << "[+] Listening on interface: " << iface_name << "\n";

    int packet_number = 0;
    uint8_t buffer[65536];

    // Step 2: Capture and parse packets
    while (true) {
        ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if (len < 0) {
            perror("[-] Packet receive failed");
            break;
        }

        packet_number++;

        // Step 3: Parse Ethernet frame
        parsers::EthernetHeader eth = parsers::parse_ethernet_header(buffer, len);

        if (eth.eth_proto == "IPv4") {
            parsers::IPv4Header ipv4 = parsers::parse_ipv4_header(eth.payload, eth.payload_len);

            if (ipv4.protocol == 6 /* TCP */ && ipv4.payload_length > sizeof(TCPHeader)) {
                const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(ipv4.payload);
                uint16_t src_port = ntohs(tcp->src_port);
                uint16_t dst_port = ntohs(tcp->dest_port);

                size_t tcp_header_len = ((tcp->data_offset >> 4) & 0x0F) * 4;
                if (tcp_header_len < sizeof(TCPHeader) || tcp_header_len > ipv4.payload_length) {
                    continue; // malformed packet
                }

                const uint8_t* tcp_payload = ipv4.payload + tcp_header_len;
                size_t tcp_payload_len = ipv4.payload_length - tcp_header_len;

                // Only parse HTTP (port 80)
                if (tcp_payload_len > 0 && (src_port == 80 || dst_port == 80)) {
                    std::string payload_str(reinterpret_cast<const char*>(tcp_payload), tcp_payload_len);
                    parsing::HTTPParser parser;
                    parser.parse(payload_str);

                    std::cout << "[HTTP] Packet #" << packet_number << " "
                              << parsers::ipv4_to_string(ipv4.src_ip) << ":" << src_port
                              << " ==> "
                              << parsers::ipv4_to_string(ipv4.dest_ip) << ":" << dst_port
                              << "\n";
                }
            }
        }
        else if (eth.eth_proto == "ARP") {
            parsers::ARPHeader arp = parsers::parse_arp_header(eth.payload, eth.payload_len);
            std::cout << "[+] ARP " << arp.sender_ip << " ==> " << arp.target_ip << "\n";
        }
    }

    close(sock);
    return 0;
}
