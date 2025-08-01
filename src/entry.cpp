#include "config/interface.h"
#include "parsers/ethernet.h"
#include "parsers/ipv4.h"
#include "utils/decIPv4.h"

#include <iostream>
#include <unistd.h>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <iomanip>

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

    // Step 2: Capture and parse packets
    uint8_t buffer[65536];
    while (true) {
        ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if (len < 0) {
            perror("[-] Packet receive failed");
            break;
        }

        packet_number++;

        // Step 3: Parse Ethernet frame (which dispatches to IPv4, etc.)
        parsers::EthernetHeader eth = parsers::parse_ethernet_header(buffer, len);

        if (eth.eth_proto == "IPv4") {
            parsers::IPv4Header ipv4 = parsers::parse_ipv4_header(eth.payload, eth.payload_len);


            std::cout << "[+] Packet #" << packet_number << parsers::ipv4_to_string(ipv4.src_ip) << " ==> " << parsers::ipv4_to_string(ipv4.dest_ip) << "\n";
            std::cout << "  Ethernet Frame:\n";
            std::cout << "      Destination MAC: " << eth.dest_mac_str << "\n";
            std::cout << "      Source MAC:      " << eth.src_mac_str << "\n";
            std::cout << "      EtherType:       " << eth.eth_type_str << " (" << eth.eth_proto << ")\n";
            std::cout << "  IPv4 Packet:\n";
            std::cout << "      Version:         " << decoders::version_to_string(static_cast<int>(ipv4.version)) << "\n";
            std::cout << "      Internet Header Length: " << decoders::ihl_to_string(static_cast<int>(ipv4.ihl)) << "\n";
            std::cout << "      Type Of Service: " << (static_cast<int>(ipv4.tos)) << "\n";
            std::cout << "      Total Length:    " << decoders::total_length_to_string(ipv4.total_length) << "\n";
            std::cout << "      Identification:  " << decoders::identification_to_string(ipv4.identification) << "\n";
            std::cout << "      Flags:           " << decoders::flags_to_string((ipv4.flags_fragment_offset)) << "\n";
            std::cout << "      Fragment Offset: " << decoders::fragment_offset_to_string((ipv4.flags_fragment_offset)) << "\n";
            std::cout << "      Time To Live:    " << decoders::ttl_to_string(static_cast<int>(ipv4.ttl)) << "\n";
            std::cout << "      Protocol:        " << decoders::protocol_to_string(static_cast<int>(ipv4.protocol)) << "\n";
            std::cout << "      Header Checksum: " << decoders::checksum_to_string(ipv4.header_checksum)<< "\n";
            std::cout << "      Source IP:       " << parsers::ipv4_to_string(ipv4.src_ip) << "\n";
            std::cout << "      Destination IP:  " << parsers::ipv4_to_string(ipv4.dest_ip) << "\n";
            std::cout << "      Payload Length:  " << ipv4.payload_length << " bytes\n";
            if (ipv4.payload_length > 0) {
                std::cout << "      Payload (hex):   \n";
                std::cout << "        ";
                for (size_t i = 0; i < ipv4.payload_length && i < 64; ++i) {
                    std::cout << std::hex << std::setw(2) << std::setfill('0')
                            << static_cast<int>(ipv4.payload[i]) << " ";
                    if ((i + 1) % 16 == 0) std::cout << "\n      ";
                }
                std::cout << "\n";
            } else {
                std::cout << "      No Payload\n";
            }
        }

        

    }

    close(sock);
    return 0;
}
