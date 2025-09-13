// src/entry.cpp (merged: original functionality restored + FTP tracking)
#include "config/interface.h"
#include "parsers/ethernet.h"
#include "parsers/ipv4.h"
#include "utils/decIPv4.h"
#include "parsers/arp.h"
#include "utils/decEthernet.h"
#include "parsers/tcp.h"
#include "parsers/http.h"
#include "utils/decHttp.h"

#include "parsers/ftp.h"

#include "rules/rules.h"

#include <iostream>
#include <unistd.h>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <iomanip>

int run_entry() {
    // Create and bind socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("[-] Failed to create socket");
        return 1;
    }

    // Load interface from config file in build/config/interface.cfg
    config::Interface iface;
    std::string iface_name = iface.get_interface();

    // SO_BINDTODEVICE expects a char*; include terminating NUL
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, iface_name.c_str(), iface_name.length() + 1) < 0) {
        perror(("[-] Failed to bind to interface: " + iface_name).c_str());
        close(sock);
        return 1;
    }

    std::cout << "[+] Listening on interface: " << iface_name << "\n";

    int packet_number = 0;

    // Step 2: Capture and parse packets
    uint8_t buffer[65536];

    // FTP session tracker (learns PORT/PASV/EPRT/EPSV and correlates data flows)
    parsers::FTPSessionTracker ftp_tracker;

    while (true) {
        ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if (len < 0) {
            perror("[-] Packet receive failed");
            break;
        }

        packet_number++;

        // Step 3: Parse Ethernet frame (which dispatches to IPv4, etc.)
        parsers::EthernetHeader eth = parsers::parse_ethernet_header(buffer, static_cast<size_t>(len));

        if (eth.eth_proto == "IPv4") {
            parsers::IPv4Header ipv4 = parsers::parse_ipv4_header(eth.payload, eth.payload_len);

            std::cout << "[+] Packet # " << packet_number << " " << parsers::ipv4_to_string(ipv4.src_ip) << " ==> " << parsers::ipv4_to_string(ipv4.dest_ip) << "\n";
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
            std::cout << "      Header Checksum: " << decoders::checksum_to_string(ipv4.header_checksum) << "\n";
            std::cout << "      Source IP:       " << parsers::ipv4_to_string(ipv4.src_ip) << "\n";
            std::cout << "      Destination IP:  " << parsers::ipv4_to_string(ipv4.dest_ip) << "\n";
            std::cout << "      Payload Length:  " << ipv4.payload_length << " bytes\n";

            // If TCP (protocol number 6)
            if (ipv4.protocol == 6) {
                parsers::TCPHeader tcp = parsers::parse_tcp_header(ipv4.payload, ipv4.payload_length);

                std::cout << "  TCP Packet: \n";
                std::cout << "      Source Port: " << tcp.src_port << "\n";
                std::cout << "      Destination Port: " << tcp.dest_port << "\n";
                std::cout << "      Sequence Number: " << tcp.seq_num << "\n";
                std::cout << "      Acknowledgment Number: " << tcp.ack_num << "\n";
                std::cout << "      Data Offset (header length in bytes): " << (tcp.data_offset * 4) << "\n";

                // Print flags individually
                std::cout << "      Flags:\n";
                std::cout << "        NS:  " << tcp.ns_flag << "\n";
                std::cout << "        CWR: " << tcp.cwr_flag << "\n";
                std::cout << "        ECE: " << tcp.ece_flag << "\n";
                std::cout << "        URG: " << tcp.urg_flag << "\n";
                std::cout << "        ACK: " << tcp.ack_flag << "\n";
                std::cout << "        PSH: " << tcp.psh_flag << "\n";
                std::cout << "        RST: " << tcp.rst_flag << "\n";
                std::cout << "        SYN: " << tcp.syn_flag << "\n";
                std::cout << "        FIN: " << tcp.fin_flag << "\n";

                std::cout << "      Window Size: " << tcp.window_size << "\n";
                std::cout << "      Checksum: " << decoders::checksum_to_string(tcp.checksum) << "\n";
                std::cout << "      Urgent Pointer: " << tcp.urgent_pointer << "\n";
                std::cout << "      Options Length: " << static_cast<int>(tcp.options_length) << "\n";
           
                // --- HTTP Parsing ---
                parsers::HTTPHeader http = parsers::parse_http_header(tcp.payload, tcp.payload_length);
                if (http.is_http) {
                std::cout << "[HTTP] Parsed Request/Response:\n"
              << http.to_string() << std::endl;
}

                // Decode HTTP fully (for rule engine)
                if (auto decoded = utils::decode_http(tcp.payload, tcp.payload_length)) {
                auto decoded_http = *decoded;

                // Load rules once (static means loaded only first time)
                static std::vector<Rule> rules = load_rules("../rules/rules.rules");

                // Get IPs/ports for the rule engine
               const std::string src_ip_str = parsers::ipv4_to_string(ipv4.src_ip);
                const std::string dst_ip_str = parsers::ipv4_to_string(ipv4.dest_ip);

               // Apply rules
               //std::cout << "[DEBUG] Decoded HTTP: " << decoded_http << std::endl;
              apply_rules(rules, decoded_http,
                src_ip_str, tcp.src_port,
                dst_ip_str, tcp.dest_port);
}


                if (tcp.options_length > 0) {
                    std::cout << "      Options (hex): ";
                    for (size_t i = 0; i < tcp.options.size(); ++i) {
                        std::cout << std::hex << std::setw(2) << std::setfill('0')
                                  << static_cast<int>(tcp.options[i]) << " ";
                    }
                    std::cout << std::dec << "\n"; // reset stream to decimal
                } else {
                    std::cout << "      No TCP Options\n";
                }

                // --- FTP handling (control + data correlation) ---
                if (tcp.payload_length > 0 && tcp.payload != nullptr) {
                    parsers::FourTuple flow{
                        parsers::ipv4_to_string(ipv4.src_ip),
                        tcp.src_port,
                        parsers::ipv4_to_string(ipv4.dest_ip),
                        tcp.dest_port
                    };

                    bool is_ftp_control = (tcp.src_port == 21 || tcp.dest_port == 21);
                    bool from_server = (tcp.src_port == 21);

                    if (is_ftp_control) {
                        // mark/control the flow and parse control payload
                        ftp_tracker.track_control(flow);
                        parsers::FTPCommand cmd = ftp_tracker.on_control_payload(flow, tcp.payload, tcp.payload_length, from_server);

                        std::cout << "[FTP CTRL] "
                                  << flow.src_ip << ":" << flow.src_port << " -> "
                                  << flow.dst_ip << ":" << flow.dst_port << " | "
                                  << cmd.to_string() << "\n";
                        //break;
                    } else {
                        // not control; check whether this matches a learned data flow
                        if (ftp_tracker.is_ftp_data_flow(flow)) {
                            ftp_tracker.remember_data_flow(flow);
                            std::cout << "[FTP DATA] "
                                      << flow.src_ip << ":" << flow.src_port << " -> "
                                      << flow.dst_ip << ":" << flow.dst_port
                                      << " | " << tcp.payload_length << " bytes\n";
                            //break;
                        }
                    }
                } // end FTP handling

                // HTTP parsing if any TCP payload exists
                if (tcp.payload_length > 0 && tcp.payload != nullptr) {
                    parsers::HTTPHeader http = parsers::parse_http_header(tcp.payload, tcp.payload_length);
                    if (http.is_http) {
                        std::cout << "[HTTP] Parsed Request/Response:\n"
                                  << http.to_string() << std::endl;
                    }
                }
            } // end if tcp
        } // end if IPv4
        else if (eth.eth_proto == "ARP") {
            parsers::ARPHeader arp = parsers::parse_arp_header(eth.payload, eth.payload_len);

            std::cout << "[+] Packet #" << packet_number << " ARP " << arp.sender_ip << " ==> " << arp.target_ip << "\n";
            std::cout << "  Ethernet Frame:\n";
            std::cout << "      Destination MAC: " << eth.dest_mac_str << "\n";
            std::cout << "      Source MAC:      " << eth.src_mac_str << "\n";
            std::cout << "      EtherType:       " << eth.eth_type_str << " (" << eth.eth_proto << ")\n";

            std::cout << "  ARP Packet:\n";
            std::cout << "      Hardware Type:   " << arp.hardware_type_str << "\n";
            std::cout << "      Protocol Type:   " << arp.protocol_type_str << "\n";
            std::cout << "      Hardware Size:   " << static_cast<int>(arp.hardware_size) << "\n";
            std::cout << "      Protocol Size:   " << static_cast<int>(arp.protocol_size) << "\n";
            std::cout << "      Operation:       " << ((arp.operation == 1) ? "Request (1)" : "Reply (2)") << "\n";

            std::cout << "      Sender MAC:      ";
            for (const auto& byte : arp.sender_mac)
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << ":";
            std::cout << std::dec << "\b \n"; // Remove last colon and reset to decimal

            std::cout << "      Sender IP:       " << arp.sender_ip << "\n";

            std::cout << "      Target MAC:      ";
            for (const auto& byte : arp.target_mac)
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << ":";
            std::cout << std::dec << "\b \n";

            std::cout << "      Target IP:       " << arp.target_ip << "\n";
        } // end else if ARP

    } // end while

    close(sock);
    return 0;
}
