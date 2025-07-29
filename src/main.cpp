#include "parsers/ethernet.h"
#include <iostream>
#include <vector>
#include <unistd.h>

// Entry point for the Ethernet frame parser
// This program creates a raw socket to listen for Ethernet frames
// and parses them using the functions defined in the parsers and utils namespaces.
int main() {
    int sock = parsers::create_raw_socket();
    if (sock < 0) return 1;

    std::cout << "Listening for Ethernet frames...\n";

    while (true) {
        std::vector<uint8_t> buffer(65536);
        ssize_t length = recv(sock, buffer.data(), buffer.size(), 0);
        if (length < 0) {
            perror("recv failed");
            break;
        }

        parsers::parse_ethernet_frame(buffer.data(), length);
    }

    close(sock);
    return 0;
}
