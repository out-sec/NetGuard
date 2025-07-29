#include "parsers/ethernet.h"
#include <iostream>
#include <vector>
#include <unistd.h>

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
