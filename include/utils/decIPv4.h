#ifndef UTILS_DEC_IPV4_H
#define UTILS_DEC_IPV4_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <optional>
#include <stdexcept>
#include <arpa/inet.h> // For ntohs

namespace utils {
    // Function for decoding the IPv4 Version
    std::string decode_ipv4_version(uint8_t version) {
        switch (version) {
            case 4: return "IPv4";
            case 6: return "IPv6";
            default: return "Unknown Version";
        }
    }

    // Function for decoding the IPv4 Header Length
    std::string decode_ipv4_header_length(uint8_t ihl) {
        if (ihl < 5) {
            return "Invalid Header Length";
        }
        if (ihl == 5) {
            return "20 bytes"; // 5 * 4
        } else {
            // Convert to bytes
            return std::to_string(ihl * 4) + " bytes";
        }
        
    }

    // Calculates and returns the decimal total length from an IPv4 packet buffer
    /*
        Implementation Note:
        This function reads the total length field from the IPv4 header, which is located at bytes 2 and 3 of the IPv4 header.
        The total length is stored in network byte order, so we use ntohs to convert it to host byte order.
        The function assumes that the buffer is at least 4 bytes long, which is the minimum size of an IPv4 header.
        If the buffer is shorter than 4 bytes, it returns 0 to indicate an invalid
        or incomplete packet.
        This function is useful for determining the size of the entire IPv4 packet, including both the
        header and the payload, which is essential for parsing and processing network packets correctly.

        Usage:
        uint16_t totalLen = get_ipv4_total_length(packet, sizeof(packet));
    */

    uint16_t get_ipv4_total_length(const uint8_t* buffer, size_t length) {
        // IPv4 header must be at least 4 bytes to access total_length (starts at byte 2)
        if (length < 4) return 0;

        // Read 2 bytes from offset 2, convert from network byte order to host byte order
        return ntohs(*reinterpret_cast<const uint16_t*>(buffer + 2));
    }

    // Function to decode the Identification field of an IPv4 header
    // and return its decimal value
    uint16_t decode_ipv4_identification(const uint8_t* buffer, size_t length) {
        if (length < 6) return 0;  // Not enough bytes to access the identification field

        // Read 2 bytes starting from byte offset 4 (identification field)
        uint16_t network_value = *reinterpret_cast<const uint16_t*>(buffer + 4);
        
        // Convert from network byte order (big-endian) to host byte order
        return ntohs(network_value);
    }

    
}

#endif