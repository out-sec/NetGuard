#ifndef PARSERS_TCP_H
#define PARSERS_TCP_H

#include <cstdint>
#include <string>
#include <vector>

namespace parsers {

    // Full TCP Header Structure
    struct TCPHeader {
        uint16_t src_port;       // Source Port
        uint16_t dest_port;      // Destination Port
        uint32_t seq_num;        // Sequence Number
        uint32_t ack_num;        // Acknowledgment Number

        // First byte after ack_num is split into:
        uint8_t data_offset;     // 4 bits: Data Offset (header length in 32-bit words)
        uint8_t reserved;        // 3 bits: Reserved (must be zero in normal traffic)
        bool ns_flag;            // 1 bit: NS (Nonce Sum) flag

        // Second byte: TCP flags
        bool cwr_flag;
        bool ece_flag;
        bool urg_flag;
        bool ack_flag;
        bool psh_flag;
        bool rst_flag;
        bool syn_flag;
        bool fin_flag;

        uint16_t window_size;    // Window Size
        uint16_t checksum;       // Checksum
        uint16_t urgent_pointer; // Urgent Pointer

        // TCP Options (if present)
        std::vector<uint8_t> options; // Raw options bytes
        uint8_t options_length;       // Length in bytes

        // Payload
        const uint8_t* payload = nullptr; // Pointer to payload data
        uint16_t payload_length = 0;      // Length of the payload

        std::string to_string() const;
    };

    // Function to parse TCP header from a buffer
    TCPHeader parse_tcp_header(const uint8_t* buffer, std::size_t length);

} // namespace parsers

#endif // PARSERS_TCP_H
