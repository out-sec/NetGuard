#include "parsers/tcp.h"

#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cstring>
#include <arpa/inet.h>
#include <iostream>

namespace parsers {

    TCPHeader parse_tcp_header(const uint8_t* buffer, std::size_t length) {
        TCPHeader tcp{};

        // Minimum TCP header size is 20 bytes (without options)
        if (length < 20) {
            std::cerr << "Buffer too short for TCP header\n";
            return tcp;
        }

        // Parse fixed header fields
        tcp.src_port = ntohs(*reinterpret_cast<const uint16_t*>(buffer));
        tcp.dest_port = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 2));
        tcp.seq_num = ntohl(*reinterpret_cast<const uint32_t*>(buffer + 4));
        tcp.ack_num = ntohl(*reinterpret_cast<const uint32_t*>(buffer + 8));

        uint8_t data_offset_reserved_ns = buffer[12];
        uint8_t flags_byte = buffer[13];

        // Extract Data Offset (upper 4 bits) - number of 32-bit words
        tcp.data_offset = (data_offset_reserved_ns >> 4) & 0x0F;  
        // Calculate header length in bytes
        size_t header_length_bytes = tcp.data_offset * 4;

        // Extract Reserved (3 bits)
        tcp.reserved = (data_offset_reserved_ns >> 1) & 0x07;

        // Extract NS flag (least significant bit of byte 12)
        tcp.ns_flag = (data_offset_reserved_ns & 0x01) != 0;

        // Extract flags (byte 13)
        tcp.cwr_flag = (flags_byte & 0x80) != 0;
        tcp.ece_flag = (flags_byte & 0x40) != 0;
        tcp.urg_flag = (flags_byte & 0x20) != 0;
        tcp.ack_flag = (flags_byte & 0x10) != 0;
        tcp.psh_flag = (flags_byte & 0x08) != 0;
        tcp.rst_flag = (flags_byte & 0x04) != 0;
        tcp.syn_flag = (flags_byte & 0x02) != 0;
        tcp.fin_flag = (flags_byte & 0x01) != 0;

        tcp.window_size = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 14));
        tcp.checksum = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 16));
        tcp.urgent_pointer = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 18));

        // Validate header length
        if (length < header_length_bytes) {
            std::cerr << "TCP header length field exceeds buffer length\n";
            return tcp;
        }

        // Calculate options length (header length minus fixed 20 bytes)
        tcp.options_length = static_cast<uint8_t>(header_length_bytes - 20);

        // Copy options if present
        if (tcp.options_length > 0) {
            tcp.options.assign(buffer + 20, buffer + 20 + tcp.options_length);
        }

        // Set payload pointer and length
        tcp.payload = buffer + header_length_bytes;
        tcp.payload_length = static_cast<uint16_t>(length - header_length_bytes);

        return tcp;
    }

} // namespace parsers
