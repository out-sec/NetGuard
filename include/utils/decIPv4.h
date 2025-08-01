#ifndef UTILS_DEC_IPV4_H
#define UTILS_DEC_IPV4_H

#include <string>
#include "parsers/ipv4.h"

namespace decoders {

std::string version_to_string(uint8_t version);
std::string ihl_to_string(uint8_t ihl);
std::string tos_to_string(uint8_t tos);
std::string total_length_to_string(uint16_t total_length);
std::string identification_to_string(uint16_t id);
std::string flags_to_string(uint16_t flags_fragment_offset);
std::string fragment_offset_to_string(uint16_t flags_fragment_offset);
std::string ttl_to_string(uint8_t ttl);
std::string protocol_to_string(uint8_t protocol);
std::string checksum_to_string(uint16_t checksum);
std::string ip_to_string(uint32_t ip);

}

#endif // DEC_IPV4_H
