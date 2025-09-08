#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include "utils/decHttp.h"   // for utils::HTTPDecodedData

struct Rule {
    std::string action;    // alert | block | log
    std::string protocol;  // tcp | udp | any
    std::string src_ip;    // "any" or literal
    std::string src_port;  // "any" or literal number
    std::string dst_ip;    // "any" or literal
    std::string dst_port;  // "any" or literal number
    std::string content;   // keyword to match in HTTP (headers/body/request-line)
    std::string msg;       // message
    int         sid = 0;   // rule id
    bool        nocase = false; // if true, case-insensitive content match
};

// Loads rules from "rules.rules" (Snort-like). If not found, returns empty.
std::vector<Rule> load_rules(const std::string& path = "rules.rules");

// Applies rules to one HTTP message (passive — logs/alerts to stdout).
void apply_rules(const std::vector<Rule>& rules,
                 const utils::HTTPDecodedData& http,
                 const std::string& src_ip, uint16_t src_port,
                 const std::string& dst_ip, uint16_t dst_port);
