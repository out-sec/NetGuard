#include "rules/rules.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cctype>

// -------- Utility functions --------
static inline std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}
static inline std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return (char)std::tolower(c); });
    return s;
}
static bool equals_ci(const std::string& a, const std::string& b) {
    return to_lower(a) == to_lower(b);
}
static bool starts_with(const std::string& s, const std::string& p) {
    return s.rfind(p, 0) == 0;
}

static bool port_match(const std::string& want, uint16_t have) {
    if (want == "any" || want.empty()) return true;
    return want == std::to_string(have);
}
static bool ip_match(const std::string& want, const std::string& have) {
    if (want == "any" || want.empty()) return true;
    return want == have;
}

// -------- Options parser --------
// Parse things like: content:"bad"; msg:"..."; sid:1001; nocase;
static void parse_options(const std::string& options, Rule& r) {
    size_t i = 0;
    while (i < options.size()) {
        size_t sc = options.find(';', i);
        std::string tok = trim(options.substr(i, (sc==std::string::npos ? options.size() : sc) - i));
        if (!tok.empty()) {
            size_t col = tok.find(':');
            std::string key, val;
            if (col == std::string::npos) {
                key = trim(tok);
                val.clear();
            } else {
                key = trim(tok.substr(0, col));
                val = trim(tok.substr(col + 1));
            }

            // remove quotes if present
            if (!val.empty() && val.front() == '\"' && val.back() == '\"' && val.size() >= 2) {
                val = val.substr(1, val.size()-2);
            }

            if (equals_ci(key, "content"))      r.content = val;
            else if (equals_ci(key, "msg"))     r.msg = val;
            else if (equals_ci(key, "sid"))     r.sid = std::atoi(val.c_str());
            else if (equals_ci(key, "nocase"))  r.nocase = true;
            // ignore unknowns for now (depth, offset, etc.)
        }

        if (sc == std::string::npos) break;
        i = sc + 1;
    }
}

// -------- Rule loader --------
std::vector<Rule> load_rules(const std::string& path) {
    std::vector<Rule> rules;
    std::ifstream f(path);
    if (!f.is_open()) {
        std::cerr << "[rules] Could not open " << path << " (no rules loaded)\n";
        return rules;
    }

    std::cout << "[rules] Loading rules from " << path << "...\n";

    std::string line;
    int line_no = 0;
    while (std::getline(f, line)) {
        ++line_no;
        std::string s = trim(line);

        // strip comments
        size_t hash = s.find('#');
        if (hash != std::string::npos) s = trim(s.substr(0, hash));
        size_t dslash = s.find("//");
        if (dslash != std::string::npos) s = trim(s.substr(0, dslash));
        if (s.empty()) continue;

        // find options region in parentheses
        size_t lp = s.find('(');
        size_t rp = s.rfind(')');
        if (lp == std::string::npos || rp == std::string::npos || rp <= lp) {
            std::cerr << "[rules] Skipping malformed line " << line_no << "\n";
            continue;
        }
        std::string head = trim(s.substr(0, lp));
        std::string opts = trim(s.substr(lp + 1, rp - lp - 1));

        // parse head: action protocol src_ip src_port -> dst_ip dst_port
        std::istringstream hs(head);
        Rule r;
        std::string arrow;
        hs >> r.action >> r.protocol >> r.src_ip >> r.src_port >> arrow >> r.dst_ip >> r.dst_port;

        if (r.action.empty() || r.protocol.empty() || arrow != "->" ||
            r.dst_ip.empty() || r.dst_port.empty()) {
            std::cerr << "[rules] Skipping malformed head on line " << line_no << "\n";
            continue;
        }

        // normalise
        r.action   = to_lower(r.action);
        r.protocol = to_lower(r.protocol);
        r.src_ip   = to_lower(r.src_ip);
        r.src_port = to_lower(r.src_port);
        r.dst_ip   = to_lower(r.dst_ip);
        r.dst_port = to_lower(r.dst_port);

        parse_options(opts, r);
        if (r.sid == 0) r.sid = 1000000 + (int)rules.size();

        rules.push_back(std::move(r));
        std::cout << "[rules] Loaded rule on line " << line_no
                  << ": " << r.msg << " (sid " << r.sid << ")\n";
    }

    std::cout << "[rules] Total loaded: " << rules.size() << "\n";
    return rules;
}

// -------- Rule applier --------
void apply_rules(const std::vector<Rule>& rules,
                 const utils::HTTPDecodedData& http,
                 const std::string& src_ip, uint16_t src_port,
                 const std::string& dst_ip, uint16_t dst_port) {
    // Build haystack: request/response line + headers + body
    std::string header_block;
    header_block.reserve(512);
    for (const auto& kv : http.headers) {
        header_block += kv.first;
        header_block += ": ";
        header_block += kv.second;
        header_block += "\n";
    }

    std::string start_line;
    if (http.is_request) {
        start_line = http.method + " " + http.path + " " + http.version;
    } else {
        start_line = http.version + " " + std::to_string(http.status_code) + " " + http.reason_phrase;
    }

    std::string haystack = start_line + "\n" + header_block + "\n" + http.body;
    haystack += "\n" + start_line;

    for (const auto& r : rules) {
        // protocol filter
        if (!(r.protocol == "any" || r.protocol == "tcp" || r.protocol == "http")) continue;

        // IP/port filters
        if (!ip_match(r.src_ip, src_ip)) continue;
        if (!ip_match(r.dst_ip, dst_ip)) continue;
        if (!port_match(r.src_port, src_port)) continue;
        if (!port_match(r.dst_port, dst_port)) continue;

        // content match
        bool matched = false;
        if (r.content.empty()) {
            matched = true; // match anything if no content specified
        } else {
            if (r.nocase) {
                std::string h = to_lower(haystack);
                std::string needle = to_lower(r.content);
                matched = (h.find(needle) != std::string::npos);
            } else {
                matched = (haystack.find(r.content) != std::string::npos);
            }
        }

        if (!matched) continue;

        // Action (passive for now)
        std::string label = (r.action == "block") ? "BLOCK" :
                            (r.action == "log")   ? "LOG"   : "ALERT";

        std::cout << "[" << label << "] sid=" << r.sid
                  << " msg=\"" << r.msg << "\" "
                  << src_ip << ":" << src_port << " -> "
                  << dst_ip << ":" << dst_port << "\n";
    }
}

// -------- Convenience overload --------
std::vector<Rule> load_rules() {
    return load_rules(std::string("../rules/rules.rules"));
}