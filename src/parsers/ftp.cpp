#include "parsers/ftp.h"
#include <sstream>
#include <cctype>
#include <algorithm>

namespace parsers {

static inline std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    while (b > a && (s[b-1] == ' ' || s[b-1] == '\t' || s[b-1] == '\r' || s[b-1] == '\n')) --b;
    return s.substr(a, b-a);
}

std::string FTPCommand::to_string() const {
    std::ostringstream oss;
    if (is_response) {
        oss << "FTP Response";
        if (response_code != -1) oss << " " << response_code;
        oss << ": ";
        for (size_t i = 0; i < responses.size(); ++i) {
            oss << responses[i];
            if (i + 1 != responses.size()) oss << "\\n";
        }
    } else {
        oss << "FTP Command: " << command;
        for (const auto& a : arguments) {
            oss << " " << a;
        }
    }
    return oss.str();
}

static std::vector<std::string> split_ws(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    std::istringstream iss(s);
    while (iss >> cur) out.push_back(cur);
    return out;
}

FTPCommand parse_ftp_command(const uint8_t* buffer, std::size_t length, bool from_server) {
    FTPCommand cmd;
    cmd.is_response = from_server;

    std::string text(reinterpret_cast<const char*>(buffer), length);

    // Split to CRLF separated lines (handle lone LF too)
    std::vector<std::string> lines;
    size_t start = 0;
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\\n') {
            size_t end = (i && text[i-1] == '\\r') ? i-1 : i;
            lines.push_back(text.substr(start, end - start));
            start = i + 1;
        }
    }
    if (start < text.size()) lines.push_back(text.substr(start));

    if (from_server) {
        // Parse multi-line reply semantics per RFC 959:
        //  xyz-text follows; if "xyz-" then multiline until "xyz ".
        int reply_code = -1;
        bool complete = false;
        for (auto line : lines) {
            if (!line.empty() && line.back() == '\\r') line.pop_back();
            if (line.size() >= 3 && std::isdigit(line[0]) && std::isdigit(line[1]) && std::isdigit(line[2])) {
                int code = (line[0]-'0')*100 + (line[1]-'0')*10 + (line[2]-'0');
                if (reply_code == -1) reply_code = code;
                if (line.size() >= 4 && line[3] == ' ') {
                    complete = true;
                }
            }
            cmd.responses.push_back(line);
        }
        cmd.response_code = reply_code;
        cmd.is_response_complete = complete;
    } else {
        // First non-empty line → command
        for (auto line : lines) {
            line = trim(line);
            if (line.empty()) continue;
            auto parts = split_ws(line);
            if (!parts.empty()) {
                cmd.command = parts[0];
                for (size_t i = 1; i < parts.size(); ++i) cmd.arguments.push_back(parts[i]);
                break;
            }
        }
    }

    return cmd;
}

// ---- FTPSessionTracker ----

void FTPSessionTracker::track_control(const FourTuple& flow_key) {
    control_to_data_.emplace(flow_key, FTPDataEndpoint{});
}

// h1,h2,h3,h4,p1,p2 → ip and port
bool FTPSessionTracker::parse_port_arg(const std::string& arg, std::string& ip, uint16_t& port) {
    // Split by comma
    std::vector<int> nums;
    int cur = 0; bool in_num = false; bool neg = false;
    for (size_t i=0;i<=arg.size();++i) {
        if (i == arg.size() || arg[i] == ',') {
            if (in_num) {
                nums.push_back(neg ? -cur : cur);
                cur = 0; in_num = false; neg = false;
            }
        } else if (arg[i] == '-') {
            neg = true; in_num = true;
        } else if (std::isdigit(static_cast<unsigned char>(arg[i]))) {
            in_num = true;
            cur = cur*10 + (arg[i]-'0');
        }
    }
    if (nums.size() != 6) return false;
    ip = std::to_string(nums[0]) + "." + std::to_string(nums[1]) + "." + std::to_string(nums[2]) + "." + std::to_string(nums[3]);
    port = static_cast<uint16_t>((nums[4] << 8) | (nums[5] & 0xff));
    return true;
}

bool FTPSessionTracker::parse_pasv_reply(const std::string& line, std::string& ip, uint16_t& port) {
    // Looking for (h1,h2,h3,h4,p1,p2)
    auto l = line.find('(');
    auto r = line.find(')', l == std::string::npos ? 0 : l+1);
    if (l == std::string::npos || r == std::string::npos || r <= l+1) return false;
    std::string inside = line.substr(l+1, r-l-1);
    return parse_port_arg(inside, ip, port);
}

bool FTPSessionTracker::parse_epsv_reply(const std::string& line, uint16_t& port) {
    // RFC 2428: 229 Entering Extended Passive Mode (|||port|) where delimiter may vary
    auto l = line.find('(');
    auto r = line.find(')', l == std::string::npos ? 0 : l+1);
    if (l == std::string::npos || r == std::string::npos || r <= l+1) return false;
    std::string inside = line.substr(l+1, r-l-1);
    if (inside.size() < 5) return false;
    char d = inside[0];
    // Expect d d d port d
    size_t lastd = inside.find_last_of(d);
    if (lastd == std::string::npos || lastd <= 3) return false;
    std::string port_str = inside.substr(3, lastd-3);
    port = static_cast<uint16_t>(std::stoi(port_str));
    return true;
}

bool FTPSessionTracker::parse_eprt_arg(const std::string& arg, std::string& ip, uint16_t& port) {
    // |af|addr|port| (af=1 for IPv4, 2 for IPv6). Delimiter is the first char.
    if (arg.size() < 5) return false;
    char d = arg[0];
    std::vector<std::string> parts;
    std::string cur;
    for (size_t i=1;i<arg.size();++i) {
        if (arg[i] == d) {
            parts.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(arg[i]);
        }
    }
    if (!cur.empty()) parts.push_back(cur);
    if (parts.size() < 3) return false;
    // parts[0] = af, parts[1] = addr, parts[2] = port
    ip = parts[1];
    port = static_cast<uint16_t>(std::stoi(parts[2]));
    return true;
}

FTPCommand FTPSessionTracker::on_control_payload(const FourTuple& flow_key,
                                                 const uint8_t* payload,
                                                 std::size_t len,
                                                 bool from_server) {
    FTPCommand c = parse_ftp_command(payload, len, from_server);

    // Ensure control map exists
    auto &endpoint = control_to_data_[flow_key];

    if (!from_server) {
        // Client → Server commands
        std::string cmd_uc = c.command;
        std::transform(cmd_uc.begin(), cmd_uc.end(), cmd_uc.begin(),
                       [](unsigned char ch){ return std::toupper(ch); });

        if (cmd_uc == "PORT" && !c.arguments.empty()) {
            std::string ip; uint16_t port;
            if (parse_port_arg(c.arguments[0], ip, port)) {
                endpoint.client_ip = ip;
                endpoint.client_port = port;
            }
        } else if (cmd_uc == "EPRT" && !c.arguments.empty()) {
            std::string ip; uint16_t port;
            if (parse_eprt_arg(c.arguments[0], ip, port)) {
                endpoint.client_ip = ip;
                endpoint.client_port = port;
            }
        } else if (cmd_uc == "RETR" || cmd_uc == "STOR" || cmd_uc == "LIST" ||
                   cmd_uc == "NLST" || cmd_uc == "APPE") {
            endpoint.pending_command = cmd_uc;
        }
    } else {
        // Server → Client replies
        if (c.response_code == 227) {
            // PASV
            std::string ip; uint16_t port;
            // Use last response line for extraction
            std::string line = c.responses.empty() ? std::string() : c.responses.back();
            if (parse_pasv_reply(line, ip, port)) {
                endpoint.server_ip = ip;
                endpoint.server_port = port;
            }
        } else if (c.response_code == 229) {
            uint16_t port;
            std::string line = c.responses.empty() ? std::string() : c.responses.back();
            if (parse_epsv_reply(line, port)) {
                // Server IP is the server side of control flow
                endpoint.server_ip = flow_key.src_ip; // from_server, src is server
                endpoint.server_port = port;
            }
        }
    }
    return c;
}

bool FTPSessionTracker::is_ftp_data_flow(const FourTuple& f) const {
    if (data_flows_.count(f)) return true;
    // Also match reverse direction
    FourTuple r{f.dst_ip, f.dst_port, f.src_ip, f.src_port};
    if (data_flows_.count(r)) return true;

    // Try to match against any negotiated endpoints
    for (const auto& kv : control_to_data_) {
        const auto& ctl = kv.first;
        const auto& ep  = kv.second;

        // Passive: client connects to server_ip:server_port
        if (!ep.server_ip.empty() && ep.server_port != 0) {
            if ((f.dst_ip == ep.server_ip && f.dst_port == ep.server_port) ||
                (f.src_ip == ep.server_ip && f.src_port == ep.server_port)) {
                return true;
            }
        }

        // Active: server connects to client_ip:client_port
        if (!ep.client_ip.empty() && ep.client_port != 0) {
            if ((f.dst_ip == ep.client_ip && f.dst_port == ep.client_port) ||
                (f.src_ip == ep.client_ip && f.src_port == ep.client_port)) {
                return true;
            }
        }
    }
    return false;
}

void FTPSessionTracker::remember_data_flow(const FourTuple& f) {
    data_flows_.insert(f);
    FourTuple r{f.dst_ip, f.dst_port, f.src_ip, f.src_port};
    data_flows_.insert(r);
}

} // namespace parsers
