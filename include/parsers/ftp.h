#ifndef PARSERS_FTP_H
#define PARSERS_FTP_H

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <utility>

namespace parsers {

// Represents a single FTP control-line command or response.
struct FTPCommand {
    std::string command;                 // e.g., USER, PASS, PORT, PASV, EPSV, EPRT, RETR, STOR, LIST...
    std::vector<std::string> arguments;  // split by spaces (raw, no unquoting)
    std::vector<std::string> responses;  // if is_response == true, collect raw lines
    bool is_response = false;            // control-server -> client
    bool is_response_complete = false;   // true iff we saw a full single- or multi-line response
    int  response_code = -1;             // e.g., 220, 331, 227 (for PASV), -1 if not applicable

    std::string to_string() const;
};

// Simple IPv4/port tuple (network-order agnostic string form used externally)
struct FourTuple {
    std::string src_ip;
    uint16_t    src_port = 0;
    std::string dst_ip;
    uint16_t    dst_port = 0;

    bool operator<(const FourTuple& o) const {
        if (src_ip != o.src_ip) return src_ip < o.src_ip;
        if (src_port != o.src_port) return src_port < o.src_port;
        if (dst_ip != o.dst_ip) return dst_ip < o.dst_ip;
        return dst_port < o.dst_port;
    }
};

// Information we learn from PORT/EPRT/PASV/EPSV to associate data connections.
struct FTPDataEndpoint {
    // For active mode via PORT/EPRT (client tells server where to connect)
    std::string client_ip;
    uint16_t    client_port = 0;

    // For passive mode via PASV/EPSV (server tells client where to connect)
    std::string server_ip;
    uint16_t    server_port = 0;

    // Optional command that led to the transfer (RETR, STOR, LIST, NLST, APPE...)
    std::string pending_command;
};

// Tracks FTP control sessions and maps upcoming data connections.
class FTPSessionTracker {
public:
    // Register that this 4-tuple carries FTP control traffic (usually dst or src port 21).
    void track_control(const FourTuple& flow_key);

    // Parse a control payload and update knowledge. Returns parsed command/response (best-effort).
    FTPCommand on_control_payload(const FourTuple& flow_key,
                                  const uint8_t* payload,
                                  std::size_t len,
                                  bool from_server);

    // Indicate a new TCP flow with payload; returns true if this looks like the negotiated FTP data channel.
    // Will match both flow directions.
    bool is_ftp_data_flow(const FourTuple& flow_key) const;

    // After we positively match a data flow, remember it (so subsequent packets match).
    void remember_data_flow(const FourTuple& flow_key);

private:
    // For each control flow, we keep the most recent data endpoint info we learned.
    std::map<FourTuple, FTPDataEndpoint> control_to_data_;

    // Known FTP data flows (both directions recorded)
    std::set<FourTuple> data_flows_;

    // Helper parsers
    static bool parse_port_arg(const std::string& arg, std::string& ip, uint16_t& port);     // h1,h2,h3,h4,p1,p2
    static bool parse_pasv_reply(const std::string& line, std::string& ip, uint16_t& port);  // 227 (h1,h2,h3,h4,p1,p2)
    static bool parse_epsv_reply(const std::string& line, uint16_t& port);                   // 229 Entering Extended Passive Mode (|||p|)
    static bool parse_eprt_arg(const std::string& arg, std::string& ip, uint16_t& port);     // |af|addr|port|
};

// Stateless line parser for a single control payload chunk (handles multi-line server responses best-effort).
FTPCommand parse_ftp_command(const uint8_t* buffer, std::size_t length, bool from_server);

} // namespace parsers

#endif // PARSERS_FTP_H
