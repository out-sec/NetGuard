#ifndef PARSERS_FTP_H
#define PARSERS_FTP_H

#include <cstdint>
#include <string>
#include <vector>

namespace parsers {
    // Full FTP Command Structure
    struct FTPCommand {
        std::string command;                 // FTP command, e.g., "USER", "PASS", "LIST"
        std::vector<std::string> arguments;  // Command arguments
        std::vector<std::string> responses;  // Server responses (multi-line support)

        bool is_response;                     // True if this is a server response
        bool is_response_complete;            // Whether full response is captured
        int response_code;                     // Numeric response code (e.g., 220, 331), -1 if not applicable

        std::string to_string() const;
    };


    // Function to parse FTP command from a buffer
    FTPCommand parse_ftp_command(const uint8_t* buffer, std::size_t length, bool from_server);
}
#endif // PARSERS_FTP_H