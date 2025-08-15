#include "parsers/ftp.h"
#include <sstream>
#include <cctype>

namespace parsers {

    std::string FTPCommand::to_string() const {
        std::ostringstream oss;

        if (is_response) {
            oss << "FTP Response: ";
            if (response_code != -1) {
                oss << response_code << " ";
            }
            for (const auto &line : responses) {
                oss << line << "\n";
            }
            oss << "Complete: " << (is_response_complete ? "Yes" : "No");
        } else {
            oss << "FTP Command: " << command;
            if (!arguments.empty()) {
                oss << " Args:";
                for (const auto &arg : arguments) {
                    oss << " " << arg;
                }
            }
        }

        return oss.str();
    }

    FTPCommand parse_ftp_command(const uint8_t* buffer, std::size_t length, bool from_server) {
        FTPCommand cmd;
        cmd.is_response = from_server;
        cmd.is_response_complete = false;
        cmd.response_code = -1;

        // Convert raw bytes to string
        std::string data(reinterpret_cast<const char*>(buffer), length);

        // Remove trailing CRLF
        if (data.size() >= 2 && data[data.size() - 2] == '\r' && data[data.size() - 1] == '\n') {
            data.erase(data.size() - 2);
        }

        std::istringstream iss(data);
        std::string line;

        if (from_server) {
            // Server response
            while (std::getline(iss, line)) {
                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }

                // Parse numeric response code
                if (line.size() >= 3 && std::isdigit(line[0]) && std::isdigit(line[1]) && std::isdigit(line[2])) {
                    cmd.response_code = std::stoi(line.substr(0, 3));
                }
                cmd.responses.push_back(line);
            }

            // Mark complete if last line ends with "<code> <message>"
            if (!cmd.responses.empty()) {
                const std::string &last = cmd.responses.back();
                if (last.size() >= 4 && std::isdigit(last[0]) && std::isdigit(last[1]) && std::isdigit(last[2]) && last[3] == ' ') {
                    cmd.is_response_complete = true;
                }
            }

        } else {
            // Client request
            if (std::getline(iss, line)) {
                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }

                std::istringstream line_stream(line);
                line_stream >> cmd.command; // first word is command

                std::string arg;
                while (line_stream >> arg) {
                    cmd.arguments.push_back(arg);
                }
            }
        }

        return cmd;
    }
}
