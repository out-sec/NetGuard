#include "parsers/http.h"
#include "utils/decHttp.h"
#include <sstream>
#include <algorithm>
#include <iomanip>

namespace parsers {

HTTPHeader parse_http_header(const uint8_t* buffer, size_t length) {
    HTTPHeader out;
    auto d = utils::decode_http(buffer, length);
    if (!d.has_value()) return out;

    out.is_http        = d->is_http;
    out.is_request     = d->is_request;
    out.complete       = d->complete;
    out.method         = d->method;
    out.path           = d->path;
    out.version        = d->version;
    out.status_code    = d->status_code;
    out.reason_phrase  = d->reason_phrase;
    out.headers        = d->headers;
    out.header_bytes   = d->header_bytes;
    out.body           = d->body;
    out.body_bytes     = d->body_bytes;
    out.content_length = d->content_length;
    out.chunked        = d->chunked;
    out.form_fields    = d->form_fields;
    out.json_pretty    = d->json_pretty; // already filled in decode_http
    return out;
}

std::string HTTPHeader::to_string() const {
    if (!is_http) return {};
    std::ostringstream oss;
    oss << "  HTTP:\n";
    if (is_request) {
        oss << "      Type:            Request\n"
            << "      Request-Line:    " << method << " " << path << " " << version << "\n";
    } else {
        oss << "      Type:            Response\n"
            << "      Status-Line:     " << version << " " << status_code << " " << reason_phrase << "\n";
    }
    oss << "      Header Bytes:    " << header_bytes << "\n";
    oss << "      Content-Length:  " << content_length << (chunked ? " (chunked)" : "") << "\n";
    oss << "      Complete:        " << (complete ? "yes" : "no") << "\n";

    if (!headers.empty()) {
        oss << "      Headers:\n";
        for (const auto& kv : headers) {
            oss << "          " << kv.first << ": " << kv.second << "\n";
        }
    }

    if (body_bytes > 0) {
        oss << "      Body (" << body_bytes << " bytes):\n";
        if (!form_fields.empty()) {
            // Handle form-urlencoded body
            for (const auto& kv : form_fields) {
                oss << "          " << kv.first << " = " << kv.second << "\n";
            }
        } else if (!json_pretty.empty()) {
            // Pretty JSON body
            std::istringstream js(json_pretty);
            std::string line;
            while (std::getline(js, line)) {
                oss << "          " << line << "\n";
            }
        } else {
            // Fallback: raw body with non-printables replaced
            const size_t MAX_SHOW = 16 * 1024 * 1024; // 16 MB safety cap
            size_t show = std::min(body.size(), MAX_SHOW);
            std::string clip = body.substr(0, show);
            for (auto& c : clip) {
                unsigned char uc = static_cast<unsigned char>(c);
                if (uc < 32 && c != '\r' && c != '\n' && c != '\t') c = '.';
            }
            std::istringstream bs(clip);
            std::string line;
            while (std::getline(bs, line)) {
                oss << "          " << line << "\n";
            }
            if (body.size() > show) {
                oss << "          ... (truncated, " << body.size() - show << " bytes more)\n";
            }
        }
    }
    return oss.str();
}

// Wrapper to expose utils::decode_http through the parsers namespace
std::optional<utils::HTTPDecodedData>
decode_http(const unsigned char* buffer, unsigned long length) {
    return utils::decode_http(
        reinterpret_cast<const uint8_t*>(buffer),
        static_cast<size_t>(length)
    );
}

} // namespace parsers