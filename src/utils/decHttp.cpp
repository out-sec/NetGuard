#include "utils/decHttp.h"
#include <sstream>
#include <algorithm>
#include <cctype>
#include <vector>
#include <utility>

namespace {

static inline std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static inline std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return (char)std::tolower(c); });
    return s;
}

static bool starts_with(const std::string& s, const std::string& p) {
    return s.rfind(p, 0) == 0;
}

// parse hex, ignore trailing characters (used for chunk size lines with extensions)
static bool parse_hex_len(const std::string& s, size_t& out) {
    out = 0;
    size_t i = 0;
    // trim leading spaces
    while (i < s.size() && isspace((unsigned char)s[i])) ++i;
    // read hex until non-hex digit
    size_t j = i;
    while (j < s.size() && std::isxdigit((unsigned char)s[j])) ++j;
    if (j == i) return false;
    std::string hexpart = s.substr(i, j - i);
    std::istringstream iss(hexpart);
    iss >> std::hex >> out;
    return !iss.fail();
}

static std::map<std::string,std::string> parse_urlencoded(const std::string& body) {
    std::map<std::string,std::string> out;
    std::string key, val;
    size_t i = 0;
    auto pct = [](const std::string& in)->std::string{
        std::string r;
        for (size_t i=0; i<in.size(); ++i) {
            if (in[i] == '%' && i+2 < in.size()) {
                char hex[3] = {in[i+1], in[i+2], 0};
                char c = (char) strtol(hex, nullptr, 16);
                r.push_back(c);
                i += 2;
            } else if (in[i] == '+') {
                r.push_back(' ');
            } else {
                r.push_back(in[i]);
            }
        }
        return r;
    };

    while (i < body.size()) {
        size_t kEnd = body.find('=', i);
        if (kEnd == std::string::npos) break;
        size_t vEnd = body.find('&', kEnd+1);
        key = body.substr(i, kEnd - i);
        val = body.substr(kEnd+1, (vEnd==std::string::npos? body.size(): vEnd) - (kEnd+1));
        out[pct(key)] = pct(val);
        if (vEnd == std::string::npos) break;
        i = vEnd + 1;
    }
    return out;
}

} // namespace

namespace utils {

std::optional<HTTPDecodedData> decode_http(const uint8_t* buffer, size_t length) {
    if (!buffer || length == 0) return std::nullopt;

    std::string payload(reinterpret_cast<const char*>(buffer), length);

    // Quick detect: request methods or "HTTP/"
    static const char* methods[] = {"GET ","POST ","HEAD ","PUT ","DELETE ","OPTIONS ","PATCH "};
    bool is_req = false;
    for (auto m : methods) { if (starts_with(payload, m)) { is_req = true; break; } }
    bool is_resp = starts_with(payload, "HTTP/");
    if (!is_req && !is_resp) return std::nullopt;

    HTTPDecodedData d;
    d.is_http = true;
    d.is_request = is_req;

    // Split headers/body at first \r\n\r\n (preferred) or \n\n (fallback)
    size_t hdr_end = payload.find("\r\n\r\n");
    size_t sep_len = 4;
    if (hdr_end == std::string::npos) {
        hdr_end = payload.find("\n\n");
        sep_len = 2;
    }
    std::string header_part = (hdr_end == std::string::npos) ? payload : payload.substr(0, hdr_end);
    std::string body_part   = (hdr_end == std::string::npos) ? std::string() : payload.substr(hdr_end + sep_len);
    d.header_bytes = (hdr_end == std::string::npos) ? payload.size() : hdr_end + sep_len;

    // We will parse headers line-by-line, but handle folded headers (lines starting with SP/TAB)
    std::vector<std::pair<std::string,std::string>> headers_vec; // preserve original case & order

    {
        std::istringstream hs(header_part);
        std::string line;
        // Start line
        if (!std::getline(hs, line)) return d;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        {
            std::istringstream sl(line);
            if (is_req) {
                sl >> d.method >> d.path >> d.version;
            } else {
                sl >> d.version >> d.status_code;
                std::getline(sl, d.reason_phrase);
                // trim reason phrase
                d.reason_phrase = trim(d.reason_phrase);
            }
        }

        // Headers lines
        std::string last_key;
        while (std::getline(hs, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) break;

            // folded header: starts with space or tab -> append to last header value
            if (!line.empty() && (line[0] == ' ' || line[0] == '\t')) {
                if (!last_key.empty()) {
                    // append trimmed continuation (with single space)
                    std::string cont = trim(line);
                    if (!cont.empty()) {
                        for (auto &kv : headers_vec) {
                            if (kv.first == last_key) {
                                if (!kv.second.empty()) kv.second += " ";
                                kv.second += cont;
                                break;
                            }
                        }
                    }
                }
                continue;
            }

            auto pos = line.find(':');
            if (pos == std::string::npos) continue;
            std::string key = line.substr(0, pos);
            std::string val = line.substr(pos+1);
            key = trim(key);
            val = trim(val);
            headers_vec.emplace_back(key, val);
            last_key = key;
        }
    }

    // Fill d.headers map preserving original key-case
    for (const auto& kv : headers_vec) {
        d.headers[kv.first] = kv.second;
    }

    // For lookups (content-type, content-length, transfer-encoding) use lower-case keys
    std::string ct_lower;
    std::string te_lower;
    size_t content_len = 0;
    bool chunked = false;
    for (const auto& kv : d.headers) {
        std::string key_l = to_lower(kv.first);
        if (key_l == "content-length") {
            content_len = (size_t) std::strtoul(kv.second.c_str(), nullptr, 10);
        } else if (key_l == "transfer-encoding") {
            te_lower = to_lower(kv.second);
            if (te_lower.find("chunked") != std::string::npos) chunked = true;
        } else if (key_l == "content-type") {
            ct_lower = to_lower(kv.second);
        }
    }
    d.chunked = chunked;

    if (chunked) {
        // Chunked decoding supporting extensions (chunk-size[;ext]\r\n)
        std::string out;
        size_t pos = 0;
        bool ok = true;
        while (pos < body_part.size()) {
            // find end of size line (handles \r\n or \n)
            size_t ln = body_part.find("\r\n", pos);
            size_t crlf_len = 2;
            if (ln == std::string::npos) {
                ln = body_part.find('\n', pos);
                crlf_len = 1;
            }
            if (ln == std::string::npos) { ok = false; break; }

            std::string size_line = body_part.substr(pos, ln - pos);
            size_t chunk_size = 0;
            if (!parse_hex_len(size_line, chunk_size)) { ok = false; break; }
            pos = ln + crlf_len;

            if (chunk_size == 0) {
                // consume optional trailer headers until CRLF CRLF or \n\n; we won't parse them, just move pointer
                d.complete = true;
                // attempt to find final double CRLF from current pos
                size_t trailer_end = std::string::npos;
                size_t rr = body_part.find("\r\n\r\n", pos);
                if (rr != std::string::npos) trailer_end = rr + 4;
                else {
                    rr = body_part.find("\n\n", pos);
                    if (rr != std::string::npos) trailer_end = rr + 2;
                }
                // ignore trailer content; break now
                break;
            }

            // ensure enough bytes for chunk
            if (pos + chunk_size > body_part.size()) { ok = false; break; }
            out.append(body_part.data() + pos, chunk_size);
            pos += chunk_size;

            // consume following CRLF after chunk data
            if (pos + 2 <= body_part.size() && body_part[pos] == '\r' && body_part[pos+1] == '\n') {
                pos += 2;
            } else if (pos + 1 <= body_part.size() && body_part[pos] == '\n') {
                pos += 1;
            } else {
                // missing expected CRLF, broken stream
                ok = false;
                break;
            }
        }
        if (!ok) {
            // partial decode: return what we have but mark incomplete
            d.body = out;
            d.body_bytes = out.size();
            d.complete = false;
        } else {
            d.body = out;
            d.body_bytes = out.size();
            // d.complete already set when zero-chunk encountered above
        }
    } else {
        // Non-chunked: if Content-Length present, take only content_len bytes
        if (content_len > 0) {
            if (body_part.size() >= content_len) {
                d.body = body_part.substr(0, content_len);
                d.body_bytes = d.body.size();
                d.content_length = content_len;
                d.complete = true;
            } else {
                // partial body
                d.body = body_part;
                d.body_bytes = body_part.size();
                d.content_length = content_len;
                d.complete = false;
            }
        } else {
            // no content-length: take whole body_part (could be response without content-length)
            d.body = body_part;
            d.body_bytes = body_part.size();
            d.content_length = 0;
            d.complete = true; // treat as complete because no length was expected
        }
    }

// Helpers: urlencoded fields
    if (!ct_lower.empty() && ct_lower.find("application/x-www-form-urlencoded") != std::string::npos) {
        d.form_fields = parse_urlencoded(d.body);
    }

    // JSON pretty-print (basic indentation, no external lib)
    if (!ct_lower.empty() && ct_lower.find("application/json") != std::string::npos) {
        std::string pretty;
        int indent = 0;
        bool in_string = false;
        for (size_t i = 0; i < d.body.size(); ++i) {
            char c = d.body[i];

            if (c == '\"') {
                bool escaped = (i > 0 && d.body[i-1] == '\\');
                if (!escaped) in_string = !in_string;
                pretty.push_back(c);
            } else if (!in_string && (c == '{' || c == '[')) {
                pretty.push_back(c);
                pretty.push_back('\n');
                indent++;
                pretty.append(indent * 2, ' ');
            } else if (!in_string && (c == '}' || c == ']')) {
                pretty.push_back('\n');
                indent = std::max(0, indent - 1);
                pretty.append(indent * 2, ' ');
                pretty.push_back(c);
            } else if (!in_string && c == ',') {
                pretty.push_back(c);
                pretty.push_back('\n');
                pretty.append(indent * 2, ' ');
            } else if (!in_string && (c == ':')) {
                pretty.push_back(c);
                pretty.push_back(' ');
            } else {
                pretty.push_back(c);
            }
        }
        d.json_pretty = pretty;
    }

    return d;
}

} // namespace utils