#include "rns/Bytes.h"

#include <stdexcept>

namespace rns {

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

Bytes Bytes::from_hex(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("Bytes::from_hex: odd-length input");
    }
    Bytes out;
    out._data.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = hex_nibble(hex[i]);
        int lo = hex_nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            throw std::invalid_argument("Bytes::from_hex: non-hex character");
        }
        out._data.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::string Bytes::to_hex() const {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.resize(_data.size() * 2);
    for (size_t i = 0; i < _data.size(); i++) {
        out[2 * i]     = digits[(_data[i] >> 4) & 0x0f];
        out[2 * i + 1] = digits[_data[i] & 0x0f];
    }
    return out;
}

Bytes Bytes::slice(size_t offset, size_t len) const {
    if (offset >= _data.size()) return {};
    size_t end = (len == npos) ? _data.size() : std::min(_data.size(), offset + len);
    return Bytes(_data.data() + offset, end - offset);
}

} // namespace rns
