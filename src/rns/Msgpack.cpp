#include "rns/Msgpack.h"

#include <cstring>
#include <stdexcept>

namespace rns { namespace msgpack {

void Writer::reserve(size_t n) {
    // Bytes uses std::vector internally; we don't expose reserve, so
    // this is a hint we currently can't act on. Left as a no-op for
    // API stability — refactor if/when Bytes grows reserve().
    (void)n;
}

void Writer::array_header(size_t n) {
    if (n >= 16) {
        throw std::invalid_argument(
            "msgpack::Writer::array_header: only fixarray (n<16) supported");
    }
    _buf.append(static_cast<uint8_t>(0x90 | n));
}

void Writer::nil() {
    _buf.append(0xc0);
}

void Writer::uint8(uint8_t v) {
    _buf.append(0xcc);
    _buf.append(v);
}

void Writer::uint16(uint16_t v) {
    _buf.append(0xcd);
    _buf.append(static_cast<uint8_t>((v >> 8) & 0xFF));
    _buf.append(static_cast<uint8_t>(v & 0xFF));
}

void Writer::uint32(uint32_t v) {
    _buf.append(0xce);
    _buf.append(static_cast<uint8_t>((v >> 24) & 0xFF));
    _buf.append(static_cast<uint8_t>((v >> 16) & 0xFF));
    _buf.append(static_cast<uint8_t>((v >>  8) & 0xFF));
    _buf.append(static_cast<uint8_t>( v        & 0xFF));
}

void Writer::float32(float v) {
    // Bit-cast to uint32_t — std::memcpy is the standard portable
    // way (no UB, optimizes to mov on every target we care about).
    uint32_t bits;
    std::memcpy(&bits, &v, 4);
    _buf.append(0xca);
    _buf.append(static_cast<uint8_t>((bits >> 24) & 0xFF));
    _buf.append(static_cast<uint8_t>((bits >> 16) & 0xFF));
    _buf.append(static_cast<uint8_t>((bits >>  8) & 0xFF));
    _buf.append(static_cast<uint8_t>( bits        & 0xFF));
}

} } // namespace rns::msgpack
