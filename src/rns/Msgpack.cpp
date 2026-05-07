#include "rns/Msgpack.h"

#include <cstring>
#include <stdexcept>

namespace rns { namespace msgpack {

// =====================================================================
// Writer
// =====================================================================

void Writer::reserve(size_t n) {
    // Bytes uses std::vector internally; we don't expose reserve, so
    // this is a hint we currently can't act on. Left as a no-op for
    // API stability — refactor if/when Bytes grows reserve().
    (void)n;
}

void Writer::be16(uint16_t v) {
    _buf.append(static_cast<uint8_t>((v >> 8) & 0xFF));
    _buf.append(static_cast<uint8_t>(v & 0xFF));
}

void Writer::be32(uint32_t v) {
    _buf.append(static_cast<uint8_t>((v >> 24) & 0xFF));
    _buf.append(static_cast<uint8_t>((v >> 16) & 0xFF));
    _buf.append(static_cast<uint8_t>((v >>  8) & 0xFF));
    _buf.append(static_cast<uint8_t>( v        & 0xFF));
}

void Writer::array_header(size_t n) {
    if (n < 16) {
        _buf.append(static_cast<uint8_t>(0x90 | n));
    } else if (n < 0x10000) {
        _buf.append(0xdc);
        be16(static_cast<uint16_t>(n));
    } else {
        throw std::invalid_argument(
            "msgpack::Writer::array_header: > 65535 elements unsupported");
    }
}

void Writer::map_header(size_t n) {
    if (n < 16) {
        _buf.append(static_cast<uint8_t>(0x80 | n));
    } else if (n < 0x10000) {
        _buf.append(0xde);
        be16(static_cast<uint16_t>(n));
    } else {
        throw std::invalid_argument(
            "msgpack::Writer::map_header: > 65535 pairs unsupported");
    }
}

void Writer::nil()                { _buf.append(0xc0); }
void Writer::bool_val(bool v)     { _buf.append(v ? 0xc3 : 0xc2); }

void Writer::uint8(uint8_t v)   { _buf.append(0xcc); _buf.append(v); }
void Writer::uint16(uint16_t v) { _buf.append(0xcd); be16(v); }
void Writer::uint32(uint32_t v) { _buf.append(0xce); be32(v); }

void Writer::float32(float v) {
    uint32_t bits;
    std::memcpy(&bits, &v, 4);
    _buf.append(0xca);
    be32(bits);
}

void Writer::str(const char* s) {
    str(std::string(s));
}

void Writer::str(const std::string& s) {
    const size_t n = s.size();
    if (n < 32) {
        _buf.append(static_cast<uint8_t>(0xa0 | n));
    } else if (n < 256) {
        _buf.append(0xd9);
        _buf.append(static_cast<uint8_t>(n));
    } else {
        throw std::invalid_argument(
            "msgpack::Writer::str: > 255 bytes unsupported (extend to str16 if needed)");
    }
    _buf.append(reinterpret_cast<const uint8_t*>(s.data()), n);
}

void Writer::bin(const uint8_t* data, size_t len) {
    if (len >= 256) {
        throw std::invalid_argument(
            "msgpack::Writer::bin: > 255 bytes unsupported (extend to bin16 if needed)");
    }
    _buf.append(0xc4);
    _buf.append(static_cast<uint8_t>(len));
    _buf.append(data, len);
}

// =====================================================================
// Reader
// =====================================================================

bool Reader::need(size_t n) {
    if (!_ok) return false;
    if (_off + n > _buf->size()) {
        _ok = false;
        return false;
    }
    return true;
}

uint8_t  Reader::read_u8()    { return (*_buf)[_off++]; }
uint16_t Reader::read_be16() {
    uint16_t v = static_cast<uint16_t>((*_buf)[_off]) << 8 |
                 static_cast<uint16_t>((*_buf)[_off + 1]);
    _off += 2;
    return v;
}
uint32_t Reader::read_be32() {
    uint32_t v = static_cast<uint32_t>((*_buf)[_off    ]) << 24 |
                 static_cast<uint32_t>((*_buf)[_off + 1]) << 16 |
                 static_cast<uint32_t>((*_buf)[_off + 2]) <<  8 |
                 static_cast<uint32_t>((*_buf)[_off + 3]);
    _off += 4;
    return v;
}
uint64_t Reader::read_be64() {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | (*_buf)[_off + i];
    _off += 8;
    return v;
}

Reader::Type Reader::peek_type() const {
    if (_off >= _buf->size()) return Type::INVALID;
    const uint8_t t = (*_buf)[_off];
    if (t == 0xc0)                       return Type::NIL;
    if (t == 0xc2 || t == 0xc3)          return Type::BOOL;
    if (t < 0x80)                        return Type::UINT;     // positive fixint
    if (t >= 0xcc && t <= 0xcf)          return Type::UINT;     // uint8/16/32/64
    if (t >= 0xe0)                       return Type::INT_SIGNED; // negative fixint
    if (t >= 0xd0 && t <= 0xd3)          return Type::INT_SIGNED; // int8/16/32/64
    if (t == 0xca)                       return Type::FLOAT32;
    if (t == 0xcb)                       return Type::FLOAT64;
    if ((t & 0xe0) == 0xa0)              return Type::STR;      // fixstr
    if (t == 0xd9 || t == 0xda)          return Type::STR;      // str8 / str16
    if (t == 0xc4 || t == 0xc5)          return Type::BIN;      // bin8 / bin16
    if ((t & 0xf0) == 0x90)              return Type::ARRAY;    // fixarray
    if (t == 0xdc || t == 0xdd)          return Type::ARRAY;    // array16 / array32
    if ((t & 0xf0) == 0x80)              return Type::MAP;      // fixmap
    if (t == 0xde || t == 0xdf)          return Type::MAP;      // map16 / map32
    return Type::INVALID;
}

bool Reader::read_nil() {
    if (!need(1)) return false;
    if (read_u8() != 0xc0) { _ok = false; return false; }
    return true;
}

bool Reader::read_bool(bool& out) {
    if (!need(1)) return false;
    const uint8_t t = read_u8();
    if (t == 0xc2)      { out = false; return true; }
    if (t == 0xc3)      { out = true;  return true; }
    _ok = false;
    return false;
}

bool Reader::read_uint(uint64_t& out) {
    if (!need(1)) return false;
    const uint8_t t = read_u8();
    if (t < 0x80) { out = t; return true; }                          // positive fixint
    switch (t) {
        case 0xcc:
            if (!need(1)) return false;
            out = read_u8();
            return true;
        case 0xcd:
            if (!need(2)) return false;
            out = read_be16();
            return true;
        case 0xce:
            if (!need(4)) return false;
            out = read_be32();
            return true;
        case 0xcf:
            if (!need(8)) return false;
            out = read_be64();
            return true;
        default:
            _ok = false;
            return false;
    }
}

bool Reader::read_int(int64_t& out) {
    if (!need(1)) return false;
    const uint8_t t = read_u8();
    // Positive fixint (0x00..0x7f) — value IS the byte.
    if (t < 0x80) { out = static_cast<int64_t>(t); return true; }
    // Negative fixint (0xe0..0xff) — value is signed 5-bit.
    if (t >= 0xe0) { out = static_cast<int64_t>(static_cast<int8_t>(t)); return true; }
    switch (t) {
        // Unsigned widths — bit-for-bit, but reject if MSB would
        // overflow int64 to keep the contract clean.
        case 0xcc:
            if (!need(1)) return false;
            out = static_cast<int64_t>(read_u8());
            return true;
        case 0xcd:
            if (!need(2)) return false;
            out = static_cast<int64_t>(read_be16());
            return true;
        case 0xce:
            if (!need(4)) return false;
            out = static_cast<int64_t>(read_be32());
            return true;
        case 0xcf:
            if (!need(8)) return false;
            {
                uint64_t v = read_be64();
                if (v > static_cast<uint64_t>(INT64_MAX)) { _ok = false; return false; }
                out = static_cast<int64_t>(v);
            }
            return true;
        // Signed widths — sign-extend native.
        case 0xd0:
            if (!need(1)) return false;
            out = static_cast<int64_t>(static_cast<int8_t>(read_u8()));
            return true;
        case 0xd1:
            if (!need(2)) return false;
            out = static_cast<int64_t>(static_cast<int16_t>(read_be16()));
            return true;
        case 0xd2:
            if (!need(4)) return false;
            out = static_cast<int64_t>(static_cast<int32_t>(read_be32()));
            return true;
        case 0xd3:
            if (!need(8)) return false;
            out = static_cast<int64_t>(read_be64());
            return true;
        default:
            _ok = false;
            return false;
    }
}

bool Reader::read_float32(float& out) {
    if (!need(1)) return false;
    const uint8_t t = read_u8();
    if (t == 0xca) {
        if (!need(4)) return false;
        uint32_t bits = read_be32();
        std::memcpy(&out, &bits, 4);
        return true;
    }
    if (t == 0xcb) {
        // float64 from a JS / Python encoder — downcast.
        if (!need(8)) return false;
        uint64_t bits = read_be64();
        double d;
        std::memcpy(&d, &bits, 8);
        out = static_cast<float>(d);
        return true;
    }
    _ok = false;
    return false;
}

bool Reader::read_str(std::string& out) {
    if (!need(1)) return false;
    const uint8_t t = read_u8();
    size_t len = 0;
    if ((t & 0xe0) == 0xa0) {
        len = t & 0x1f;
    } else if (t == 0xd9) {
        if (!need(1)) return false;
        len = read_u8();
    } else if (t == 0xda) {
        if (!need(2)) return false;
        len = read_be16();
    } else {
        _ok = false;
        return false;
    }
    if (!need(len)) return false;
    out.assign(reinterpret_cast<const char*>(_buf->data() + _off), len);
    _off += len;
    return true;
}

bool Reader::read_bin(Bytes& out) {
    if (!need(1)) return false;
    const uint8_t t = read_u8();
    size_t len = 0;
    if (t == 0xc4) {
        if (!need(1)) return false;
        len = read_u8();
    } else if (t == 0xc5) {
        if (!need(2)) return false;
        len = read_be16();
    } else {
        _ok = false;
        return false;
    }
    if (!need(len)) return false;
    out = Bytes(_buf->data() + _off, len);
    _off += len;
    return true;
}

bool Reader::read_array_header(size_t& out) {
    if (!need(1)) return false;
    const uint8_t t = read_u8();
    if ((t & 0xf0) == 0x90) {
        out = t & 0x0f;
        return true;
    }
    if (t == 0xdc) {
        if (!need(2)) return false;
        out = read_be16();
        return true;
    }
    if (t == 0xdd) {
        if (!need(4)) return false;
        out = read_be32();
        return true;
    }
    _ok = false;
    return false;
}

bool Reader::read_map_header(size_t& out) {
    if (!need(1)) return false;
    const uint8_t t = read_u8();
    if ((t & 0xf0) == 0x80) {
        out = t & 0x0f;
        return true;
    }
    if (t == 0xde) {
        if (!need(2)) return false;
        out = read_be16();
        return true;
    }
    if (t == 0xdf) {
        if (!need(4)) return false;
        out = read_be32();
        return true;
    }
    _ok = false;
    return false;
}

bool Reader::skip_value() {
    const Type t = peek_type();
    switch (t) {
        case Type::NIL:        return read_nil();
        case Type::BOOL:       { bool b; return read_bool(b); }
        case Type::UINT:       { uint64_t v; return read_uint(v); }
        case Type::INT_SIGNED: { int64_t v; return read_int(v); }
        case Type::FLOAT32:    { float f; return read_float32(f); }
        case Type::FLOAT64:    { float f; return read_float32(f); }  // accepts both
        case Type::STR:        { std::string s; return read_str(s); }
        case Type::BIN:        { Bytes b; return read_bin(b); }
        case Type::ARRAY: {
            size_t n;
            if (!read_array_header(n)) return false;
            for (size_t i = 0; i < n; ++i) if (!skip_value()) return false;
            return true;
        }
        case Type::MAP: {
            size_t n;
            if (!read_map_header(n)) return false;
            for (size_t i = 0; i < n; ++i) {
                if (!skip_value()) return false;  // key
                if (!skip_value()) return false;  // value
            }
            return true;
        }
        default:
            _ok = false;
            return false;
    }
}

} } // namespace rns::msgpack
