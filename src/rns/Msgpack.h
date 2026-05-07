// src/rns/Msgpack.h — minimal msgpack writer + reader.
//
// Hand-rolled, no Arduino deps. Used by:
//   - Telemetry beacon payload (emit-only, fixed-shape array).
//   - Future ConfigProtocol command frames (read + write — webapp
//     ↔ firmware request/response over Serial and BLE).
//
// All multi-byte values are big-endian per the msgpack spec
// (https://github.com/msgpack/msgpack/blob/master/spec.md).
//
// Scope deliberately narrow: nil, bool, positive uint up to 32-bit,
// float32, fixstr / str8, bin8, fixarray / array16, fixmap / map16.
// Negative ints, float64, and the larger string/array/map variants
// aren't needed for our wire today; extend if/when LXMF or another
// caller actually emits them.

#pragma once

#include <cstdint>
#include <cstring>
#include <string>

#include "rns/Bytes.h"

namespace rns { namespace msgpack {

// =====================================================================
// Writer
// =====================================================================

class Writer {
public:
    // Reserve roughly N bytes; helps avoid reallocations for known
    // payload sizes. Optional — vector grows as needed otherwise.
    void reserve(size_t n);

    // Array header. Emits fixarray (n<16) or array16 (n<65536).
    // Larger arrays throw — extend with array32 if a caller needs it.
    void array_header(size_t n);

    // Map header. Emits fixmap (n<16) or map16 (n<65536). `n` is the
    // number of key-value PAIRS (each pair is two msgpack elements:
    // a key and a value).
    void map_header(size_t n);

    // nil — 0xc0.
    void nil();

    // Bool — 0xc2 (false) or 0xc3 (true).
    void bool_val(bool v);

    // Unsigned ints — always emitted as the smallest fixed-width
    // form that fits, preserving wire stability for downstream
    // parsers that switch on the tag byte. Callers who need a
    // specific width should call uint8/uint16/uint32 directly.
    void uint8(uint8_t v);     // 0xcc + 1 BE byte
    void uint16(uint16_t v);   // 0xcd + 2 BE bytes
    void uint32(uint32_t v);   // 0xce + 4 BE bytes

    // float32 — 0xca + 4 BE bytes (IEEE-754 single).
    void float32(float v);

    // String. Emits fixstr (len<32), str8 (len<256), or throws on
    // larger inputs. UTF-8 in / UTF-8 out — we don't validate.
    void str(const char* s);
    void str(const std::string& s);

    // Binary blob. Emits bin8 (len<256) or throws on larger inputs.
    void bin(const uint8_t* data, size_t len);
    void bin(const Bytes& b) { bin(b.data(), b.size()); }

    // Accumulated bytes.
    const Bytes& bytes() const { return _buf; }

private:
    Bytes _buf;

    void be16(uint16_t v);
    void be32(uint32_t v);
};

// =====================================================================
// Reader
// =====================================================================
//
// Streaming-style reader over a Bytes buffer. Cursor advances as
// each value is consumed. On any error (buffer overrun, type
// mismatch, truncated value, unsupported tag) the `ok` flag flips
// false and stays false — all subsequent reads short-circuit to
// false / 0 without further side effects, so callers can do a long
// chain of reads and check `ok()` at the end.
//
// Read methods return `bool` indicating immediate success. A `false`
// return implies `ok()` is now also false.

class Reader {
public:
    explicit Reader(const Bytes& buf) : _buf(&buf) {}

    bool ok()      const { return _ok; }
    size_t offset() const { return _off; }
    bool   at_end() const { return _off >= _buf->size(); }

    // Tagged element type — peek without consuming.
    enum class Type { NIL, BOOL, UINT, INT_SIGNED, FLOAT32, FLOAT64,
                      STR, BIN, ARRAY, MAP, INVALID };
    Type peek_type() const;

    // Type-specific reads. Each consumes one msgpack element on
    // success. On failure, sets _ok = false and returns false; the
    // cursor is not guaranteed to be at any particular position.
    bool read_nil();
    bool read_bool(bool& out);
    bool read_uint(uint64_t& out);   // accepts fixint + uint8/16/32/64 ONLY
    // Accepts BOTH unsigned (positive fixint, uint8/16/32/64) AND
    // signed (negative fixint, int8/16/32/64) msgpack integer
    // encodings. Use this for any field that might receive a value
    // from a JS / Python encoder — those encoders pick the smallest
    // signed representation by default, so a JS `lat_udeg: -122419400`
    // arrives as msgpack int32, not as a uint32 bit-pattern.
    bool read_int(int64_t& out);
    // Accepts BOTH float32 (0xca) and float64 (0xcb). float64 values
    // are downcast to float — fine for our config-tier precision
    // (battery dividers, lat/lon already int32 microdegrees, etc.).
    // JS numbers are doubles, so @msgpack/msgpack defaults to float64
    // for any non-integer; without float64 acceptance every webclient
    // batt_mult write would fail.
    bool read_float32(float& out);
    bool read_str(std::string& out); // fixstr / str8 / str16
    bool read_bin(Bytes& out);       // bin8 / bin16
    bool read_array_header(size_t& out);  // fixarray / array16
    bool read_map_header(size_t& out);    // fixmap / map16

    // Skip the next element (whatever type), advancing the cursor.
    // Returns false on any error during the skip.
    bool skip_value();

private:
    const Bytes* _buf;
    size_t _off = 0;
    bool   _ok  = true;

    bool need(size_t n);            // ensures _off+n bytes available; sets _ok=false otherwise
    uint8_t  read_u8();
    uint16_t read_be16();
    uint32_t read_be32();
    uint64_t read_be64();
};

} } // namespace rns::msgpack
