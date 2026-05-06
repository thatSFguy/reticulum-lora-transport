// src/rns/Msgpack.h — minimal msgpack writer.
//
// Only the value shapes we currently emit (nil, uint8/16/32, float32,
// fixarray header). Hand-rolled rather than vendored: tiny, no
// Arduino deps, easy to extend when LXMF / propagation-node app_data
// shapes need str8 / bin8 / map etc.
//
// All multi-byte values are big-endian per the msgpack spec
// (https://github.com/msgpack/msgpack/blob/master/spec.md).

#pragma once

#include <cstdint>
#include <cstring>

#include "rns/Bytes.h"

namespace rns { namespace msgpack {

class Writer {
public:
    // Reserve roughly N bytes; helps avoid reallocations for known
    // payload sizes. Optional — vector grows as needed otherwise.
    void reserve(size_t n);

    // Array header. Currently only fixarray (n < 16). Throws if n >=
    // 16; extend with array16/array32 when needed.
    void array_header(size_t n);

    // nil — 0xc0.
    void nil();

    // Unsigned ints — always emitted as the smallest fixed-width
    // form that fits, preserving wire stability for downstream
    // parsers that switch on the tag byte. Callers who need a
    // specific width should call uint8/uint16/uint32 directly.
    void uint8(uint8_t v);     // 0xcc + 1 BE byte
    void uint16(uint16_t v);   // 0xcd + 2 BE bytes
    void uint32(uint32_t v);   // 0xce + 4 BE bytes

    // float32 — 0xca + 4 BE bytes (IEEE-754 single).
    void float32(float v);

    // Accumulated bytes.
    const Bytes& bytes() const { return _buf; }

private:
    Bytes _buf;
};

} } // namespace rns::msgpack
