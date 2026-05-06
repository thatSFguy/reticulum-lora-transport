// src/rns/Bytes.h — minimal byte buffer for the RNS stack.
//
// Owns its storage. Move-friendly. No reference-counted shared data
// (microReticulum's Bytes used SharedData; we don't — keeps the
// ownership story simple). Exposes hex round-trip for test vectors.

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace rns {

class Bytes {
public:
    Bytes() = default;
    Bytes(const uint8_t* data, size_t len) : _data(data, data + len) {}
    Bytes(std::initializer_list<uint8_t> il) : _data(il) {}
    explicit Bytes(size_t len) : _data(len, 0) {}

    static Bytes from_hex(const std::string& hex);
    std::string to_hex() const;

    const uint8_t* data() const { return _data.data(); }
    uint8_t* data() { return _data.data(); }
    size_t size() const { return _data.size(); }
    bool empty() const { return _data.empty(); }

    void resize(size_t n) { _data.resize(n); }
    void append(const uint8_t* data, size_t len) { _data.insert(_data.end(), data, data + len); }
    void append(const Bytes& other) { append(other.data(), other.size()); }
    void append(uint8_t b) { _data.push_back(b); }

    // Slice — returns a new Bytes covering [offset, offset+len).
    // Clamps to the buffer's size; len == npos means "to end".
    static constexpr size_t npos = static_cast<size_t>(-1);
    Bytes slice(size_t offset, size_t len = npos) const;

    bool operator==(const Bytes& other) const { return _data == other._data; }
    bool operator!=(const Bytes& other) const { return !(*this == other); }

    uint8_t operator[](size_t i) const { return _data[i]; }
    uint8_t& operator[](size_t i) { return _data[i]; }

private:
    std::vector<uint8_t> _data;
};

} // namespace rns
