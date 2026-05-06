#include "ConfigStore.h"

#include <cstring>

#include "Storage.h"

namespace rlr { namespace config_store {

namespace {

// CRC-32 (IEEE 802.3 polynomial 0xEDB88320), bit-reflected. Used
// only here, so kept as a private static. Slow path (no table); we
// CRC ~120 bytes once per save / load — performance is irrelevant.
uint32_t crc32(const uint8_t* data, size_t len) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        c ^= data[i];
        for (int k = 0; k < 8; ++k) {
            c = (c >> 1) ^ (0xEDB88320u & -(c & 1u));
        }
    }
    return c ^ 0xFFFFFFFFu;
}

// CRC over `cfg` excluding the trailing `crc32` field itself. The
// struct is `#pragma pack(push, 1)` so layout is deterministic.
uint32_t crc_of_config(const Config& cfg) {
    constexpr size_t hashed_len = sizeof(Config) - sizeof(uint32_t);
    return crc32(reinterpret_cast<const uint8_t*>(&cfg), hashed_len);
}

} // namespace

bool load(Config& out) {
    if (!storage::exists(PATH)) return false;

    Config tmp;
    int n = storage::load_file(
        PATH, reinterpret_cast<uint8_t*>(&tmp), sizeof(tmp));
    if (n != static_cast<int>(sizeof(tmp))) return false;

    // Schema gate — bump `version` in Config.h when fields change
    // shape. Old persisted blobs then fall back to defaults rather
    // than being mis-interpreted as the new shape.
    if (tmp.version != Config{}.version) return false;

    if (tmp.crc32 != crc_of_config(tmp)) return false;

    out = tmp;
    return true;
}

bool save(const Config& cfg) {
    Config to_write = cfg;
    to_write.crc32 = crc_of_config(to_write);

    // Diff-before-write per `flash_wear_minimize_writes` memory: read
    // the existing file (if any) and skip the flash op when it's
    // byte-identical to what we'd write. Reads are cheap, writes
    // burn cycles.
    if (storage::exists(PATH)) {
        Config existing;
        int n = storage::load_file(
            PATH, reinterpret_cast<uint8_t*>(&existing), sizeof(existing));
        if (n == static_cast<int>(sizeof(existing))
            && std::memcmp(&existing, &to_write, sizeof(Config)) == 0) {
            return true;  // already up-to-date — no flash write
        }
    }

    return storage::save_file(
        PATH, reinterpret_cast<const uint8_t*>(&to_write), sizeof(to_write));
}

}} // namespace rlr::config_store
