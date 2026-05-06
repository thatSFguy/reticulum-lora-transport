#pragma once
// src/ConfigStore.h — load/save the Config struct via Storage with
// CRC32 integrity check.
//
// Diff-before-write per memory `flash_wear_minimize_writes`:
// save() computes CRC over the new struct, reads back the on-flash
// version, and only issues a flash write if the CRC differs (or the
// file doesn't exist). Cheap; bounds wear regardless of how often
// callers invoke save().

#include <cstdint>

#include "Config.h"

namespace rlr { namespace config_store {

constexpr const char* PATH = "/config.bin";

// Read the persisted Config. On success, copies the on-flash struct
// into `out` and returns true. Returns false on missing file,
// version mismatch (schema upgrade boundary — caller should fall
// back to defaults), CRC failure (corrupted), or I/O error. `out`
// is unmodified on failure.
bool load(Config& out);

// Persist `cfg` to flash. Recomputes crc32 over the struct (excluding
// the crc32 field itself), then diff-then-writes — skips the flash
// op if the new bytes match what's already there. Returns true on
// success or no-write-needed; false on I/O error.
bool save(const Config& cfg);

}} // namespace rlr::config_store
