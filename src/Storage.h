#pragma once
// src/Storage.h — thin file-I/O abstraction over Adafruit's
// InternalFS (littlefs on the nRF52's internal flash partition).
//
// Pure C-style API — no Arduino types in the header — so files
// outside src/ that need persistence can include this without
// pulling Adafruit headers transitively. Implementation lives in
// Storage.cpp and is excluded from the native build.
//
// Usage pattern:
//   if (!rlr::storage::init()) { /* mount failed */ }
//   if (rlr::storage::exists("/identity.bin")) { ... }
//   rlr::storage::save_file("/identity.bin", priv, 64);
//   int n = rlr::storage::load_file("/identity.bin", buf, sizeof(buf));
//
// Per memory `flash_wear_minimize_writes`: callers MUST diff against
// the in-flash version before issuing a write. nRF52 internal flash
// is rated for ~10k cycles/page; naive save-on-every-change will
// brick the device in days.

#include <cstddef>
#include <cstdint>

namespace rlr { namespace storage {

// Mount the internal-flash filesystem. Idempotent — safe to call
// multiple times. Returns true on success. Call once during setup()
// before any other Storage call.
bool init();

// Returns true if `path` exists on the mounted filesystem.
bool exists(const char* path);

// Read up to `bufsize` bytes from `path` into `buf`. Returns the
// number of bytes actually read on success (which may be less than
// the file's full size if `bufsize` was the limiter), 0 on empty
// file, or -1 on error (file missing, mount not initialised, etc.).
int load_file(const char* path, uint8_t* buf, size_t bufsize);

// Write `len` bytes from `data` to `path`, replacing any existing
// file at that path. Returns true on success. Caller is responsible
// for the flash-wear discipline — no diff-before-write here.
bool save_file(const char* path, const uint8_t* data, size_t len);

// Remove the file at `path`. Returns true if it existed and was
// removed, false otherwise.
bool remove_file(const char* path);

}} // namespace rlr::storage
