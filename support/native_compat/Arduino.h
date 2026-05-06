// support/native_compat/Arduino.h
//
// Minimal Arduino.h shim for the `native` PlatformIO env. Only on the
// include path for native builds (added via build_flags in
// platformio.ini); board envs use the real Arduino.h from their
// platform package.
//
// Background — rweather/Crypto's RNG.cpp does `#include <Arduino.h>`
// even though the rest of the library is portable C++. We only call
// the deterministic primitives (SHA256, Ed25519 verify/sign/derive,
// Curve25519::eval), so RNG.o never gets linked when Crypto is built
// as a static archive (PlatformIO's default). We just need RNG.cpp to
// COMPILE — the unresolved millis/micros references stay in the
// archive's RNG.o and the linker discards the .o entirely.
//
// Stubs return 0 (inline) so the file is also valid if someone ever
// does pull RNG.o into the link. This shim is intentionally NOT
// API-complete — board builds want the real Arduino.h.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

inline unsigned long millis() { return 0; }
inline unsigned long micros() { return 0; }
