// src/main.cpp — firmware entry point.
//
// Guarded by `#ifdef ARDUINO` so the native test envs (which don't
// supply Arduino's setup/loop entry points) skip compiling the body.
// The translation unit still gets built on native — it just produces
// no symbols and the linker ignores it.

#ifdef ARDUINO

#include <Arduino.h>

#include <utility>

#include "rns/Bytes.h"
#include "rns/Identity.h"
#include "rns/Transport.h"

namespace {

// Placeholder identity for the v0 firmware boot. Real firmware will
// load this from flash storage (Config / Storage modules — landing in
// later PRs once the board layer matures). Hardcoded for now so the
// firmware links and `loop()` has a Transport to drive.
//
// SECURITY NOTE: every device flashed with this build shares the
// same identity, which means cross-device messaging is broken AND a
// captured device leaks its priv to anyone with the binary. Acceptable
// for "does it boot and tick" bring-up; not acceptable for deployment.
constexpr const char* PLACEHOLDER_PRIV_HEX =
    "00000000000000000000000000000000000000000000000000000000000000aa"
    "00000000000000000000000000000000000000000000000000000000000000bb";

rns::Transport* g_transport = nullptr;

}  // namespace

void setup() {
    Serial.begin(115200);

    auto identity = rns::Identity::from_private_bytes(
        rns::Bytes::from_hex(PLACEHOLDER_PRIV_HEX));
    g_transport = new rns::Transport(std::move(identity),
                                     /*transport_enabled=*/true);

    // No interfaces registered yet — LoRaInterface lands in a
    // follow-up PR (it'll wrap src/Radio.cpp). Until then, Transport
    // just sits idle. tick() still runs the periodic jobs (table
    // eviction, hashlist purge), keeping memory bounded.

    Serial.println(F("rlr: Transport constructed, idling without interfaces"));
}

void loop() {
    if (g_transport) g_transport->tick(millis());
    delay(10);
}

#endif  // ARDUINO
