// src/main.cpp — firmware entry point.
//
// `#ifdef ARDUINO` guards the entire body so native test envs can
// include src/* without trying to compile Arduino-specific code.
// The translation unit still gets built on native; it just produces
// no symbols and the linker ignores it.

#ifdef ARDUINO

#include <Arduino.h>

#include <utility>

#include "Config.h"
#include "Radio.h"

#include "rns/Bytes.h"
#include "rns/Identity.h"
#include "rns/Interface.h"
#include "rns/LoRaInterface.h"
#include "rns/Transport.h"

namespace {

// Placeholder identity for v0 firmware boot. Real firmware will load
// from flash via Storage / Config (later PR). Hardcoded for now.
//
// SECURITY NOTE: every device flashed with this build shares the
// same identity, which means cross-device messaging is broken AND a
// captured device leaks its priv. Acceptable for "does it boot and
// peer" bring-up; not for deployment.
constexpr const char* PLACEHOLDER_PRIV_HEX =
    "00000000000000000000000000000000000000000000000000000000000000aa"
    "00000000000000000000000000000000000000000000000000000000000000bb";

// LoRa effective bitrate at SF7 / BW250 / CR4/5 ≈ 10937 bps. Used
// for the §12.3.1 announce-cap budget. Approximate — the cap is a
// pacing hint, not a hard schedule, so being off by 2x is fine.
// Recompute when Config gets used to derive runtime SF/BW/CR.
constexpr uint32_t LORA_EFFECTIVE_BPS_DEFAULT = 10937u;

rns::Transport*     g_transport  = nullptr;
rns::LoRaInterface* g_lora_iface = nullptr;
rlr::Config         g_cfg;        // hardcoded defaults from Config.h

}  // namespace

void setup() {
    Serial.begin(115200);
    delay(50);
    Serial.println(F("rlr: setup begin"));

    // Radio bring-up.
    if (!rlr::radio::init_hardware()) {
        Serial.println(F("rlr: radio init_hardware FAILED"));
    } else if (!rlr::radio::begin(g_cfg)) {
        Serial.println(F("rlr: radio begin() FAILED"));
    } else if (!rlr::radio::start_rx()) {
        Serial.println(F("rlr: radio start_rx() FAILED"));
    }

    // Identity + Transport.
    auto identity = rns::Identity::from_private_bytes(
        rns::Bytes::from_hex(PLACEHOLDER_PRIV_HEX));
    g_transport = new rns::Transport(std::move(identity),
                                     /*transport_enabled=*/true);

    // LoRaInterface — wraps the Interface base with a TX callback
    // that funnels into rlr::radio::transmit. RX is driven from
    // loop() below via rlr::radio::read_pending → transport.inbound.
    rns::Interface::Config iface_cfg;
    iface_cfg.bitrate_bps          = LORA_EFFECTIVE_BPS_DEFAULT;
    iface_cfg.announce_cap_pct     = 2.0f;
    iface_cfg.airtime_window_ms    = 60ULL * 60ULL * 1000ULL;  // 1h rolling
    iface_cfg.max_queued_announces = 64;
    iface_cfg.hw_mtu_bytes         = 500;  // RNS Reticulum.MTU default
    g_lora_iface = new rns::LoRaInterface(iface_cfg,
        [](const uint8_t* p, size_t n) -> int {
            return rlr::radio::transmit(p, n);
        });
    g_transport->register_interface(g_lora_iface);

    Serial.println(F("rlr: setup complete — Transport + LoRa interface ready"));
}

void loop() {
    if (!g_transport) return;

    g_transport->tick(millis());

    // Drain any RX from the radio and route to Transport.inbound. The
    // radio's read_pending handles RNode split-packet reassembly
    // internally, so what we get here is already a logical packet.
    if (rlr::radio::rx_pending()) {
        uint8_t buf[512];
        int n = rlr::radio::read_pending(buf, sizeof(buf));
        if (n > 0) {
            rns::Bytes wire(buf, static_cast<size_t>(n));
            g_transport->inbound(g_lora_iface, wire, millis());
        }
    }

    delay(2);
}

#endif  // ARDUINO
