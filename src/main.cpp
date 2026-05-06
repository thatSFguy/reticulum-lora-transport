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
#include "Storage.h"

#include "rns/Bytes.h"
#include "rns/Identity.h"
#include "rns/Interface.h"
#include "rns/LoRaInterface.h"
#include "rns/Transport.h"

namespace {

constexpr const char* IDENTITY_FILE = "/identity.bin";

// LoRa effective bitrate at SF7 / BW250 / CR4/5 ≈ 10937 bps. Used
// for the §12.3.1 announce-cap budget. Approximate — the cap is a
// pacing hint, not a hard schedule, so being off by 2x is fine.
// Recompute when Config gets used to derive runtime SF/BW/CR.
constexpr uint32_t LORA_EFFECTIVE_BPS_DEFAULT = 10937u;

rns::Transport*     g_transport  = nullptr;
rns::LoRaInterface* g_lora_iface = nullptr;
rlr::Config         g_cfg;        // hardcoded defaults from Config.h

// Load the persisted Identity from /identity.bin on internal flash,
// or generate a fresh 64-byte priv (X25519(32) || Ed25519(32)) using
// the SX1262's RNG and save it. Returns the constructed Identity.
//
// First-boot generation is the security-critical path. The radio's
// random_byte() pulls from the chip's RSSI-noise-floor entropy
// source — adequate for a one-shot 64-byte draw, not high-rate.
//
// Per memory `flash_wear_minimize_writes`: the priv only gets
// written ONCE per device lifetime (first-boot generation). All
// subsequent boots load from flash with no write.
rns::Identity load_or_generate_identity() {
    uint8_t priv[64];
    int n = rlr::storage::load_file(IDENTITY_FILE, priv, sizeof(priv));
    if (n == 64) {
        Serial.println(F("rlr: identity loaded from flash"));
        return rns::Identity::from_private_bytes(rns::Bytes(priv, 64));
    }

    Serial.println(F("rlr: no stored identity — generating fresh"));
    for (int i = 0; i < 64; ++i) priv[i] = rlr::radio::random_byte();
    if (!rlr::storage::save_file(IDENTITY_FILE, priv, 64)) {
        Serial.println(F("rlr: WARNING — failed to persist identity, "
                          "will regenerate next boot"));
    }
    return rns::Identity::from_private_bytes(rns::Bytes(priv, 64));
}

}  // namespace

void setup() {
    Serial.begin(115200);
    delay(50);
    Serial.println(F("rlr: setup begin"));

    // Storage MUST mount before identity load — load_or_generate
    // calls rlr::storage::load_file. Failures here are non-fatal
    // (we'll just regenerate identity on every boot — bad but boots).
    if (!rlr::storage::init()) {
        Serial.println(F("rlr: WARNING — storage init failed; "
                          "identity will not persist"));
    }

    // Radio bring-up MUST precede identity generation — random_byte()
    // requires begin() to have run.
    if (!rlr::radio::init_hardware()) {
        Serial.println(F("rlr: radio init_hardware FAILED"));
    } else if (!rlr::radio::begin(g_cfg)) {
        Serial.println(F("rlr: radio begin() FAILED"));
    } else if (!rlr::radio::start_rx()) {
        Serial.println(F("rlr: radio start_rx() FAILED"));
    }

    // Identity + Transport. Loaded from flash if present, otherwise
    // generated fresh from the radio's RNG and persisted.
    auto identity = load_or_generate_identity();
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
