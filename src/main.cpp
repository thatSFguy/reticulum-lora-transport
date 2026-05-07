// src/main.cpp — firmware entry point.
//
// `#ifdef ARDUINO` guards the entire body so native test envs can
// include src/* without trying to compile Arduino-specific code.
// The translation unit still gets built on native; it just produces
// no symbols and the linker ignores it.

#ifdef ARDUINO

#include <Arduino.h>

#include <utility>

#include "Battery.h"
#include "Ble.h"
#include "Config.h"
#include "ConfigProtocol.h"
#include "ConfigStore.h"
#include "Led.h"
#include "Radio.h"
#include "SerialConsole.h"
#include "Storage.h"

#include "rns/Bytes.h"
#include "rns/Destination.h"
#include "rns/Identity.h"
#include "rns/Interface.h"
#include "rns/LoRaInterface.h"
#include "rns/Telemetry.h"
#include "rns/Transport.h"

namespace {

constexpr const char* IDENTITY_FILE = "/identity.bin";

// LoRa effective bitrate at the deployment defaults
// (SF10 / BW250 / CR4/5):
//   bitrate ≈ (SF * BW * 4) / (2^SF * CR_denom)
//           = (10 * 250000 * 4) / (1024 * 5)
//           ≈ 1953 bps
// Used for the §12.3.1 announce-cap budget. Approximate — the cap
// is a pacing hint, not a hard schedule, so being off by 2x is fine.
// Recompute on the fly when Config drives runtime SF/BW/CR (lands
// when SerialConsole / BLE allow setting them at runtime).
constexpr uint32_t LORA_EFFECTIVE_BPS_DEFAULT = 1953u;

// Per memory transport_node_telemetry_beacon (cadence option b):
// lightweight 5-min "alive" announce keeps paths fresh per §7.5,
// 2h "full" beacon carries the metrics payload along the warm path.
constexpr uint64_t TELEMETRY_ALIVE_PERIOD_MS  = 5ULL * 60ULL * 1000ULL;
constexpr uint64_t TELEMETRY_BEACON_PERIOD_MS = 2ULL * 60ULL * 60ULL * 1000ULL;
constexpr const char* TELEMETRY_DEST_NAME = "transport.telemetry";

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
// Source of (random_prefix, unix_seconds) for outbound announce
// construction. random_prefix comes from the SX1262's RNG (5 bytes).
// unix_seconds is millis()/1000 — seconds-since-boot, NOT real wall
// clock. Per §9.6 / memory transport_node_telemetry_beacon, peers
// tolerate clockless senders by treating implausible timestamps as
// "no clock" and substituting receive time. Real wall-clock time
// would require an RTC or a network sync; out of scope for this
// firmware.
rns::AnnounceSeed announce_seed_fn() {
    rns::Bytes prefix(5);
    for (size_t i = 0; i < 5; ++i) prefix[i] = rlr::radio::random_byte();
    return rns::AnnounceSeed{ std::move(prefix), millis() / 1000ULL };
}

// Build the §telemetry-beacon payload per memory
// transport_node_telemetry_beacon's frozen schema. Field stability
// is the contract; Stats counters can evolve internally without
// breaking the wire format.
rns::telemetry::Snapshot make_telemetry_snapshot() {
    rns::telemetry::Snapshot s;

    // lat/lon are manually configured via the webapp (per memory).
    // Both fields stored as microdegrees in Config; 0/0 = unset.
    if (g_cfg.latitude_udeg != 0 || g_cfg.longitude_udeg != 0) {
        s.have_position = true;
        s.lat = static_cast<float>(g_cfg.latitude_udeg) / 1000000.0f;
        s.lon = static_cast<float>(g_cfg.longitude_udeg) / 1000000.0f;
    }

    s.battery_mv = rlr::battery::read_mv(g_cfg.batt_mult);

    s.name = g_cfg.display_name;  // [8] — operator label or auto "Rptr-XXXXXXXX"

    if (g_transport) {
        s.route_count = static_cast<uint16_t>(
            g_transport->path_table().size());
        const auto& st = g_transport->stats();
        // [4] aggregate — what a network-health dashboard would chart
        // as "this node's relay throughput". Kept for backward compat.
        s.packets_forwarded = static_cast<uint32_t>(
            st.announces_rebroadcast +
            st.data_forwarded_header_1 +
            st.data_forwarded_header_2 +
            st.proof_forwarded +
            st.link_data_forwarded);
        // [5..7] discrete counters so a remote observer can verify
        // *what* the node is actually relaying without serial access.
        // §12.3 announce relays specifically — proves the relay path
        // is alive even when no DATA traffic is flowing.
        s.announces_rebroadcast = static_cast<uint32_t>(st.announces_rebroadcast);
        s.data_forwarded        = static_cast<uint32_t>(
            st.data_forwarded_header_1 + st.data_forwarded_header_2);
        s.inbound_packets       = static_cast<uint32_t>(st.inbound_packets);
    }
    return s;
}

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

    rlr::led::init();
    rlr::battery::init();

    // Storage MUST mount before identity load — load_or_generate
    // calls rlr::storage::load_file. Failures here are non-fatal
    // (we'll just regenerate identity on every boot — bad but boots).
    if (!rlr::storage::init()) {
        Serial.println(F("rlr: WARNING — storage init failed; "
                          "identity will not persist"));
    }

    // Load persisted Config if present, otherwise stick with the
    // hardcoded defaults from Config.h. CRC mismatch / version
    // bump / missing file all fall through to defaults — diagnostic
    // only.
    if (rlr::config_store::load(g_cfg)) {
        Serial.println(F("rlr: config loaded from flash"));
    } else {
        Serial.println(F("rlr: no valid config — using defaults"));
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

    // Stamp a unique default display_name on first boot so each
    // repeater is distinguishable on BLE scans and in the webapp's
    // device list. Format: "Rptr-XXXXXXXX" — first 4 bytes of
    // identity_hash hex (32 bits = 4 billion variations, plenty for
    // a small fleet, fits in BLE's name length cap). Persists once;
    // operator can override via the webapp.
    if (g_cfg.display_name[0] == '\0') {
        const auto& h = identity.identity_hash();
        snprintf(g_cfg.display_name, sizeof(g_cfg.display_name),
                 "Rptr-%02x%02x%02x%02x",
                 (unsigned)h[0], (unsigned)h[1],
                 (unsigned)h[2], (unsigned)h[3]);
        if (rlr::config_store::save(g_cfg)) {
            Serial.print(F("rlr: assigned default name: "));
            Serial.println(g_cfg.display_name);
        }
    }

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

    // Telemetry destination + scheduled announces (per memory
    // transport_node_telemetry_beacon). Same Identity as the
    // transport node itself — the dest_hash is stable across boots
    // because Identity persists.
    g_transport->set_announce_seed_fn(announce_seed_fn);

    // Tag every Transport-level emit with WHY we're transmitting. The
    // radio-layer log only knows the wire bytes; this disambiguates
    // own scheduled announces from rebroadcast vs path-response vs
    // DATA/PROOF/LINK forwards. Pairs with the next "Radio: TX ..."
    // line for a complete picture.
    g_transport->set_tx_observer([](rns::TxKind k) {
        const char* tag = "?";
        switch (k) {
            case rns::TxKind::OwnAnnounce:        tag = "own-announce";      break;
            case rns::TxKind::PathResponse:       tag = "path-response";     break;
            case rns::TxKind::Rebroadcast:        tag = "relay-announce";    break;
            case rns::TxKind::DataForward:        tag = "fwd-data";          break;
            case rns::TxKind::ProofForward:       tag = "fwd-proof";         break;
            case rns::TxKind::LinkForward:        tag = "fwd-link";          break;
            case rns::TxKind::PathRequestForward: tag = "fwd-path-request";  break;
        }
        Serial.print("rlr: tx ");
        Serial.println(tag);
    });

    // Surface every path-table insert/update on Serial so the operator
    // can watch the routing table grow as announces arrive. The first
    // 8 hex chars of the destination_hash are enough to disambiguate
    // in a small mesh; full hash printed on first sighting only.
    g_transport->set_path_observer([](const rns::PathUpdate& u) {
        Serial.print("rlr: path ");
        Serial.print(u.is_new ? "NEW " : "UPD ");
        Serial.print(u.destination_hash.to_hex().c_str());
        Serial.print("  hops=");
        Serial.print(u.hops);
        if (!u.next_hop.empty()) {
            Serial.print("  via=");
            Serial.print(u.next_hop.to_hex().substr(0, 8).c_str());
        } else {
            Serial.print("  (direct)");
        }
        Serial.println();
    });
    rns::Destination tel_dest(g_transport->local_identity(),
                              TELEMETRY_DEST_NAME);
    rns::Bytes tel_hash = tel_dest.destination_hash();
    g_transport->register_local_destination(std::move(tel_dest));
    // 5-min lightweight "alive" — empty app_data, just refreshes
    // path table entries on relays in earshot.
    g_transport->schedule_announce(tel_hash,
                                   TELEMETRY_ALIVE_PERIOD_MS,
                                   /*fn=*/nullptr);
    // 2-hour full beacon — encodes the Snapshot at emit time.
    g_transport->schedule_announce(tel_hash,
                                   TELEMETRY_BEACON_PERIOD_MS,
                                   []() {
                                       return rns::telemetry::encode(
                                           make_telemetry_snapshot());
                                   });

    // BLE config service. Same ConfigProtocol underneath as
    // SerialConsole — only the transport adapter differs. Failure
    // is non-fatal; SerialConsole still works.
    auto save_fn = [](const rlr::Config& c) -> bool {
        return rlr::config_store::save(c);
    };
    if (!rlr::ble::init(g_cfg, g_transport, save_fn)) {
        Serial.println(F("rlr: BLE init failed; Serial-only config available"));
    }

    Serial.println(F("rlr: setup complete — Transport + LoRa + telemetry + BLE ready"));
}

void loop() {
    if (!g_transport) return;

    const uint64_t now = millis();
    rlr::led::tick(now);
    g_transport->tick(now);

    // Drain any RX from the radio and route to Transport.inbound. The
    // radio's read_pending handles RNode split-packet reassembly
    // internally, so what we get here is already a logical packet.
    if (rlr::radio::rx_pending()) {
        uint8_t buf[512];
        int n = rlr::radio::read_pending(buf, sizeof(buf));
        if (n > 0) {
            rns::Bytes wire(buf, static_cast<size_t>(n));
            g_transport->inbound(g_lora_iface, wire, now);
        }
    }

    // Drain any pending Serial frames and dispatch to ConfigProtocol.
    // BLE has its own write-callback path so it doesn't need a tick.
    // The save callback is identical for both; ConfigStore.save's
    // diff-before-write keeps the flash discipline regardless of
    // which transport committed.
    rlr::serial_console::tick(g_cfg, g_transport,
        [](const rlr::Config& c) -> bool {
            return rlr::config_store::save(c);
        });

    delay(2);
}

#endif  // ARDUINO
