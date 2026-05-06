// src/rns/Interface.h — SPEC §12.3.1 outbound announce cap.
//
// Abstract base for a Reticulum interface (LoRa, TCP, BLE, …). The
// base class manages the outbound announce queue and enforces the 2%
// airtime cap (`Reticulum.ANNOUNCE_CAP`); concrete interfaces
// implement `on_transmit` to push bytes onto their physical medium.
//
// Time is supplied externally to `tick()` rather than read via
// `millis()`, because per CLAUDE.md the `src/rns/` tree is portable
// C++17 and must not include Arduino headers. Firmware glue passes
// `millis()` (or platform equivalent) at the call site.
//
// Inbound rate limiting (§4.5 step 8 `held_announces`) is NOT in this
// header. It needs Transport-layer state (path_table, path_requests)
// to decide whether to hold an announce; that lands with Transport.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rns/Bytes.h"

namespace rns {

class Interface {
public:
    // §12.3.1 — `Reticulum.ANNOUNCE_CAP = 2.0` (percent of airtime).
    static constexpr float DEFAULT_ANNOUNCE_CAP_PCT = 2.0f;

    // §3177 — `Reticulum.MAX_QUEUED_ANNOUNCES` default ~64.
    static constexpr size_t DEFAULT_MAX_QUEUED_ANNOUNCES = 64;

    // Rolling window over which the cap is computed. RNS's exact
    // window length is implementation-private; 1 hour is a reasonable
    // default that matches the AP_PATH_TIME order-of-magnitude.
    static constexpr uint64_t DEFAULT_AIRTIME_WINDOW_MS = 60ULL * 60ULL * 1000ULL;

    struct Config {
        // Effective on-air bitrate in bits/sec. For LoRa, derived from
        // SF / BW / CR (§8 / RNode firmware). For TCP, the link rate.
        // Required (must be > 0) for budget calculation.
        uint32_t bitrate_bps          = 0;
        float    announce_cap_pct     = DEFAULT_ANNOUNCE_CAP_PCT;
        size_t   max_queued_announces = DEFAULT_MAX_QUEUED_ANNOUNCES;
        uint64_t airtime_window_ms    = DEFAULT_AIRTIME_WINDOW_MS;

        // §6.6 / §12.2.4 — Hardware MTU in bytes, used by the
        // LINKREQUEST forward path to clamp the requested link MTU
        // when it exceeds what this interface can carry. Default
        // UINT32_MAX = "no clamp" (preserves existing test behaviour
        // where signalling is forwarded as-is). Real LoRa interfaces
        // typically set this to ~508 (RNS Reticulum.MTU constant).
        uint32_t hw_mtu_bytes         = 0xFFFFFFFFu;
    };

    explicit Interface(const Config& cfg);
    virtual ~Interface() = default;

    Interface(const Interface&) = delete;
    Interface& operator=(const Interface&) = delete;

    // Queue an outbound announce. `wire` is the fully-packed announce
    // (header + body). `hops` drives drain priority (lowest first).
    // Returns false if the queue is full — caller may retry later.
    bool queue_announce(const Bytes& wire, uint8_t hops);

    // Send wire bytes immediately, bypassing the announce queue. Used
    // for DATA / LINKREQUEST / PROOF — §12.3.1 caps only announces,
    // so these don't compete for the announce budget. Counts toward
    // total link utilization but not toward the announce cap.
    void transmit_now(const Bytes& wire);

    // Periodic drive. Pops queued announces in lowest-hops-first order
    // for as long as the rolling-window airtime budget permits, then
    // returns. Non-blocking; safe to call frequently.
    void tick(uint64_t now_ms);

    // Stats / introspection — used by tests and Transport's pacing
    // decisions.
    bool   has_pending_announce() const { return !_queue.empty(); }
    size_t queue_depth()          const { return _queue.size(); }
    uint64_t airtime_used_ms_in_window(uint64_t now_ms);

    // §6.6 — used by Transport's LINKREQUEST forward to clamp link
    // MTU signalling when this interface is the outbound hop.
    uint32_t hw_mtu_bytes() const { return _cfg.hw_mtu_bytes; }

protected:
    // Derived classes (LoraInterface, etc.) push these bytes onto the
    // physical medium. Called from `tick()` and `transmit_now()`. The
    // base class assumes success; failure handling lives in the
    // concrete impl.
    virtual void on_transmit(const Bytes& wire) = 0;

private:
    struct QueueEntry { Bytes wire; uint8_t hops; };
    struct EmitRecord { uint64_t when_ms; uint64_t airtime_ms; };

    Config _cfg;
    std::vector<QueueEntry> _queue;
    std::vector<EmitRecord> _emits;

    uint64_t airtime_for_bytes(size_t n_bytes) const;
    uint64_t window_cap_ms() const;
    void     prune_old_emits(uint64_t now_ms);
    bool     budget_allows(uint64_t now_ms, uint64_t needed_ms);
};

} // namespace rns
