#include "rns/Interface.h"

#include <algorithm>

namespace rns {

Interface::Interface(const Config& cfg) : _cfg(cfg) {}

bool Interface::queue_announce(const Bytes& wire, uint8_t hops) {
    if (_queue.size() >= _cfg.max_queued_announces) return false;
    _queue.push_back({wire, hops});
    return true;
}

void Interface::transmit_now(const Bytes& wire) {
    on_transmit(wire);
}

uint64_t Interface::airtime_for_bytes(size_t n_bytes) const {
    if (_cfg.bitrate_bps == 0) return 0;
    // ms = bytes * 8 * 1000 / bitrate_bps. Integer math is fine —
    // sub-ms precision doesn't change the cap-vs-overshoot decision
    // any more than the rolling window's coarseness already does.
    return (static_cast<uint64_t>(n_bytes) * 8000ULL) / _cfg.bitrate_bps;
}

uint64_t Interface::window_cap_ms() const {
    return static_cast<uint64_t>(
        (_cfg.announce_cap_pct / 100.0f) *
        static_cast<float>(_cfg.airtime_window_ms));
}

void Interface::prune_old_emits(uint64_t now_ms) {
    const uint64_t cutoff = (now_ms > _cfg.airtime_window_ms)
                          ? now_ms - _cfg.airtime_window_ms
                          : 0;
    auto first_keep = std::find_if(_emits.begin(), _emits.end(),
        [cutoff](const EmitRecord& e) { return e.when_ms >= cutoff; });
    _emits.erase(_emits.begin(), first_keep);
}

uint64_t Interface::airtime_used_ms_in_window(uint64_t now_ms) {
    prune_old_emits(now_ms);
    uint64_t total = 0;
    for (const auto& e : _emits) total += e.airtime_ms;
    return total;
}

bool Interface::budget_allows(uint64_t now_ms, uint64_t needed_ms) {
    return airtime_used_ms_in_window(now_ms) + needed_ms <= window_cap_ms();
}

void Interface::tick(uint64_t now_ms) {
    // Drain greedily — emit every queued announce the budget can fit
    // in this call, lowest-hops first per §12.3.1. Caller pacing
    // (tick frequency) sets the upper rate; the cap sets the floor.
    while (!_queue.empty()) {
        auto pick = std::min_element(_queue.begin(), _queue.end(),
            [](const QueueEntry& a, const QueueEntry& b) {
                return a.hops < b.hops;
            });
        const uint64_t needed = airtime_for_bytes(pick->wire.size());
        if (!budget_allows(now_ms, needed)) break;

        Bytes wire = std::move(pick->wire);
        _queue.erase(pick);
        on_transmit(wire);
        _emits.push_back({now_ms, needed});
    }
}

} // namespace rns
