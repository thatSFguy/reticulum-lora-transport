#include "rns/tables/ReverseTable.h"

#include <utility>

namespace rns {

std::string ReverseTable::key_of(const Bytes& b) { return b.to_hex(); }

void ReverseTable::put(ReverseEntry entry) {
    auto k = key_of(entry.packet_hash);
    _entries[k] = std::move(entry);
}

std::optional<ReverseEntry> ReverseTable::pop(const Bytes& packet_hash) {
    auto it = _entries.find(key_of(packet_hash));
    if (it == _entries.end()) return std::nullopt;
    ReverseEntry out = std::move(it->second);
    _entries.erase(it);
    return out;
}

const ReverseEntry* ReverseTable::get(const Bytes& packet_hash) const {
    auto it = _entries.find(key_of(packet_hash));
    return (it == _entries.end()) ? nullptr : &it->second;
}

size_t ReverseTable::evict_aged(uint64_t now_ms) {
    size_t removed = 0;
    for (auto it = _entries.begin(); it != _entries.end(); ) {
        if (it->second.timestamp_ms + REVERSE_TIMEOUT_MS <= now_ms) {
            it = _entries.erase(it);
            removed++;
        } else {
            ++it;
        }
    }
    return removed;
}

} // namespace rns
