#include "rns/tables/AnnounceTable.h"

#include <utility>

namespace rns {

std::string AnnounceTable::key_of(const Bytes& b) { return b.to_hex(); }

void AnnounceTable::put(AnnounceEntry entry) {
    auto k = key_of(entry.dest_hash);
    _entries[k] = std::move(entry);
}

bool AnnounceTable::remove(const Bytes& dest_hash) {
    return _entries.erase(key_of(dest_hash)) != 0;
}

const AnnounceEntry* AnnounceTable::get(const Bytes& dest_hash) const {
    auto it = _entries.find(key_of(dest_hash));
    return (it == _entries.end()) ? nullptr : &it->second;
}

std::vector<AnnounceEntry> AnnounceTable::pop_due(uint64_t now_ms) {
    std::vector<AnnounceEntry> due;
    for (auto it = _entries.begin(); it != _entries.end(); ) {
        if (it->second.retransmit_at_ms <= now_ms) {
            due.push_back(std::move(it->second));
            it = _entries.erase(it);
        } else {
            ++it;
        }
    }
    return due;
}

} // namespace rns
