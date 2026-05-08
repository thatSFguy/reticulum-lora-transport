#include "rns/tables/PathTable.h"

#include <algorithm>

namespace rns {

std::string PathTable::key_of(const Bytes& b) {
    return b.to_hex();
}

void PathTable::put(const Bytes& dest_hash, PathEntry entry) {
    _entries[key_of(dest_hash)] = std::move(entry);
}

const PathEntry* PathTable::get(const Bytes& dest_hash) const {
    auto it = _entries.find(key_of(dest_hash));
    return (it == _entries.end()) ? nullptr : &it->second;
}

PathEntry* PathTable::get_mut(const Bytes& dest_hash) {
    auto it = _entries.find(key_of(dest_hash));
    return (it == _entries.end()) ? nullptr : &it->second;
}

bool PathTable::remove(const Bytes& dest_hash) {
    return _entries.erase(key_of(dest_hash)) != 0;
}

bool PathTable::note_random_blob(const Bytes& dest_hash, const Bytes& blob) {
    PathEntry* entry = get_mut(dest_hash);
    if (!entry) return false;

    // Linear scan over a bounded (≤ MAX_RANDOM_BLOBS) vector — fine.
    for (const Bytes& seen : entry->random_blobs) {
        if (seen == blob) return false;
    }
    entry->random_blobs.push_back(blob);
    if (entry->random_blobs.size() > MAX_RANDOM_BLOBS) {
        entry->random_blobs.erase(entry->random_blobs.begin());
    }
    return true;
}

size_t PathTable::evict_expired(uint64_t now_ms, EvictObserverFn on_evict) {
    size_t removed = 0;
    for (auto it = _entries.begin(); it != _entries.end(); ) {
        if (it->second.expires_ms <= now_ms) {
            if (on_evict) on_evict(it->first, it->second.expires_ms, now_ms);
            it = _entries.erase(it);
            removed++;
        } else {
            ++it;
        }
    }
    return removed;
}

} // namespace rns
