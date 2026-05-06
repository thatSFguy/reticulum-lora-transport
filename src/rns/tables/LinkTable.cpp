#include "rns/tables/LinkTable.h"

#include <utility>

namespace rns {

std::string LinkTable::key_of(const Bytes& b) { return b.to_hex(); }

void LinkTable::put(LinkEntry entry) {
    auto k = key_of(entry.link_id);
    _entries[k] = std::move(entry);
}

const LinkEntry* LinkTable::get(const Bytes& link_id) const {
    auto it = _entries.find(key_of(link_id));
    return (it == _entries.end()) ? nullptr : &it->second;
}

LinkEntry* LinkTable::get_mut(const Bytes& link_id) {
    auto it = _entries.find(key_of(link_id));
    return (it == _entries.end()) ? nullptr : &it->second;
}

bool LinkTable::remove(const Bytes& link_id) {
    return _entries.erase(key_of(link_id)) != 0;
}

size_t LinkTable::evict_unproven(uint64_t now_ms) {
    size_t removed = 0;
    for (auto it = _entries.begin(); it != _entries.end(); ) {
        const LinkEntry& e = it->second;
        if (!e.validated && e.proof_timeout_ms != 0 && e.proof_timeout_ms <= now_ms) {
            it = _entries.erase(it);
            removed++;
        } else {
            ++it;
        }
    }
    return removed;
}

} // namespace rns
