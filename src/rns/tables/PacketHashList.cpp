#include "rns/tables/PacketHashList.h"

namespace rns {

PacketHashList::PacketHashList(size_t max_size) : _max(max_size) {}

std::string PacketHashList::key_of(const Bytes& b) {
    return b.to_hex();
}

bool PacketHashList::insert(const Bytes& hash) {
    auto k = key_of(hash);
    auto [_, inserted] = _set.insert(k);
    if (!inserted) return false;
    _order.push_back(hash);
    return true;
}

bool PacketHashList::contains(const Bytes& hash) const {
    return _set.count(key_of(hash)) != 0;
}

size_t PacketHashList::purge_if_over_cap() {
    if (_order.size() <= _max) return 0;
    const size_t drop = _order.size() / 2;
    for (size_t i = 0; i < drop; i++) {
        _set.erase(key_of(_order[i]));
    }
    _order.erase(_order.begin(), _order.begin() + drop);
    return drop;
}

} // namespace rns
