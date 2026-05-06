#include "rns/Destination.h"

#include <stdexcept>
#include <utility>

#include "rns/Crypto.h"
#include "rns/Packet.h"

namespace rns {

Destination::Destination(Identity identity, std::string app_name)
    : _identity(std::move(identity)),
      _app_name(std::move(app_name)),
      _name_hash(Identity::name_hash(_app_name)),
      _dest_hash(Identity::destination_hash_for(_app_name,
                                                _identity.identity_hash())) {}

Bytes Destination::build_announce(const Bytes& random_prefix,
                                  uint64_t timestamp_secs,
                                  const Bytes& app_data,
                                  const Bytes& ratchet_pub,
                                  bool path_response) const {
    if (random_prefix.size() != 5) {
        throw std::invalid_argument(
            "Destination::build_announce: random_prefix must be 5 bytes");
    }
    if (!ratchet_pub.empty() && ratchet_pub.size() != 32) {
        throw std::invalid_argument(
            "Destination::build_announce: ratchet_pub must be 32 bytes or empty");
    }
    if (_identity.private_key().size() != Identity::PRIV_KEY_LEN) {
        throw std::invalid_argument(
            "Destination::build_announce: identity has no private key");
    }

    // §4.1 random_hash = 5-byte random || 5-byte big-endian uint40 unix-secs.
    Bytes random_hash;
    random_hash.append(random_prefix);
    for (int i = 4; i >= 0; --i) {
        random_hash.append(static_cast<uint8_t>((timestamp_secs >> (i * 8)) & 0xFF));
    }

    // §4.2 signed_data = dest_hash || public_key || name_hash ||
    // random_hash || [ratchet_pub] || app_data. ratchet_pub is empty
    // (zero bytes), NOT absent, when context_flag is 0. app_data is
    // empty when omitted.
    Bytes signed_data;
    signed_data.append(_dest_hash);
    signed_data.append(_identity.public_key());
    signed_data.append(_name_hash);
    signed_data.append(random_hash);
    signed_data.append(ratchet_pub);
    signed_data.append(app_data);

    Bytes ed_priv   = _identity.ed25519_priv();
    Bytes signature = crypto::ed25519_sign(ed_priv,
                                           signed_data.data(),
                                           signed_data.size());

    // §4.1 body = public_key || name_hash || random_hash ||
    // [ratchet_pub] || signature || app_data. Note signature is in
    // the body (§4.1) but NOT in signed_data (§4.2).
    Bytes body;
    body.append(_identity.public_key());
    body.append(_name_hash);
    body.append(random_hash);
    body.append(ratchet_pub);
    body.append(signature);
    body.append(app_data);

    // §2.1 flags for an announce:
    //   HEADER_1 (00) | (context_flag if ratchet) | BROADCAST (0) |
    //   SINGLE (00) | ANNOUNCE (01)
    uint8_t flags = 0x01;
    if (!ratchet_pub.empty()) flags |= 0x20;

    const uint8_t context = path_response
        ? Packet::CONTEXT_PATH_RESPONSE
        : Packet::CONTEXT_NONE;

    return Packet::pack_header_1(flags, /*hops=*/0, _dest_hash,
                                 context, body);
}

} // namespace rns
