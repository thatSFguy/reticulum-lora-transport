// src/rns/LoRaInterface.h — Interface bridge to a LoRa-radio TX hook.
//
// Spec-layer (src/rns/) class with no Arduino dependencies. The
// firmware-glue layer wires up the actual `rlr::radio::transmit` (or
// any other LoRa transmit primitive) via a std::function callback at
// construction time. RX is driven from outside: the firmware's loop
// calls `rlr::radio::read_pending`, then `transport.inbound(this,
// wire, now_ms)` directly — LoRaInterface itself is a pure
// outbound/queue surface.
//
// This separation keeps the spec layer linkable on the native
// host-test env (no `rlr::radio` symbols required) while allowing
// the firmware to register a real LoRaInterface against Transport.

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <utility>

#include "rns/Bytes.h"
#include "rns/Interface.h"

namespace rns {

class LoRaInterface : public Interface {
public:
    // Returns 0 (or positive bytes-sent) on success, negative on
    // hardware error. Called once per outbound packet from the
    // Interface base's queue/transmit_now path.
    using TransmitFn = std::function<int(const uint8_t* data, size_t len)>;

    LoRaInterface(const Interface::Config& cfg, TransmitFn tx)
        : Interface(cfg), _tx(std::move(tx)) {}

protected:
    void on_transmit(const Bytes& wire) override {
        if (_tx) _tx(wire.data(), wire.size());
    }

private:
    TransmitFn _tx;
};

} // namespace rns
