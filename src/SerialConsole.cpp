#include "SerialConsole.h"

#include <Arduino.h>

#include "rns/Bytes.h"

namespace rlr { namespace serial_console {

namespace {

// Hard cap on accepted frame size. Real config requests / responses
// are well under 200 bytes; setting the cap at 1 KiB gives plenty of
// headroom for future commands without inviting unbounded memory
// allocation from a misbehaving / malicious peer on the cable.
constexpr size_t MAX_FRAME_LEN = 1024;

enum class State : uint8_t { LEN_HI, LEN_LO, PAYLOAD };

State    s_state    = State::LEN_HI;
uint16_t s_expected = 0;
size_t   s_received = 0;
uint8_t  s_buf[MAX_FRAME_LEN];

void reset() {
    s_state    = State::LEN_HI;
    s_expected = 0;
    s_received = 0;
}

void send_response(const rns::Bytes& resp) {
    // Shouldn't happen — ConfigProtocol responses are well under
    // MAX_FRAME_LEN — but guard the cast since uint16 is the wire
    // type. Drop oversize silently rather than corrupt the frame.
    if (resp.size() > 0xFFFFu) return;
    const uint16_t n = static_cast<uint16_t>(resp.size());
    Serial.write(static_cast<uint8_t>((n >> 8) & 0xFF));
    Serial.write(static_cast<uint8_t>(n & 0xFF));
    Serial.write(resp.data(), resp.size());
}

}  // namespace

void tick(rlr::Config& cfg,
          rns::Transport* transport,
          rlr::config_protocol::SaveFn save) {
    while (Serial.available() > 0) {
        const int c = Serial.read();
        if (c < 0) break;
        const uint8_t b = static_cast<uint8_t>(c);

        switch (s_state) {
            case State::LEN_HI:
                s_expected = static_cast<uint16_t>(b) << 8;
                s_state    = State::LEN_LO;
                break;

            case State::LEN_LO:
                s_expected |= b;
                if (s_expected == 0 || s_expected > MAX_FRAME_LEN) {
                    // Implausible length — reset and wait for the
                    // next start-of-frame. The webapp's framing layer
                    // can recover by sending a fresh complete frame.
                    reset();
                    break;
                }
                s_received = 0;
                s_state    = State::PAYLOAD;
                break;

            case State::PAYLOAD:
                s_buf[s_received++] = b;
                if (s_received >= s_expected) {
                    rns::Bytes req(s_buf, s_expected);
                    rns::Bytes resp = rlr::config_protocol::handle_request(
                        req, cfg, transport, save);
                    send_response(resp);
                    reset();
                }
                break;
        }
    }
}

}}  // namespace rlr::serial_console
