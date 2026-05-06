# CLAUDE.md

Guidance for Claude Code working in this repo.

## What this repo is

A clean-room C++ implementation of an RNS Transport node, pinned to the Reticulum wire-format spec. Successor to `../reticulum-lora-repeater`, which wrapped microReticulum and patched it via build-time string replacement.

The spec lives in `../reticulum-specifications/` (sibling repo). Test vectors at `../reticulum-specifications/test-vectors/{identities,announces,links,lxmf}.json` are the source of truth — every layer must validate against them.

## Architectural principles

- **Spec is canon.** When implementation and spec disagree, the spec wins. Cite section numbers in comments where behavior is non-obvious.
- **No vendored upstream library.** No `microReticulum`, no patching jobs in `pre_build.py`. The `src/rns/` tree implements RNS Transport directly.
- **Test-vector-driven.** Every primitive (Identity, Packet, IFAC, link KDF) has a `pio test -e native` test pinned to a JSON test vector before it's allowed to run on hardware.
- **Firmware glue stays separate.** `src/rns/` is portable C++17 (no Arduino headers). Anything that touches `Serial`, `millis()`, `digitalWrite()`, etc. lives in `src/` outside that tree.

## Module layout

```
src/rns/                          # the spec implementation
├── Bytes.{h,cpp}                 # minimal byte buffer
├── Crypto.{h,cpp}                # SHA256, HKDF, Ed25519, X25519, AES-CBC
├── Identity.{h,cpp}              # SPEC §1.1, §1.2, §4.5 validate_announce
├── Packet.{h,cpp}                # SPEC §2 wire format, all 4 types, both headers
├── Ifac.{h,cpp}                  # SPEC §8.6.6 mask/unmask
├── Interface.{h,cpp}             # base + announce_queue + 2% airtime cap
├── LoraInterface.{h,cpp}         # bridges Interface ↔ src/Radio.cpp
├── Transport.{h,cpp}             # SPEC §4, §6, §7, §12 — the centerpiece
└── tables/
    ├── PathTable.{h,cpp}
    ├── AnnounceTable.{h,cpp}
    ├── ReverseTable.{h,cpp}
    ├── LinkTable.{h,cpp}
    └── PacketHashList.{h,cpp}

src/                              # firmware glue (Arduino-side)
├── main.cpp                      # setup() / loop() — dispatch only
├── Config.{h,cpp}                # persisted config, schema-versioned
├── Storage.{h,cpp}               # littlefs mount
├── Radio.{h,cpp}                 # SX1262 + RNode air-frame split-packet codec
├── Led.{h,cpp}                   # heartbeat
├── SerialConsole.{h,cpp}         # provisioning
├── Telemetry.{h,cpp}             # battery/health announces
└── Ble.{h,cpp}                   # custom GATT + NUS log stream

test/native/                      # pio test -e native — host-side, Unity
├── test_identity/                # pinned to test-vectors/identities.json
├── test_packet/                  # pinned to test-vectors/announces.json
├── test_ifac/
├── test_link/                    # pinned to test-vectors/links.json
└── test_transport/
```

## Build envs

- `native` — host tests, Unity framework
- `ProMicroDIY` / `RAK4631` / `XIAO_nRF52840` / `Heltec_T114` / `RAK3401` — board envs (added as the stack reaches them)

## Naming conventions

- Namespace: everything spec-side under `rns::`, firmware-side under `rlr::`
- File-scope static state: `s_` prefix
- Constants/macros: `UPPER_SNAKE_CASE`
- Board macros prefixed: `BOARD_`, `PIN_`, `RADIO_`, `DEFAULT_CONFIG_`, `HAS_`

## Constraints

- C++17, exceptions and RTTI enabled (some spec primitives benefit from exceptions for parse failures)
- No dynamic allocation in radio ISR paths
- Cooperative multitasking — every `tick()` non-blocking
- BLE/SPI coexistence: SPI must yield to SoftDevice during BLE connection. `loop()` does NOT pause transport during BLE.

## When working on this repo

- Implementing a spec primitive? Open both the relevant `flows/<name>.md` AND the corresponding `test-vectors/*.json` first. Match the JSON exactly before claiming the layer works.
- Touching the Crypto layer? It must compile on both `native` and `arduino-nrf52` — keep API portable, hide platform-specific impls behind `#ifdef NATIVE_BUILD`.
- Adding a new spec section? Comment with the section number and a one-line summary. Don't restate the spec; cite it.
