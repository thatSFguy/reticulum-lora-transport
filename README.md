# reticulum-lora-transport

Clean-room C++ implementation of an [RNS Transport node](https://github.com/markqvist/Reticulum) for nRF52840 + SX1262 boards, pinned to the [reticulum-specifications](https://github.com/thatSFguy/reticulum-specifications) wire-format spec.

Successor to `reticulum-lora-repeater`. The previous firmware wrapped `microReticulum` (a partial Python→C++ port) and patched it via build-time string replacement; this one implements RNS Transport directly against the spec, with test vectors as the source of truth.

**Status:** under construction. See `CLAUDE.md` for current scope and architecture.

## Why a rewrite

- The Reticulum wire format has been stable for 10+ years — a clean-room implementation is a one-time cost.
- `microReticulum` is a half-finished port (stub `process_announce_queue`, commented-out IFAC, no airtime cap). Patching it via `pre_build.py` inherits all of those gaps.
- A spec-pinned implementation can be tested deterministically against `reticulum-specifications/test-vectors/`, which the previous firmware never could.

## Scope

- Full RNS Transport node (announce forwarding, path-aware DATA forwarding, link establishment forwarding, PROOF forwarding via reverse_table)
- IFAC (Interface Authentication Codes) included
- LoRa-only for now; the `Interface` abstraction leaves room for AutoInterface / TCP later
- No LXMF — transport nodes don't run application-layer routers

## Build

```sh
pio test -e native    # unit tests pinned to reticulum-specifications/test-vectors/
pio run  -e Faketec   # firmware build (board envs land as the stack reaches them)
```

## License

MIT — see `LICENSE`.
