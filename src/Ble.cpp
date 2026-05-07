#include "Ble.h"

#include <Arduino.h>
#include <bluefruit.h>

#include "rns/Bytes.h"

namespace rlr { namespace ble {

namespace {

// 128-bit UUID family carried over from the predecessor repo. Bytes
// in little-endian order per Bluefruit's BLEUuid convention. Pattern:
//
//   00000000 a5a5 524c 7272 NNNN-00726c
//                                ^^^^---- characteristic ID
//
// Service NNNN = 0001, Request char = 0002, Response char = 0003.
// Webapp hardcodes the matching UUIDs in JS.
const uint8_t RLR_UUID_SERVICE[]  = {
    0x00, 0x00, 0x00, 0x00, 0xa5, 0xa5, 0x52, 0x4c,
    0x72, 0x72, 0x00, 0x00, 0x01, 0x00, 0x72, 0x6c
};
const uint8_t RLR_UUID_REQUEST[]  = {
    0x00, 0x00, 0x00, 0x00, 0xa5, 0xa5, 0x52, 0x4c,
    0x72, 0x72, 0x00, 0x00, 0x02, 0x00, 0x72, 0x6c
};
const uint8_t RLR_UUID_RESPONSE[] = {
    0x00, 0x00, 0x00, 0x00, 0xa5, 0xa5, 0x52, 0x4c,
    0x72, 0x72, 0x00, 0x00, 0x03, 0x00, 0x72, 0x6c
};

BLEService        s_rlr_service(RLR_UUID_SERVICE);
BLECharacteristic s_request_chr(RLR_UUID_REQUEST);
BLECharacteristic s_response_chr(RLR_UUID_RESPONSE);

// Bluefruit's write callback is a C-style function pointer; closures
// aren't an option. Stash the wiring in file-scope statics so the
// callback can reach Config / Transport / save.
rlr::Config*                 s_cfg       = nullptr;
rns::Transport*              s_transport = nullptr;
rlr::config_protocol::SaveFn s_save;

void on_request_write(uint16_t /*conn_handle*/, BLECharacteristic* /*chr*/,
                      uint8_t* data, uint16_t len) {
    if (!s_cfg) return;  // shouldn't happen — init() sets it before advertising

    rns::Bytes req(data, len);
    rns::Bytes resp = rlr::config_protocol::handle_request(
        req, *s_cfg, s_transport, s_save);

    // Notify on the response characteristic. notify() handles the
    // current ATT MTU internally; for our typical < 200 byte
    // responses one notification is enough. If a future command
    // emits something larger than ATT MTU, Bluefruit fragments it.
    s_response_chr.notify(resp.data(), resp.size());
}

}  // namespace

bool init(rlr::Config& cfg,
          rns::Transport* transport,
          rlr::config_protocol::SaveFn save) {
    s_cfg       = &cfg;
    s_transport = transport;
    s_save      = std::move(save);

    Bluefruit.begin();
    // Per-device name: cfg.display_name is stamped at first boot to
    // "Rptr-XXXXXXXX" (4 bytes of identity_hash), so each repeater
    // shows a unique label on BLE scanners. Falls back to a static
    // family name if Config persistence ever returns an empty string.
    const char* ble_name =
        (cfg.display_name[0] != '\0') ? cfg.display_name : "rlr-transport";
    Bluefruit.setName(ble_name);
    Bluefruit.setTxPower(4);  // dBm; max for nRF52840 BLE radio

    // Register service + characteristics.
    s_rlr_service.begin();

    s_request_chr.setProperties(CHR_PROPS_WRITE | CHR_PROPS_WRITE_WO_RESP);
    s_request_chr.setPermission(SECMODE_OPEN, SECMODE_OPEN);
    s_request_chr.setMaxLen(244);   // ATT MTU 247 - 3 (opcode + handle)
    s_request_chr.setWriteCallback(on_request_write);
    s_request_chr.begin();

    s_response_chr.setProperties(CHR_PROPS_NOTIFY);
    s_response_chr.setPermission(SECMODE_OPEN, SECMODE_OPEN);
    s_response_chr.setMaxLen(244);
    s_response_chr.begin();

    // Advertising. Add the service UUID to the advert payload so the
    // webapp can filter for our devices.
    Bluefruit.Advertising.addFlags(BLE_GAP_ADV_FLAGS_LE_ONLY_GENERAL_DISC_MODE);
    Bluefruit.Advertising.addTxPower();
    Bluefruit.Advertising.addService(s_rlr_service);
    Bluefruit.Advertising.addName();
    Bluefruit.Advertising.restartOnDisconnect(true);
    Bluefruit.Advertising.setInterval(32, 244);   // ms units of 0.625
    Bluefruit.Advertising.setFastTimeout(30);     // seconds at fast interval
    Bluefruit.Advertising.start(0);               // 0 = forever

    Serial.println(F("rlr: BLE config service advertising"));
    return true;
}

}}  // namespace rlr::ble
