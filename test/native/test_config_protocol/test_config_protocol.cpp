// test/native/test_config_protocol/test_config_protocol.cpp
//
// Tests for the webapp ↔ firmware command dispatcher. ConfigProtocol
// is transport-agnostic (no Serial, no BLE, no Arduino) — tests
// build msgpack requests, hand them to handle_request, and decode
// the msgpack responses with the same Reader the firmware uses.

#include <unity.h>
#include <cstdint>
#include <cstring>
#include <string>

#include "Config.h"
#include "ConfigProtocol.h"
#include "rns/Bytes.h"
#include "rns/Identity.h"
#include "rns/Msgpack.h"
#include "rns/Transport.h"

using rns::Bytes;
using rns::Identity;
using rns::Transport;
using rns::msgpack::Reader;
using rns::msgpack::Writer;

void setUp() {}
void tearDown() {}

namespace {

// Bob's identity from identities.json — gives ping's response a
// known identity_hash to assert against (28d43a... — actually that's
// alice's; bob's is c090410e5b5bf8956194c1872dccec3b).
constexpr const char* BOB_PRIV_HEX =
    "0f453e75d564532f2fa671aea79e9a714e4564e1ff833d1df19986fe8a36aa21"
    "9a6acdad966af7d006cfd393ca8278c608978bcaefa5b5f24db867179f83a863";
constexpr const char* BOB_IDENTITY_HASH = "c090410e5b5bf8956194c1872dccec3b";

Identity bob() {
    return Identity::from_private_bytes(Bytes::from_hex(BOB_PRIV_HEX));
}

// Read the "ok" field from a response. Asserts that it's the FIRST
// pair (handle_request always emits it first) and returns its bool.
bool response_ok(const Bytes& response) {
    Reader r(response);
    size_t pairs = 0;
    if (!r.read_map_header(pairs)) return false;
    std::string key; if (!r.read_str(key))   return false;
    if (key != "ok")                          return false;
    bool v = false; r.read_bool(v);
    return v;
}

// Helper — find a string-keyed value in the response map and run a
// callback on the reader at that value's position. Order-independent.
template <typename F>
bool response_with(const Bytes& response, const char* needle, F&& cb) {
    Reader r(response);
    size_t pairs = 0;
    if (!r.read_map_header(pairs)) return false;
    for (size_t i = 0; i < pairs; ++i) {
        std::string key;
        if (!r.read_str(key)) return false;
        if (key == needle) {
            cb(r);
            return true;
        }
        if (!r.skip_value()) return false;
    }
    return false;
}

Bytes build_request_ping() {
    Writer w;
    w.map_header(1);
    w.str("cmd"); w.str("ping");
    return w.bytes();
}

Bytes build_request_get_config() {
    Writer w;
    w.map_header(1);
    w.str("cmd"); w.str("get_config");
    return w.bytes();
}

Bytes build_request_commit() {
    Writer w;
    w.map_header(1);
    w.str("cmd"); w.str("commit");
    return w.bytes();
}

}  // namespace

// ---- ping ---------------------------------------------------------

void test_ping_without_transport_returns_version() {
    rlr::Config cfg;
    Bytes resp = rlr::config_protocol::handle_request(
        build_request_ping(), cfg, /*transport=*/nullptr);
    TEST_ASSERT_TRUE(response_ok(resp));
    bool found = response_with(resp, "version", [](Reader& r) {
        std::string ver;
        TEST_ASSERT_TRUE(r.read_str(ver));
        // FIRMWARE_VERSION is injected at compile time via the
        // scripts/inject_fw_version.py PIO pre-build script for
        // firmware envs; the native test env doesn't run that
        // script, so we get the "dev" fallback. We just verify the
        // field is present and non-empty — the exact value depends
        // on the build environment.
        TEST_ASSERT_TRUE(ver.size() > 0);
    });
    TEST_ASSERT_TRUE(found);
}

void test_ping_with_transport_includes_identity_hash() {
    rlr::Config cfg;
    Transport t(bob(), false);
    Bytes resp = rlr::config_protocol::handle_request(
        build_request_ping(), cfg, &t);
    TEST_ASSERT_TRUE(response_ok(resp));
    bool found = response_with(resp, "identity_hash", [](Reader& r) {
        Bytes id;
        TEST_ASSERT_TRUE(r.read_bin(id));
        TEST_ASSERT_EQUAL_STRING(BOB_IDENTITY_HASH, id.to_hex().c_str());
    });
    TEST_ASSERT_TRUE(found);
}

// ---- get_config ---------------------------------------------------

void test_get_config_emits_radio_fields() {
    rlr::Config cfg;
    cfg.freq_hz = 904375000u;
    cfg.bw_hz   = 250000u;
    cfg.sf      = 10;
    cfg.cr      = 5;
    cfg.txp_dbm = 22;

    Bytes resp = rlr::config_protocol::handle_request(
        build_request_get_config(), cfg, nullptr);
    TEST_ASSERT_TRUE(response_ok(resp));

    response_with(resp, "freq_hz", [](Reader& r) {
        uint64_t v; TEST_ASSERT_TRUE(r.read_uint(v));
        TEST_ASSERT_EQUAL_UINT64(904375000u, v);
    });
    response_with(resp, "sf", [](Reader& r) {
        uint64_t v; TEST_ASSERT_TRUE(r.read_uint(v));
        TEST_ASSERT_EQUAL_UINT64(10, v);
    });
    response_with(resp, "txp_dbm", [](Reader& r) {
        uint64_t v; TEST_ASSERT_TRUE(r.read_uint(v));
        TEST_ASSERT_EQUAL_UINT64(22, v);
    });
}

// ---- set_config ---------------------------------------------------

void test_set_config_mutates_known_fields() {
    rlr::Config cfg;
    cfg.freq_hz = 0;
    cfg.sf      = 0;

    Writer w;
    w.map_header(3);
    w.str("cmd");     w.str("set_config");
    w.str("freq_hz"); w.uint32(904375000u);
    w.str("sf");      w.uint8(10);

    Bytes resp = rlr::config_protocol::handle_request(w.bytes(), cfg, nullptr);
    TEST_ASSERT_TRUE(response_ok(resp));

    TEST_ASSERT_EQUAL_UINT(904375000u, cfg.freq_hz);
    TEST_ASSERT_EQUAL_UINT8(10, cfg.sf);

    response_with(resp, "set", [](Reader& r) {
        uint64_t v; TEST_ASSERT_TRUE(r.read_uint(v));
        TEST_ASSERT_EQUAL_UINT64(2, v);
    });
}

void test_set_config_silently_skips_unknown_fields() {
    rlr::Config cfg;
    cfg.freq_hz = 0;

    // Unknown key "future_field" with a string value — must not break
    // parse, must not be counted.
    Writer w;
    w.map_header(3);
    w.str("cmd");           w.str("set_config");
    w.str("freq_hz");       w.uint32(902000000u);
    w.str("future_field");  w.str("ignored");

    Bytes resp = rlr::config_protocol::handle_request(w.bytes(), cfg, nullptr);
    TEST_ASSERT_TRUE(response_ok(resp));

    TEST_ASSERT_EQUAL_UINT(902000000u, cfg.freq_hz);
    response_with(resp, "set", [](Reader& r) {
        uint64_t v; TEST_ASSERT_TRUE(r.read_uint(v));
        TEST_ASSERT_EQUAL_UINT64(1, v);  // freq_hz only
    });
}

void test_set_config_display_name_truncates_oversized() {
    rlr::Config cfg;
    std::string huge(50, 'A');
    Writer w;
    w.map_header(2);
    w.str("cmd");          w.str("set_config");
    w.str("display_name"); w.str(huge);

    Bytes resp = rlr::config_protocol::handle_request(w.bytes(), cfg, nullptr);
    TEST_ASSERT_TRUE(response_ok(resp));
    // Truncated to display_name capacity - 1 (NUL terminator).
    TEST_ASSERT_EQUAL_UINT(sizeof(cfg.display_name) - 1,
                           std::strlen(cfg.display_name));
}

// ---- commit -------------------------------------------------------

void test_commit_without_save_callback_errors() {
    rlr::Config cfg;
    Bytes resp = rlr::config_protocol::handle_request(
        build_request_commit(), cfg, nullptr, /*save=*/nullptr);
    TEST_ASSERT_FALSE(response_ok(resp));
    response_with(resp, "err", [](Reader& r) {
        std::string e; TEST_ASSERT_TRUE(r.read_str(e));
        TEST_ASSERT_EQUAL_STRING("commit not configured", e.c_str());
    });
}

void test_commit_invokes_save_callback_with_current_cfg() {
    rlr::Config cfg;
    cfg.freq_hz = 904375000u;
    cfg.sf      = 10;

    int calls = 0;
    rlr::Config seen;
    auto save = [&](const rlr::Config& c) -> bool {
        calls++;
        seen = c;
        return true;
    };

    Bytes resp = rlr::config_protocol::handle_request(
        build_request_commit(), cfg, nullptr, save);
    TEST_ASSERT_TRUE(response_ok(resp));
    TEST_ASSERT_EQUAL_INT(1, calls);
    TEST_ASSERT_EQUAL_UINT(904375000u, seen.freq_hz);
    TEST_ASSERT_EQUAL_UINT8(10, seen.sf);
}

void test_commit_returns_error_when_save_returns_false() {
    rlr::Config cfg;
    auto failing = [](const rlr::Config&) -> bool { return false; };
    Bytes resp = rlr::config_protocol::handle_request(
        build_request_commit(), cfg, nullptr, failing);
    TEST_ASSERT_FALSE(response_ok(resp));
}

// ---- error paths --------------------------------------------------

void test_unknown_cmd_returns_error() {
    rlr::Config cfg;
    Writer w;
    w.map_header(1);
    w.str("cmd"); w.str("not_a_real_cmd");
    Bytes resp = rlr::config_protocol::handle_request(w.bytes(), cfg, nullptr);
    TEST_ASSERT_FALSE(response_ok(resp));
}

void test_non_map_request_returns_error() {
    rlr::Config cfg;
    Writer w;
    w.array_header(2);  // not a map
    w.str("cmd"); w.str("ping");
    Bytes resp = rlr::config_protocol::handle_request(w.bytes(), cfg, nullptr);
    TEST_ASSERT_FALSE(response_ok(resp));
}

void test_empty_map_returns_error() {
    rlr::Config cfg;
    Writer w;
    w.map_header(0);
    Bytes resp = rlr::config_protocol::handle_request(w.bytes(), cfg, nullptr);
    TEST_ASSERT_FALSE(response_ok(resp));
}

void test_cmd_not_first_key_returns_error() {
    rlr::Config cfg;
    Writer w;
    w.map_header(2);
    w.str("freq_hz"); w.uint32(902000000u);  // first
    w.str("cmd");     w.str("set_config");   // second — wrong order
    Bytes resp = rlr::config_protocol::handle_request(w.bytes(), cfg, nullptr);
    TEST_ASSERT_FALSE(response_ok(resp));
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    UNITY_BEGIN();
    RUN_TEST(test_ping_without_transport_returns_version);
    RUN_TEST(test_ping_with_transport_includes_identity_hash);
    RUN_TEST(test_get_config_emits_radio_fields);
    RUN_TEST(test_set_config_mutates_known_fields);
    RUN_TEST(test_set_config_silently_skips_unknown_fields);
    RUN_TEST(test_set_config_display_name_truncates_oversized);
    RUN_TEST(test_commit_without_save_callback_errors);
    RUN_TEST(test_commit_invokes_save_callback_with_current_cfg);
    RUN_TEST(test_commit_returns_error_when_save_returns_false);
    RUN_TEST(test_unknown_cmd_returns_error);
    RUN_TEST(test_non_map_request_returns_error);
    RUN_TEST(test_empty_map_returns_error);
    RUN_TEST(test_cmd_not_first_key_returns_error);
    return UNITY_END();
}
