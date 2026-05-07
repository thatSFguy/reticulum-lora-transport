// test/native/test_msgpack/test_msgpack.cpp
//
// Unit tests for the minimal msgpack writer + the telemetry payload
// encoder. msgpack wire bytes are pinned to the spec
// (https://github.com/msgpack/msgpack/blob/master/spec.md) — the
// writer is small enough that byte-for-byte round-trip checks beat
// abstract behaviour tests.

#include <unity.h>
#include <cstdint>
#include <stdexcept>

#include "rns/Bytes.h"
#include "rns/Msgpack.h"
#include "rns/Telemetry.h"

using rns::Bytes;
using rns::msgpack::Reader;
using rns::msgpack::Writer;

void setUp() {}
void tearDown() {}

void test_msgpack_nil() {
    Writer w;
    w.nil();
    TEST_ASSERT_EQUAL_STRING("c0", w.bytes().to_hex().c_str());
}

void test_msgpack_uint8() {
    Writer w;
    w.uint8(0x42);
    TEST_ASSERT_EQUAL_STRING("cc42", w.bytes().to_hex().c_str());
}

void test_msgpack_uint16_be() {
    Writer w;
    w.uint16(0x1234);
    TEST_ASSERT_EQUAL_STRING("cd1234", w.bytes().to_hex().c_str());
}

void test_msgpack_uint32_be() {
    Writer w;
    w.uint32(0xdeadbeef);
    TEST_ASSERT_EQUAL_STRING("cedeadbeef", w.bytes().to_hex().c_str());
}

// 1.0f in IEEE-754 single is 0x3f800000.
void test_msgpack_float32_one_point_zero() {
    Writer w;
    w.float32(1.0f);
    TEST_ASSERT_EQUAL_STRING("ca3f800000", w.bytes().to_hex().c_str());
}

void test_msgpack_array_header_fixarray() {
    Writer w;
    w.array_header(5);
    TEST_ASSERT_EQUAL_STRING("95", w.bytes().to_hex().c_str());
}

// fixarray boundary: 15 elements stays fixarray, 16 promotes to array16.
// Both produce valid output; only > 65535 throws now.
void test_msgpack_array_header_promotes_to_array16() {
    Writer w15; w15.array_header(15);
    TEST_ASSERT_EQUAL_STRING("9f", w15.bytes().to_hex().c_str());

    Writer w16; w16.array_header(16);
    TEST_ASSERT_EQUAL_STRING("dc0010", w16.bytes().to_hex().c_str());

    Writer w_too_big;
    try {
        w_too_big.array_header(65536);
        TEST_FAIL_MESSAGE("expected throw — array32 unsupported");
    } catch (const std::invalid_argument&) {
        // expected
    }
}

// Compose a small full payload and verify the byte sequence.
void test_msgpack_full_payload_assembly() {
    Writer w;
    w.array_header(3);
    w.nil();
    w.uint16(0x0a0b);
    w.uint32(0x12345678);
    TEST_ASSERT_EQUAL_STRING("93c0cd0a0bce12345678",
                             w.bytes().to_hex().c_str());
}

// §telemetry encoder — full snapshot with position.
//   array(9)                  = 0x99
//   float32 1.0               = 0xca 3f800000   (lat)
//   float32 -1.0              = 0xca bf800000   (lon)
//   uint16 3700               = 0xcd 0e74       (battery_mv)
//   uint16 42                 = 0xcd 002a       (route_count)
//   uint32 1000               = 0xce 000003e8   (packets_forwarded — aggregate)
//   uint32 17                 = 0xce 00000011   (announces_rebroadcast)
//   uint32 5                  = 0xce 00000005   (data_forwarded)
//   uint32 100                = 0xce 00000064   (inbound_packets)
//   fixstr "Rptr-aabbccdd"    = 0xad + 13 ASCII bytes
//                                  hex form: ad 527074722d6161626263636464
void test_telemetry_encode_with_position() {
    rns::telemetry::Snapshot s;
    s.have_position          = true;
    s.lat                    =  1.0f;
    s.lon                    = -1.0f;
    s.battery_mv             = 3700;
    s.route_count            = 42;
    s.packets_forwarded      = 1000;
    s.announces_rebroadcast  = 17;
    s.data_forwarded         = 5;
    s.inbound_packets        = 100;
    s.name                   = "Rptr-aabbccdd";  // 13 chars — fixstr 0xa0|13 = 0xad
    Bytes out = rns::telemetry::encode(s);
    TEST_ASSERT_EQUAL_STRING(
        "99"
        "ca3f800000"
        "cabf800000"
        "cd0e74"
        "cd002a"
        "ce000003e8"
        "ce00000011"
        "ce00000005"
        "ce00000064"
        "ad52707472" "2d6161626263636464",
        out.to_hex().c_str());
}

// ---- New writer tests (bool / map_header / str / bin) -------------

void test_msgpack_bool_true_false() {
    Writer wt; wt.bool_val(true);  TEST_ASSERT_EQUAL_STRING("c3", wt.bytes().to_hex().c_str());
    Writer wf; wf.bool_val(false); TEST_ASSERT_EQUAL_STRING("c2", wf.bytes().to_hex().c_str());
}

// fixmap (n<16) → 0x80 | n
void test_msgpack_map_header_fixmap() {
    Writer w; w.map_header(3);
    TEST_ASSERT_EQUAL_STRING("83", w.bytes().to_hex().c_str());
}

// map16 (16 ≤ n < 65536) → 0xde + 2 BE bytes
void test_msgpack_map_header_map16() {
    Writer w; w.map_header(20);
    TEST_ASSERT_EQUAL_STRING("de0014", w.bytes().to_hex().c_str());
}

// fixstr "hello" — 0xa0|5 (=0xa5) + "hello" UTF-8 bytes
void test_msgpack_str_fixstr() {
    Writer w; w.str("hello");
    TEST_ASSERT_EQUAL_STRING("a568656c6c6f", w.bytes().to_hex().c_str());
}

// str8 — string with len ≥ 32. 0xd9 + 1 len byte + bytes.
void test_msgpack_str_str8() {
    std::string s(40, 'x');  // 40 'x' chars
    Writer w; w.str(s);
    Bytes out = w.bytes();
    TEST_ASSERT_EQUAL_UINT8(0xd9, out[0]);
    TEST_ASSERT_EQUAL_UINT8(40, out[1]);
    TEST_ASSERT_EQUAL_UINT(42, out.size());
}

// bin8 — 0xc4 + 1 len + bytes.
void test_msgpack_bin8() {
    Bytes b = Bytes::from_hex("deadbeef");
    Writer w; w.bin(b);
    TEST_ASSERT_EQUAL_STRING("c404deadbeef", w.bytes().to_hex().c_str());
}

// ---- Reader tests --------------------------------------------------

void test_reader_nil() {
    Bytes b = Bytes::from_hex("c0");
    Reader r(b);
    TEST_ASSERT_TRUE(r.peek_type() == Reader::Type::NIL);
    TEST_ASSERT_TRUE(r.read_nil());
    TEST_ASSERT_TRUE(r.ok());
    TEST_ASSERT_TRUE(r.at_end());
}

void test_reader_bool() {
    Bytes b = Bytes::from_hex("c3c2");
    Reader r(b);
    bool v = false;
    TEST_ASSERT_TRUE(r.read_bool(v)); TEST_ASSERT_TRUE(v);
    TEST_ASSERT_TRUE(r.read_bool(v)); TEST_ASSERT_FALSE(v);
}

void test_reader_uint_widths() {
    // positive fixint 0x05 / uint8 0x42 / uint16 0x1234 / uint32 0xdeadbeef
    Bytes b = Bytes::from_hex("05cc42cd1234cedeadbeef");
    Reader r(b);
    uint64_t v;
    TEST_ASSERT_TRUE(r.read_uint(v)); TEST_ASSERT_EQUAL_UINT64(0x05, v);
    TEST_ASSERT_TRUE(r.read_uint(v)); TEST_ASSERT_EQUAL_UINT64(0x42, v);
    TEST_ASSERT_TRUE(r.read_uint(v)); TEST_ASSERT_EQUAL_UINT64(0x1234, v);
    TEST_ASSERT_TRUE(r.read_uint(v)); TEST_ASSERT_EQUAL_UINT64(0xdeadbeef, v);
    TEST_ASSERT_TRUE(r.at_end());
}

void test_reader_float32() {
    // 1.0 = 0x3f800000
    Bytes b = Bytes::from_hex("ca3f800000");
    Reader r(b);
    float f = 0;
    TEST_ASSERT_TRUE(r.read_float32(f));
    TEST_ASSERT_EQUAL_FLOAT(1.0f, f);
}

// read_int handles all signed encodings (negative fixint + int8/16/32/64).
// Critical for the webclient's natural negative-int encoding.
void test_reader_int_signed_widths() {
    // negative fixint (-1) = 0xff, sign-bit treated as int8
    {
        Bytes b = Bytes::from_hex("ff");
        Reader r(b); int64_t v = 0;
        TEST_ASSERT_TRUE(r.read_int(v));
        TEST_ASSERT_EQUAL_INT64(-1, v);
    }
    // int8(-50) = d0 ce  (0xce as signed = -50)
    {
        Bytes b = Bytes::from_hex("d0ce");
        Reader r(b); int64_t v = 0;
        TEST_ASSERT_TRUE(r.read_int(v));
        TEST_ASSERT_EQUAL_INT64(-50, v);
    }
    // int16(-1000) = d1 fc 18
    {
        Bytes b = Bytes::from_hex("d1fc18");
        Reader r(b); int64_t v = 0;
        TEST_ASSERT_TRUE(r.read_int(v));
        TEST_ASSERT_EQUAL_INT64(-1000, v);
    }
    // int32(-122419400) = d2 f8 b4 07 38  (msgpack encoding of -122419400 = lon_udeg
    // for San Francisco — exactly the case the webclient hits for save-config)
    {
        Bytes b = Bytes::from_hex("d2f8b40738");
        Reader r(b); int64_t v = 0;
        TEST_ASSERT_TRUE(r.read_int(v));
        TEST_ASSERT_EQUAL_INT64(-122419400, v);
    }
    // int64(-1) = d3 ff ff ff ff ff ff ff ff
    {
        Bytes b = Bytes::from_hex("d3ffffffffffffffff");
        Reader r(b); int64_t v = 0;
        TEST_ASSERT_TRUE(r.read_int(v));
        TEST_ASSERT_EQUAL_INT64(-1, v);
    }
}

// read_int also accepts unsigned encodings transparently — both
// callers can use it uniformly.
void test_reader_int_accepts_uint_encodings() {
    // positive fixint(42) = 0x2a
    {
        Bytes b = Bytes::from_hex("2a");
        Reader r(b); int64_t v = 0;
        TEST_ASSERT_TRUE(r.read_int(v));
        TEST_ASSERT_EQUAL_INT64(42, v);
    }
    // uint32(904375000) = ce 35 e7 aa d8 — typical freq_hz value
    {
        Bytes b = Bytes::from_hex("ce35e7aad8");
        Reader r(b); int64_t v = 0;
        TEST_ASSERT_TRUE(r.read_int(v));
        TEST_ASSERT_EQUAL_INT64(904375000, v);
    }
}

// read_float32 accepts both float32 (0xca) and float64 (0xcb).
// JS numbers default to float64 in @msgpack/msgpack, so without this
// every batt_mult write would fail.
void test_reader_float32_accepts_float64() {
    // float64(1.284) = cb 3f f4 8b 43 95 81 06 25
    Bytes b = Bytes::from_hex("cb3ff48b4395810625");
    Reader r(b); float f = 0;
    TEST_ASSERT_TRUE(r.read_float32(f));
    TEST_ASSERT_FLOAT_WITHIN(1e-5f, 1.284f, f);
}

void test_reader_str_fixstr_and_str8() {
    Writer w;
    w.str("hi");
    w.str(std::string(40, 'x'));  // forces str8
    Reader r(w.bytes());
    std::string s1, s2;
    TEST_ASSERT_TRUE(r.read_str(s1));
    TEST_ASSERT_TRUE(r.read_str(s2));
    TEST_ASSERT_EQUAL_STRING("hi", s1.c_str());
    TEST_ASSERT_EQUAL_UINT(40, s2.size());
    TEST_ASSERT_TRUE(r.at_end());
}

void test_reader_bin8() {
    Bytes b = Bytes::from_hex("c404deadbeef");
    Reader r(b);
    Bytes payload;
    TEST_ASSERT_TRUE(r.read_bin(payload));
    TEST_ASSERT_EQUAL_STRING("deadbeef", payload.to_hex().c_str());
}

// Round-trip a typical config command: {"cmd": "set", "field":
// "freq_hz", "value": 904375000}.
void test_reader_writer_round_trip_config_command() {
    Writer w;
    w.map_header(3);
        w.str("cmd");   w.str("set");
        w.str("field"); w.str("freq_hz");
        w.str("value"); w.uint32(904375000u);

    Reader r(w.bytes());
    size_t pairs = 0;
    TEST_ASSERT_TRUE(r.read_map_header(pairs));
    TEST_ASSERT_EQUAL_UINT(3, pairs);

    std::string k1, v1, k2, v2, k3;
    uint64_t v3 = 0;
    TEST_ASSERT_TRUE(r.read_str(k1)); TEST_ASSERT_TRUE(r.read_str(v1));
    TEST_ASSERT_TRUE(r.read_str(k2)); TEST_ASSERT_TRUE(r.read_str(v2));
    TEST_ASSERT_TRUE(r.read_str(k3)); TEST_ASSERT_TRUE(r.read_uint(v3));

    TEST_ASSERT_EQUAL_STRING("cmd",     k1.c_str());
    TEST_ASSERT_EQUAL_STRING("set",     v1.c_str());
    TEST_ASSERT_EQUAL_STRING("field",   k2.c_str());
    TEST_ASSERT_EQUAL_STRING("freq_hz", v2.c_str());
    TEST_ASSERT_EQUAL_STRING("value",   k3.c_str());
    TEST_ASSERT_EQUAL_UINT64(904375000u, v3);
    TEST_ASSERT_TRUE(r.at_end());
}

// Sticky error: type mismatch flips ok() and stays flipped.
void test_reader_type_mismatch_sets_sticky_error() {
    Bytes b = Bytes::from_hex("c0");  // nil
    Reader r(b);
    bool boolean;
    TEST_ASSERT_FALSE(r.read_bool(boolean));  // nil isn't a bool
    TEST_ASSERT_FALSE(r.ok());
    // Subsequent reads short-circuit.
    uint64_t v;
    TEST_ASSERT_FALSE(r.read_uint(v));
}

// Buffer overrun on a length-prefixed type sets sticky error.
void test_reader_truncated_str_sets_error() {
    // str8 declaring length 5 but only 3 bytes follow
    Bytes b = Bytes::from_hex("d905616263");  // d9=str8, 05=len, then "abc" (truncated)
    Reader r(b);
    std::string s;
    TEST_ASSERT_FALSE(r.read_str(s));
    TEST_ASSERT_FALSE(r.ok());
}

// skip_value advances over arbitrary types.
void test_reader_skip_value() {
    Writer w;
    w.array_header(2);
        w.uint16(100);
        w.str("ignored");
    w.uint8(0xAA);  // sentinel that should still be reachable

    Reader r(w.bytes());
    TEST_ASSERT_TRUE(r.skip_value());  // skips the whole array
    uint64_t v;
    TEST_ASSERT_TRUE(r.read_uint(v));
    TEST_ASSERT_EQUAL_UINT64(0xAA, v);
}

// Without position: lat/lon are nil; counters are zero; name is
// the empty string (the wire shape a freshly-booted node would emit
// if it had no display_name yet — main.cpp normally stamps one
// before the first beacon, so this is the absolute floor).
void test_telemetry_encode_without_position() {
    rns::telemetry::Snapshot s;
    s.have_position          = false;
    s.battery_mv             = 0;
    s.route_count            = 0;
    s.packets_forwarded      = 0;
    s.announces_rebroadcast  = 0;
    s.data_forwarded         = 0;
    s.inbound_packets        = 0;
    // s.name defaults to "" — emits as fixstr 0xa0 (length 0).
    Bytes out = rns::telemetry::encode(s);
    TEST_ASSERT_EQUAL_STRING(
        "99"
        "c0"
        "c0"
        "cd0000"
        "cd0000"
        "ce00000000"
        "ce00000000"
        "ce00000000"
        "ce00000000"
        "a0",
        out.to_hex().c_str());
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    UNITY_BEGIN();
    RUN_TEST(test_msgpack_nil);
    RUN_TEST(test_msgpack_uint8);
    RUN_TEST(test_msgpack_uint16_be);
    RUN_TEST(test_msgpack_uint32_be);
    RUN_TEST(test_msgpack_float32_one_point_zero);
    RUN_TEST(test_msgpack_array_header_fixarray);
    RUN_TEST(test_msgpack_array_header_promotes_to_array16);
    RUN_TEST(test_msgpack_full_payload_assembly);
    RUN_TEST(test_telemetry_encode_with_position);
    RUN_TEST(test_telemetry_encode_without_position);
    RUN_TEST(test_msgpack_bool_true_false);
    RUN_TEST(test_msgpack_map_header_fixmap);
    RUN_TEST(test_msgpack_map_header_map16);
    RUN_TEST(test_msgpack_str_fixstr);
    RUN_TEST(test_msgpack_str_str8);
    RUN_TEST(test_msgpack_bin8);
    RUN_TEST(test_reader_nil);
    RUN_TEST(test_reader_bool);
    RUN_TEST(test_reader_uint_widths);
    RUN_TEST(test_reader_int_signed_widths);
    RUN_TEST(test_reader_int_accepts_uint_encodings);
    RUN_TEST(test_reader_float32_accepts_float64);
    RUN_TEST(test_reader_float32);
    RUN_TEST(test_reader_str_fixstr_and_str8);
    RUN_TEST(test_reader_bin8);
    RUN_TEST(test_reader_writer_round_trip_config_command);
    RUN_TEST(test_reader_type_mismatch_sets_sticky_error);
    RUN_TEST(test_reader_truncated_str_sets_error);
    RUN_TEST(test_reader_skip_value);
    return UNITY_END();
}
