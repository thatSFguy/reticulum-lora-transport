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

void test_msgpack_array_header_rejects_large() {
    Writer w;
    try {
        w.array_header(16);
        TEST_FAIL_MESSAGE("expected throw — fixarray cap is 15");
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
//   array(5)   = 0x95
//   float32 1.0 = 0xca 3f800000
//   float32 -1.0 = 0xca bf800000
//   uint16 3700 = 0xcd 0e74
//   uint16 42   = 0xcd 002a
//   uint32 1000 = 0xce 000003e8
void test_telemetry_encode_with_position() {
    rns::telemetry::Snapshot s;
    s.have_position    = true;
    s.lat              =  1.0f;
    s.lon              = -1.0f;
    s.battery_mv       = 3700;
    s.route_count      = 42;
    s.packets_forwarded = 1000;
    Bytes out = rns::telemetry::encode(s);
    TEST_ASSERT_EQUAL_STRING(
        "95"
        "ca3f800000"
        "cabf800000"
        "cd0e74"
        "cd002a"
        "ce000003e8",
        out.to_hex().c_str());
}

// Without position: lat/lon are nil.
void test_telemetry_encode_without_position() {
    rns::telemetry::Snapshot s;
    s.have_position    = false;
    s.battery_mv       = 0;
    s.route_count      = 0;
    s.packets_forwarded = 0;
    Bytes out = rns::telemetry::encode(s);
    TEST_ASSERT_EQUAL_STRING(
        "95"
        "c0"
        "c0"
        "cd0000"
        "cd0000"
        "ce00000000",
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
    RUN_TEST(test_msgpack_array_header_rejects_large);
    RUN_TEST(test_msgpack_full_payload_assembly);
    RUN_TEST(test_telemetry_encode_with_position);
    RUN_TEST(test_telemetry_encode_without_position);
    return UNITY_END();
}
