#include "harness.hpp"
#include "bytescanner/bytes.hpp"

using namespace bscan;

TEST(Bytes, HexNibble) {
	CHECK_EQ(hexNibble('a'), 10);
	CHECK_EQ(hexNibble('F'), 15);
	CHECK_EQ(hexNibble('0'), 0);
	CHECK_EQ(hexNibble('g'), -1);
}

TEST(Bytes, ParseHex) {
	CHECK_EQ(parseHexU64("0xAE"), 0xAEull);
	CHECK_EQ(parseHexU64("10"), 10ull);
	CHECK_EQ(parseHexU64("ae309d8"), 0xAE309D8ull);
	CHECK_EQ(formatHex(255), std::string("0xFF"));
	CHECK_THROWS(parseHexU64(""));
}

TEST(Bytes, Endian) {
	uint8_t b[8] = {0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0};
	CHECK_EQ(loadU32le(b), 0x12345678u);
	CHECK_EQ(loadU16be(b), 0x7856);
	uint8_t raw[8]{};
	storeLe<uint32_t>(raw, 0x12345678u);
	CHECK_EQ(loadU32le(raw), 0x12345678u);
	storeBe<uint16_t>(raw, 0x7856);
	CHECK_EQ(loadU16be(raw), 0x7856);
}

TEST(Bytes, Range) {
	CHECK(inRange(1, 2, 4));
	CHECK(!inRange(3, 2, 4));
}

TEST(Bytes, ContainsJoin) {
	std::vector<uint64_t> v{1, 2};
	CHECK(contains(v, 2ull));
	CHECK(!contains(v, 3ull));
	pushUnique(v, 2ull);
	CHECK_EQ(v.size(), size_t{2});
	pushUnique(v, 3ull);
	CHECK_EQ(v.size(), size_t{3});
	CHECK_EQ(join({"a", "b"}, ';'), std::string("a;b"));
	CHECK_EQ(asciiLowerCopy("DATA"), std::string("data"));
	uint8_t hay[] = {0, 1, 2, 9, 1, 2, 3};
	auto hits = findBytes(hay, std::span<const uint8_t>(hay + 4, 2), 8);
	REQUIRE_EQ(hits.size(), size_t{2});
	CHECK_EQ(hits[0], 1ull);
	CHECK_EQ(hits[1], 4ull);
}
