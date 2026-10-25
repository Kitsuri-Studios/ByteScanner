#include "harness.hpp"
#include "bytescanner/scan.hpp"

using namespace bscan;

namespace {

std::vector<uint8_t> callHay() {
	std::vector<uint8_t> data(256, 0x90);
	data[40] = 0xE8;
	data[41] = 0x01;
	data[42] = 0x02;
	data[43] = 0x03;
	data[44] = 0x04;
	data[45] = 0x45;
	data[46] = 0x33;
	data[47] = 0xF6;
	return data;
}

}

TEST(Scan, HybridHit) {
	auto data = callHay();
	Pattern p = parsePattern("E8 ? ? ? ? 45 33 F6");
	CHECK_EQ(searchHybrid(data, p), size_t{40});
	CHECK(patternMatches(std::span<const uint8_t>(data.data() + 40, p.size()), p));
}

TEST(Scan, FindOne) {
	auto data = callHay();
	Pattern p = parsePattern("E8 ? ? ? ? 45 33 F6");
	Binary bin = Binary::loadBytes(data, Arch::X64);
	Scanner sc(bin, true);
	auto hits = sc.find(p, 8);
	REQUIRE_EQ(hits.size(), size_t{1});
	CHECK_EQ(hits[0].fileOffset, 40ull);
	CHECK_EQ(sc.count(p, 4), size_t{1});
}

TEST(Scan, CountTwo) {
	auto data = callHay();
	data[200] = 0xE8;
	data[201] = 0xAA;
	data[202] = 0xBB;
	data[203] = 0xCC;
	data[204] = 0xDD;
	data[205] = 0x45;
	data[206] = 0x33;
	data[207] = 0xF6;
	Pattern p = parsePattern("E8 ? ? ? ? 45 33 F6");
	Binary bin = Binary::loadBytes(data, Arch::X64);
	Scanner sc(bin, true);
	CHECK_EQ(sc.count(p, 4), size_t{2});
	CHECK_EQ(sc.count(p, 1), size_t{1});
	std::vector<size_t> rel;
	searchHybridN(data, p, 8, rel);
	REQUIRE_EQ(rel.size(), size_t{2});
	CHECK_EQ(rel[0], size_t{40});
	CHECK_EQ(rel[1], size_t{200});
}

TEST(Scan, IndexMiss) {
	auto data = callHay();
	Pattern p = parsePattern("CC DD EE FF");
	Binary bin = Binary::loadBytes(data, Arch::X64);
	Scanner sc(bin, true);
	CHECK(sc.hasIndex());
	CHECK_EQ(sc.count(p, 4), size_t{0});
	CHECK(sc.find(p, 4).empty());
}
