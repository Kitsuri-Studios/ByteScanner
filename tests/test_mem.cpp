#include "harness.hpp"
#include "bytescanner/mem.hpp"
#include "bytescanner/scan.hpp"

using namespace bscan;

TEST(Mem, ParseSize) {
	CHECK_EQ(parseMemSize("512M", 0), 512ull * 1024 * 1024);
	CHECK_EQ(parseMemSize("1G", 0), 1024ull * 1024 * 1024);
	CHECK_EQ(parseMemSize("64MB", 0), 64ull * 1024 * 1024);
	CHECK_EQ(parseMemSize("50%", 1000), 500ull);
	CHECK_EQ(parseMemSize("", 0), 0ull);
}

TEST(Mem, PickBudget) {
	CHECK_EQ(pickBudget(8ull * 1024 * 1024 * 1024, 0), kDefaultMemCap);
	CHECK_EQ(pickBudget(200ull * 1024 * 1024, kDefaultMemCap), 100ull * 1024 * 1024);
	CHECK_EQ(formatMem(512ull * 1024 * 1024), std::string("512M"));
}

TEST(Mem, TtyHelpers) {
	(void)streamIsTty(stderr);
	(void)wantColor(stderr);
	enableVt(stderr);
}

TEST(Mem, Reserve) {
	MemBudget b(1024);
	CHECK(b.tryReserve(512));
	CHECK_EQ(b.used(), 512ull);
	CHECK(!b.tryReserve(1024));
	b.release(512);
	CHECK_EQ(b.left(), 1024ull);
}

TEST(Mem, ScannerSkipsIndexWhenTight) {
	std::vector<uint8_t> data(256, 0x90);
	data[40] = 0xE8;
	data[41] = 0x01;
	data[42] = 0x02;
	data[43] = 0x03;
	data[44] = 0x04;
	data[45] = 0x45;
	data[46] = 0x33;
	data[47] = 0xF6;
	Binary bin = Binary::loadBytes(data, Arch::X64);
	MemBudget tiny(1);
	Scanner sc(bin, true, &tiny, nullptr);
	CHECK(!sc.hasIndex());
	Pattern p = parsePattern("E8 ? ? ? ? 45 33 F6");
	auto hits = sc.find(p, 8);
	REQUIRE_EQ(hits.size(), size_t{1});
	CHECK_EQ(hits[0].fileOffset, 40ull);
	CHECK_EQ(sc.count(p, 4), size_t{1});
	Scanner indexed(bin, true);
	CHECK(indexed.hasIndex());
	CHECK_EQ(indexed.count(p, 4), size_t{1});
}
