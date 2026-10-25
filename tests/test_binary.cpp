#include "harness.hpp"
#include "bytescanner/image.hpp"

#include <cstring>

using namespace bscan;

namespace {

std::vector<uint8_t> makeElf64(const std::vector<uint8_t>& code) {
	std::vector<uint8_t> b(0x80 + code.size(), 0);
	b[0] = 0x7F;
	b[1] = 'E';
	b[2] = 'L';
	b[3] = 'F';
	b[4] = 2;
	b[5] = 1;
	b[6] = 1;
	auto wu16 = [&](size_t o, uint16_t v) {
		b[o] = static_cast<uint8_t>(v);
		b[o + 1] = static_cast<uint8_t>(v >> 8);
	};
	auto wu32 = [&](size_t o, uint32_t v) {
		wu16(o, static_cast<uint16_t>(v));
		wu16(o + 2, static_cast<uint16_t>(v >> 16));
	};
	auto wu64 = [&](size_t o, uint64_t v) {
		wu32(o, static_cast<uint32_t>(v));
		wu32(o + 4, static_cast<uint32_t>(v >> 32));
	};
	wu16(16, 3);
	wu16(18, 183);
	wu32(20, 1);
	wu64(32, 64);
	wu16(52, 64);
	wu16(54, 56);
	wu16(56, 1);
	wu16(58, 64);
	wu32(64, 1);
	wu32(68, 5);
	wu64(72, 0);
	wu64(80, 0);
	wu64(88, 0);
	wu64(96, b.size());
	wu64(104, b.size());
	wu64(112, 0x1000);
	std::memcpy(b.data() + 0x80, code.data(), code.size());
	return b;
}

std::vector<uint8_t> makePe64(const std::vector<uint8_t>& code) {
	std::vector<uint8_t> b(0x400 + code.size(), 0);
	b[0] = 'M';
	b[1] = 'Z';
	auto wu16 = [&](size_t o, uint16_t v) {
		b[o] = static_cast<uint8_t>(v);
		b[o + 1] = static_cast<uint8_t>(v >> 8);
	};
	auto wu32 = [&](size_t o, uint32_t v) {
		wu16(o, static_cast<uint16_t>(v));
		wu16(o + 2, static_cast<uint16_t>(v >> 16));
	};
	auto wu64 = [&](size_t o, uint64_t v) {
		wu32(o, static_cast<uint32_t>(v));
		wu32(o + 4, static_cast<uint32_t>(v >> 32));
	};
	wu32(0x3C, 0x80);
	b[0x80] = 'P';
	b[0x81] = 'E';
	wu16(0x84, 0x8664);
	wu16(0x86, 1);
	wu16(0x94, 0xF0);
	wu16(0x98, 0x20B);
	wu64(0x80 + 24 + 24, 0x180000000ull);
	wu32(0x80 + 24 + 56, 0x400);
	const size_t sec = 0x80 + 24 + 0xF0;
	const char secName[8] = {'.', 't', 'e', 'x', 't', 0, 0, 0};
	std::memcpy(b.data() + sec, secName, 8);
	wu32(sec + 8, static_cast<uint32_t>(code.size()));
	wu32(sec + 12, 0x1000);
	wu32(sec + 16, static_cast<uint32_t>(code.size()));
	wu32(sec + 20, 0x400);
	wu32(sec + 36, 0x60000020);
	std::memcpy(b.data() + 0x400, code.data(), code.size());
	return b;
}

}

TEST(Binary, Elf64) {
	std::vector<uint8_t> code = {0xA9, 0x00, 0x00, 0x00, 0xD6, 0x5F, 0x03, 0xC0};
	Binary elf = Binary::loadBytes(makeElf64(code));
	CHECK(elf.kind() == FileKind::Elf64);
	CHECK(elf.arch() == Arch::Arm64);
	auto r = elf.resolve(0x80);
	REQUIRE(r.has_value());
	CHECK_EQ(r->fileOffset, 0x80ull);
	CHECK_EQ(elf.sliceFile(0x80, 4)[0], 0xA9);
}

TEST(Binary, Pe64) {
	std::vector<uint8_t> code = {0xA9, 0x00, 0x00, 0x00, 0xD6, 0x5F, 0x03, 0xC0};
	Binary pe = Binary::loadBytes(makePe64(code));
	CHECK(pe.kind() == FileKind::Pe64);
	CHECK(pe.arch() == Arch::X64);
	auto p = pe.resolve(0x1000);
	REQUIRE(p.has_value());
	CHECK_EQ(p->fileOffset, 0x400ull);
	auto p2 = pe.resolve(0x180001000ull);
	CHECK(p2.has_value());
}

TEST(Binary, RawAndArchName) {
	Binary raw = Binary::loadBytes({1, 2, 3, 4, 5});
	CHECK(raw.kind() == FileKind::Unknown);
	CHECK_EQ(raw.sections().size(), size_t{1});
	CHECK(parseArch("arm64") == Arch::Arm64);
	CHECK_EQ(std::string(archName(Arch::X64)), std::string("x86_64"));
}
