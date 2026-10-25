#include "harness.hpp"
#include "bytescanner/arch.hpp"
#include "bytescanner/bytes.hpp"
#include "bytescanner/func.hpp"

#include <span>

using namespace bscan;

TEST(Arch, X64CallRel) {
	uint8_t call[] = {0xE8, 0x11, 0x22, 0x33, 0x44};
	Insn x = decodeX86(call, true);
	CHECK_EQ(x.length, 5);
	CHECK_EQ(x.mask[0], 0xFF);
	CHECK_EQ(x.mask[1], 0);
	CHECK_EQ(x.mask[4], 0);
}

TEST(Arch, Arm64Bl) {
	uint8_t bl[4];
	storeLe<uint32_t>(bl, 0x94000003);
	Insn a = decodeArm64(bl);
	CHECK_EQ(a.length, 4);
	CHECK_EQ(a.mask[0], 0);
	CHECK_EQ(a.mask[3], 0xF0);
}

TEST(Arch, Arm32Bl) {
	uint8_t armbl[4];
	storeLe<uint32_t>(armbl, 0xEB000001);
	Insn b = decodeArm32(armbl);
	CHECK_EQ(b.length, 4);
	CHECK_EQ(b.mask[0], 0);
}

TEST(Arch, Arm64Nop) {
	uint8_t nop[] = {0x1F, 0x20, 0x03, 0xD5};
	Insn n = decodeArm64(nop);
	CHECK_EQ(n.length, 4);
	CHECK_EQ(n.mask[0], 0xFF);
	CHECK_EQ(minSigLen(Arch::Arm64), size_t{8});
	CHECK_EQ(insnAlign(Arch::X64), size_t{1});
}

TEST(Arch, Arm64Prelude) {
	uint8_t stp[] = {0xE9, 0x23, 0xBC, 0x6D};
	CHECK(isPrelude(Arch::Arm64, std::span<const uint8_t>(stp, 4)));
	uint8_t frame[] = {0xFD, 0x7B, 0xBF, 0xA9};
	CHECK(isPrelude(Arch::Arm64, std::span<const uint8_t>(frame, 4)));
	uint8_t stpOff[] = {0xFD, 0x7B, 0x01, 0xA9};
	CHECK(isPrelude(Arch::Arm64, std::span<const uint8_t>(stpOff, 4)));
	uint8_t spill[] = {0xF3, 0x53, 0x01, 0xA9};
	CHECK(!isPrelude(Arch::Arm64, std::span<const uint8_t>(spill, 4)));
	uint8_t addSp[] = {0xFF, 0x43, 0x00, 0x91};
	CHECK(!isPrelude(Arch::Arm64, std::span<const uint8_t>(addSp, 4)));
	uint8_t mrsFrm[] = {0x48, 0xD0, 0x3B, 0xD5, 0xFF, 0x43, 0x00, 0xD1};
	CHECK(isPrelude(Arch::Arm64, std::span<const uint8_t>(mrsFrm, 8)));
	uint8_t mrsOnly[] = {0x48, 0xD0, 0x3B, 0xD5, 0x00, 0x00, 0x00, 0x00};
	CHECK(!isPrelude(Arch::Arm64, std::span<const uint8_t>(mrsOnly, 8)));
	uint8_t subSp[] = {0xFF, 0x43, 0x00, 0xD1};
	uint8_t retw[] = {0xC0, 0x03, 0x5F, 0xD6};
	uint8_t ldr[] = {0x08, 0x00, 0x40, 0xF9};
	CHECK(isPrelude(Arch::Arm64, std::span<const uint8_t>(subSp, 4), std::span<const uint8_t>(retw, 4)));
	CHECK(!isPrelude(Arch::Arm64, std::span<const uint8_t>(subSp, 4)));
	CHECK(!isPrelude(Arch::Arm64, std::span<const uint8_t>(subSp, 4), std::span<const uint8_t>(ldr, 4)));
}

TEST(Arch, Arm64FrameWild) {
	uint8_t subSp[] = {0xFF, 0x43, 0x00, 0xD1};
	Insn sub = decodeArm64(std::span<const uint8_t>(subSp, 4));
	CHECK_EQ(sub.length, 4);
	CHECK_EQ(sub.mask[0], 0xFF);
	CHECK_EQ(sub.mask[1], 0xFF);
	Pattern framePat;
	framePat.append(0xFF, 0xFF);
	framePat.append(0x43, 0xFF);
	framePat.append(0x00, 0xFF);
	framePat.append(0xD1, 0xFF);
	applyArchWildcards(framePat, Arch::Arm64);
	CHECK_EQ(framePat.mask[1], 0x03);
	CHECK_EQ(framePat.mask[2], 0x80);
	uint8_t stpOff[] = {0xFD, 0x7B, 0x01, 0xA9};
	Insn stpW = decodeArm64(std::span<const uint8_t>(stpOff, 4));
	wildArm64Frame(stpW, 0xA9017BFD);
	CHECK_EQ(stpW.mask[1], 0x7F);
	CHECK_EQ(stpW.mask[2], 0xC0);
	Pattern grow = parsePattern("FF 43 00 D1 20 00 80 52");
	applyArchWildcards(grow, Arch::Arm64);
	uint8_t neuFrm[] = {0xFF, 0x83, 0x00, 0xD1, 0x20, 0x00, 0x80, 0x52};
	CHECK(grow.matches(std::span<const uint8_t>(neuFrm, 8)));
}
