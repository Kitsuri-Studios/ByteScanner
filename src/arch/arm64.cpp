#include "bytescanner/arch.hpp"

#include "bytescanner/bytes.hpp"

namespace bscan {

Insn decodeArm64(std::span<const uint8_t> bytes) {
	Insn insn;
	if (bytes.size() < 4)
		return insn;
	insn.fillExact(4);
	const uint32_t w = loadU32le(bytes.data());
	const uint32_t op26 = w >> 26;
	if (op26 == 0x05 || op26 == 0x25) {
		insn.wildRange(0, 3);
		insn.mask[3] = 0xF0;
		return insn;
	}
	if ((w & 0xFF000010u) == 0x54000000u || (w & 0x7E000000u) == 0x34000000u
		|| (w & 0x7E000000u) == 0x36000000u
		|| (w & 0xFF000000u) == 0x18000000u || (w & 0xFF000000u) == 0x58000000u
		|| (w & 0xFF000000u) == 0x98000000u || (w & 0xFF000000u) == 0xD8000000u) {
		insn.mask[0] = 0x1F;
		insn.mask[1] = 0;
		insn.mask[2] = 0;
		insn.mask[3] = 0xFF;
		return insn;
	}
	if ((w & 0x1F000000u) == 0x10000000u) {
		insn.mask[0] = 0x1F;
		insn.mask[1] = 0;
		insn.mask[2] = 0;
		insn.mask[3] = 0x9F;
		return insn;
	}
	return insn;
}

void wildArm64Frame(Insn& insn, uint32_t w) {
	if (insn.length < 4)
		return;
	const uint32_t rd = w & 31;
	const uint32_t rn = (w >> 5) & 31;
	if ((w & 0x1F000000u) == 0x11000000u && (rn == 31 || rd == 31)) {
		insn.mask[1] = 0x03;
		insn.mask[2] = 0x80;
		return;
	}
	const uint32_t pair = w >> 22;
	if (rn == 31
		&& (pair == 0x2A2 || pair == 0x2A3 || pair == 0x2A4 || pair == 0x2A5 || pair == 0x2A6 || pair == 0x2A7
			|| pair == 0x292 || pair == 0x293 || pair == 0x294 || pair == 0x295 || pair == 0x296
			|| pair == 0x297)) {
		insn.mask[1] = 0x7F;
		insn.mask[2] = 0xC0;
	}
}

}
