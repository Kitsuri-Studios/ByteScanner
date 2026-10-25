#include "bytescanner/arch.hpp"

#include "bytescanner/bytes.hpp"

namespace bscan {

Insn decodeArm32(std::span<const uint8_t> bytes) {
	Insn insn;
	if (bytes.size() < 4)
		return insn;
	insn.fillExact(4);
	const uint32_t w = loadU32le(bytes.data());
	const uint32_t op = (w >> 24) & 0x0F;
	if (op == 0xA || op == 0xB || (w & 0x0E000000u) == 0x0A000000u) {
		insn.wildRange(0, 3);
		return insn;
	}
	if ((w & 0x0F7F0000u) == 0x051F0000u) {
		insn.wildRange(0, 2);
		return insn;
	}
	return insn;
}

Insn decodeThumb(std::span<const uint8_t> bytes) {
	Insn insn;
	if (bytes.size() < 2)
		return insn;
	const uint16_t h = loadU16le(bytes.data());
	const uint16_t hi = static_cast<uint16_t>(h >> 11);
	if (hi == 0x1D || hi == 0x1E || hi == 0x1F) {
		if (bytes.size() < 4)
			return insn;
		insn.fillExact(4);
		if ((h & 0xF800) == 0xF000 && (loadU16le(bytes.data() + 2) & 0xD000) == 0xD000) {
			insn.mask[0] = 0;
			insn.mask[1] = 0xF8;
			insn.mask[2] = 0;
			insn.mask[3] = 0xD0;
		}
		return insn;
	}
	insn.fillExact(2);
	if ((h & 0xF000) == 0xD000 && (h & 0x0F00) != 0x0F00) {
		insn.mask[0] = 0;
		return insn;
	}
	if ((h & 0xF800) == 0xE000) {
		insn.mask[0] = 0;
		insn.mask[1] = 0xF8;
		return insn;
	}
	return insn;
}

}
