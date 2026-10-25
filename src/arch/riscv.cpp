#include "bytescanner/arch.hpp"

#include "bytescanner/bytes.hpp"

namespace bscan {

Insn decodeRiscv(std::span<const uint8_t> bytes) {
	Insn insn;
	if (bytes.size() < 2)
		return insn;
	const uint16_t h = loadU16le(bytes.data());
	if ((h & 3) != 3) {
		insn.fillExact(2);
		if ((h & 0xE003) == 0xA001) {
			insn.mask[0] = 0x03;
			insn.mask[1] = 0xE0;
		}
		return insn;
	}
	if (bytes.size() < 4)
		return insn;
	insn.fillExact(4);
	const uint32_t w = loadU32le(bytes.data());
	const uint32_t opc = w & 0x7F;
	if (opc == 0x6F || opc == 0x17 || opc == 0x37) {
		insn.mask[0] = 0x7F;
		insn.mask[1] = 0x0F;
		insn.mask[2] = 0;
		insn.mask[3] = 0;
		return insn;
	}
	if (opc == 0x63) {
		insn.mask[0] = 0x7F;
		insn.mask[1] = 0x0F;
		insn.mask[2] = 0x0F;
		insn.mask[3] = 0;
		return insn;
	}
	return insn;
}

}
