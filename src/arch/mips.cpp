#include "bytescanner/arch.hpp"

#include "bytescanner/bytes.hpp"

namespace bscan {

Insn decodeMips(std::span<const uint8_t> bytes) {
	Insn insn;
	if (bytes.size() < 4)
		return insn;
	insn.fillExact(4);
	const uint32_t w = loadU32le(bytes.data());
	const uint32_t op = w >> 26;
	if (op == 2 || op == 3) {
		insn.wildRange(0, 3);
		insn.mask[3] = 0xFC;
		return insn;
	}
	if (op == 4 || op == 5 || op == 6 || op == 7 || op == 1) {
		insn.wildRange(0, 2);
		return insn;
	}
	return insn;
}

}
