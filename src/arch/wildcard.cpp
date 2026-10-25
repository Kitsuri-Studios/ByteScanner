#include "bytescanner/arch.hpp"
#include "bytescanner/func.hpp"

namespace bscan {

size_t insnAlign(Arch arch) {
	switch (arch) {
	case Arch::Arm64:
	case Arch::Arm32:
	case Arch::Mips32:
	case Arch::Mips64:
		return 4;
	case Arch::Thumb:
	case Arch::Riscv32:
	case Arch::Riscv64:
		return 2;
	default:
		return 1;
	}
}

size_t minSigLen(Arch arch) {
	switch (arch) {
	case Arch::Arm64:
	case Arch::Arm32:
	case Arch::Mips32:
	case Arch::Mips64:
		return 8;
	case Arch::Thumb:
		return 6;
	case Arch::Riscv32:
	case Arch::Riscv64:
		return 6;
	case Arch::X86:
	case Arch::X64:
		return 5;
	default:
		return 4;
	}
}

Insn decodeInsn(Arch arch, std::span<const uint8_t> bytes) {
	Insn insn;
	switch (arch) {
	case Arch::X86:
		insn = decodeX86(bytes, false);
		break;
	case Arch::X64:
		insn = decodeX86(bytes, true);
		break;
	case Arch::Arm64:
		insn = decodeArm64(bytes);
		break;
	case Arch::Arm32:
		insn = decodeArm32(bytes);
		break;
	case Arch::Thumb:
		insn = decodeThumb(bytes);
		break;
	case Arch::Mips32:
	case Arch::Mips64:
		insn = decodeMips(bytes);
		break;
	case Arch::Riscv32:
	case Arch::Riscv64:
		insn = decodeRiscv(bytes);
		break;
	default:
		if (!bytes.empty()) {
			insn.length = 1;
			insn.mask[0] = 0xFF;
		}
		break;
	}
	classifyInsn(arch, bytes, insn);
	return insn;
}

void applyArchWildcards(Pattern& p, Arch arch) {
	if (p.empty() || !isCodeArch(arch))
		return;
	size_t off = 0;
	while (off < p.size()) {
		Insn insn = decodeInsn(arch, std::span<const uint8_t>(p.bytes.data() + off, p.size() - off));
		if (insn.length == 0 || insn.length > p.size() - off)
			break;
		if (arch == Arch::Arm64 && insn.length >= 4)
			wildArm64Frame(insn, loadU32le(p.bytes.data() + off));
		for (size_t i = 0; i < insn.length && i < 16; i++)
			p.mask[off + i] = static_cast<uint8_t>(p.mask[off + i] & insn.mask[i]);
		off += insn.length;
	}
}

}
