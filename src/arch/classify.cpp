#include "bytescanner/func.hpp"

namespace bscan {

namespace {

void classifyX86(std::span<const uint8_t> bytes, Insn& insn, bool is64) {
	if (insn.length == 0 || bytes.empty()) {
		insn.cls = InsnClass::Invalid;
		return;
	}
	size_t i = 0;
	while (i < bytes.size() && i < insn.length && isX86Prefix(bytes[i], is64))
		i++;
	if (i >= bytes.size() || i >= insn.length) {
		insn.cls = InsnClass::Other;
		return;
	}
	uint8_t op = bytes[i];
	uint32_t key = op;
	if (op == 0x0F && i + 1 < bytes.size()) {
		key = 0x0F00u | bytes[i + 1];
		op = bytes[i + 1];
		if (key == 0x0F05 || key == 0x0F07 || key == 0x0F34)
			insn.cls = InsnClass::Ret;
		else if (op >= 0x80 && op <= 0x8F)
			insn.cls = InsnClass::Jcc;
		else if (key == 0x0F1F)
			insn.cls = InsnClass::Nop;
		else
			insn.cls = InsnClass::Other;
		insn.key = key;
		return;
	}
	insn.key = key;
	if (op == 0xC3 || op == 0xC2 || op == 0xCB || op == 0xCA || op == 0xCF)
		insn.cls = InsnClass::Ret;
	else if (op == 0xE8)
		insn.cls = InsnClass::Call;
	else if (op == 0xE9 || op == 0xEB || op == 0xEA)
		insn.cls = InsnClass::Jmp;
	else if (op >= 0x70 && op <= 0x7F)
		insn.cls = InsnClass::Jcc;
	else if ((op >= 0x50 && op <= 0x57) || op == 0x68 || op == 0x6A)
		insn.cls = InsnClass::Push;
	else if (op == 0x90)
		insn.cls = InsnClass::Nop;
	else if (op == 0xFF && i + 1 < bytes.size()) {
		const uint8_t reg = static_cast<uint8_t>((bytes[i + 1] >> 3) & 7);
		if (reg == 2)
			insn.cls = InsnClass::Call;
		else if (reg == 4 || reg == 5)
			insn.cls = InsnClass::Jmp;
		else
			insn.cls = InsnClass::Other;
	} else
		insn.cls = InsnClass::Other;
}

void classifyArm64(std::span<const uint8_t> bytes, Insn& insn) {
	if (insn.length < 4 || bytes.size() < 4) {
		insn.cls = InsnClass::Invalid;
		return;
	}
	const uint32_t w = loadU32le(bytes.data());
	const uint32_t op26 = w >> 26;
	if (w == 0xD65F03C0) {
		insn.cls = InsnClass::Ret;
		insn.key = 0xD65F03C0;
		return;
	}
	if ((w & 0xFFFFFC1F) == 0xD61F0000) {
		insn.cls = InsnClass::Jmp;
		insn.key = 0xD61F0000;
		return;
	}
	if ((w & 0xFFFFFC1F) == 0xD63F0000) {
		insn.cls = InsnClass::Call;
		insn.key = 0xD63F0000;
		return;
	}
	if (op26 == 0x05) {
		insn.cls = InsnClass::Jmp;
		insn.key = 0x14000000;
		return;
	}
	if (op26 == 0x25) {
		insn.cls = InsnClass::Call;
		insn.key = 0x94000000;
		return;
	}
	if ((w & 0xFF000010) == 0x54000000) {
		insn.cls = InsnClass::Jcc;
		insn.key = 0x54000000 | (w & 0x0F);
		return;
	}
	if (w == 0xD503201F)
		insn.cls = InsnClass::Nop;
	else
		insn.cls = InsnClass::Other;
	insn.key = w & 0xFFE0001F;
}

void classifyArm32(std::span<const uint8_t> bytes, Insn& insn) {
	if (insn.length < 4 || bytes.size() < 4) {
		insn.cls = InsnClass::Invalid;
		return;
	}
	const uint32_t w = loadU32le(bytes.data());
	if (w == 0xE12FFF1E || (w & 0x0FFFFFFF) == 0x012FFF1E) {
		insn.cls = InsnClass::Ret;
		insn.key = 0xE12FFF1E;
		return;
	}
	const uint32_t op = (w >> 24) & 0x0F;
	if (op == 0xA) {
		insn.cls = InsnClass::Jmp;
		insn.key = 0xEA000000;
	} else if (op == 0xB) {
		insn.cls = InsnClass::Call;
		insn.key = 0xEB000000;
	} else {
		insn.cls = InsnClass::Other;
		insn.key = w & 0x0FF00000;
	}
}

void classifyThumb(std::span<const uint8_t> bytes, Insn& insn) {
	if (insn.length == 0 || bytes.empty()) {
		insn.cls = InsnClass::Invalid;
		return;
	}
	if (insn.length >= 4 && bytes.size() >= 4) {
		const uint16_t h1 = loadU16le(bytes.data());
		const uint16_t h2 = loadU16le(bytes.data() + 2);
		if ((h1 & 0xF800) == 0xF000 && (h2 & 0xD000) == 0xD000) {
			insn.cls = InsnClass::Call;
			insn.key = 0xF000D000;
			return;
		}
	}
	const uint16_t h = loadU16le(bytes.data());
	insn.key = h;
	if ((h & 0xFF00) == 0x4700)
		insn.cls = InsnClass::Jmp;
	else if ((h & 0xF000) == 0xD000 && (h & 0x0F00) != 0x0F00)
		insn.cls = InsnClass::Jcc;
	else if ((h & 0xF800) == 0xE000)
		insn.cls = InsnClass::Jmp;
	else
		insn.cls = InsnClass::Other;
}

void classifyMips(std::span<const uint8_t> bytes, Insn& insn) {
	if (insn.length < 4 || bytes.size() < 4) {
		insn.cls = InsnClass::Invalid;
		return;
	}
	const uint32_t w = loadU32le(bytes.data());
	const uint32_t op = w >> 26;
	if (op == 3) {
		insn.cls = InsnClass::Call;
		insn.key = 0x0C000000;
	} else if (op == 2) {
		insn.cls = InsnClass::Jmp;
		insn.key = 0x08000000;
	} else if (op == 0 && (w & 0x3F) == 9) {
		insn.cls = InsnClass::Call;
		insn.key = 9;
	} else if (op == 0 && (w & 0x3F) == 8) {
		insn.cls = InsnClass::Ret;
		insn.key = 8;
	} else {
		insn.cls = InsnClass::Other;
		insn.key = op;
	}
}

void classifyRiscv(std::span<const uint8_t> bytes, Insn& insn) {
	if (insn.length == 0 || bytes.size() < 2) {
		insn.cls = InsnClass::Invalid;
		return;
	}
	if (insn.length < 4 || bytes.size() < 4) {
		insn.cls = InsnClass::Other;
		insn.key = loadU16le(bytes.data());
		return;
	}
	const uint32_t w = loadU32le(bytes.data());
	const uint32_t opc = w & 0x7F;
	const uint32_t rd = (w >> 7) & 0x1F;
	if (opc == 0x6F) {
		insn.cls = rd == 1 ? InsnClass::Call : InsnClass::Jmp;
		insn.key = 0x6F;
	} else if (opc == 0x67) {
		const uint32_t rs1 = (w >> 15) & 0x1F;
		if (rd == 0 && rs1 == 1)
			insn.cls = InsnClass::Ret;
		else if (rd == 1)
			insn.cls = InsnClass::Call;
		else
			insn.cls = InsnClass::Jmp;
		insn.key = 0x67;
	} else {
		insn.cls = InsnClass::Other;
		insn.key = opc;
	}
}

} // namespace

void classifyInsn(Arch arch, std::span<const uint8_t> bytes, Insn& insn) {
	switch (arch) {
	case Arch::X86:
		classifyX86(bytes, insn, false);
		break;
	case Arch::X64:
		classifyX86(bytes, insn, true);
		break;
	case Arch::Arm64:
		classifyArm64(bytes, insn);
		break;
	case Arch::Arm32:
		classifyArm32(bytes, insn);
		break;
	case Arch::Thumb:
		classifyThumb(bytes, insn);
		break;
	case Arch::Mips32:
	case Arch::Mips64:
		classifyMips(bytes, insn);
		break;
	case Arch::Riscv32:
	case Arch::Riscv64:
		classifyRiscv(bytes, insn);
		break;
	default:
		if (insn.length == 0)
			insn.cls = InsnClass::Invalid;
		else {
			insn.cls = InsnClass::Other;
			insn.key = bytes.empty() ? 0 : bytes[0];
		}
		break;
	}
}

}
