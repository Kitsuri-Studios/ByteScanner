#pragma once

#include "image.hpp"
#include "pattern.hpp"

#include <span>

namespace bscan {

enum class InsnClass : uint8_t {
	Other,
	Invalid,
	Ret,
	Call,
	Jmp,
	Jcc,
	Push,
	Nop,
};

struct Insn {
	uint8_t length = 0;
	uint8_t mask[16]{};
	uint32_t key = 0;
	InsnClass cls = InsnClass::Other;

	void fillExact(uint8_t n) {
		length = n;
		for (uint8_t i = 0; i < n && i < 16; i++)
			mask[i] = 0xFF;
	}

	void wildRange(uint8_t from, uint8_t n) {
		for (uint8_t i = 0; i < n; i++) {
			const uint8_t idx = static_cast<uint8_t>(from + i);
			if (idx < 16)
				mask[idx] = 0;
		}
	}
};

inline bool isX86Prefix(uint8_t b, bool is64) {
	if (b == 0xF0 || b == 0xF2 || b == 0xF3)
		return true;
	if (b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65)
		return true;
	if (b == 0x66 || b == 0x67)
		return true;
	return is64 && b >= 0x40 && b <= 0x4F;
}

inline size_t skipX86Prefix(std::span<const uint8_t> bytes, bool is64, size_t maxN = 14) {
	size_t i = 0;
	while (i < bytes.size() && i < maxN && isX86Prefix(bytes[i], is64))
		i++;
	return i;
}

Insn decodeInsn(Arch arch, std::span<const uint8_t> bytes);
void applyArchWildcards(Pattern& p, Arch arch);
void wildArm64Frame(Insn& insn, uint32_t w);
size_t minSigLen(Arch arch);
size_t insnAlign(Arch arch);

Insn decodeX86(std::span<const uint8_t> bytes, bool is64);
Insn decodeArm64(std::span<const uint8_t> bytes);
Insn decodeArm32(std::span<const uint8_t> bytes);
Insn decodeThumb(std::span<const uint8_t> bytes);
Insn decodeMips(std::span<const uint8_t> bytes);
Insn decodeRiscv(std::span<const uint8_t> bytes);

}
