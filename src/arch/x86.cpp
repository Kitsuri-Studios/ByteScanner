#include "bytescanner/arch.hpp"

namespace bscan {

namespace {

enum : uint8_t {
	N = 0,
	M = 1,
	Ib = 2,
	Iz = 3,
	Iv = 4,
	MIb = 5,
	MIz = 6,
	Jb = 7,
	Jz = 8,
	Iw = 9,
	Ibw = 10,
	Esc = 11,
};

const uint8_t kPrimary[256] = {
	M, M, M, M, Ib, Iz, N, N, M, M, M, M, Ib, Iz, N, Esc,
	M, M, M, M, Ib, Iz, N, N, M, M, M, M, Ib, Iz, N, N,
	M, M, M, M, Ib, Iz, N, N, M, M, M, M, Ib, Iz, N, N,
	M, M, M, M, Ib, Iz, N, N, M, M, M, M, Ib, Iz, N, N,
	N, N, N, N, N, N, N, N, N, N, N, N, N, N, N, N,
	N, N, N, N, N, N, N, N, N, N, N, N, N, N, N, N,
	N, N, M, M, N, N, N, N, Iz, MIz, Ib, MIb, N, N, N, N,
	Jb, Jb, Jb, Jb, Jb, Jb, Jb, Jb, Jb, Jb, Jb, Jb, Jb, Jb, Jb, Jb,
	MIb, MIz, MIb, MIb, M, M, M, M, M, M, M, M, M, M, M, M,
	N, N, N, N, N, N, N, N, N, N, N, N, N, N, N, N,
	N, N, N, N, N, N, N, N, Ib, Iz, N, N, N, N, N, N,
	Ib, Ib, Ib, Ib, Ib, Ib, Ib, Ib, Iv, Iv, Iv, Iv, Iv, Iv, Iv, Iv,
	MIb, MIb, Iw, N, M, M, MIb, MIz, Ibw, N, Iw, N, N, Ib, N, N,
	M, M, M, M, Ib, Ib, N, N, M, M, M, M, M, M, M, M,
	Jb, Jb, Jb, Jb, Ib, Ib, Ib, Ib, Jz, Jz, N, Jb, N, N, N, N,
	N, N, N, N, N, N, M, M, N, N, N, N, N, N, M, M,
};

size_t parseModrm(std::span<const uint8_t> bytes, size_t off, bool is64, bool addr32, bool& isRip,
	size_t& dispAt, size_t& dispSz) {
	isRip = false;
	dispAt = 0;
	dispSz = 0;
	if (off >= bytes.size())
		return 0;
	const uint8_t m = bytes[off];
	size_t used = 1;
	const uint8_t mod = static_cast<uint8_t>(m >> 6);
	const uint8_t rm = static_cast<uint8_t>(m & 7);
	if (mod == 3)
		return used;
	bool sib = false;
	uint8_t sibByte = 0;
	if (!addr32) {
		if (rm == 6 && mod == 0) {
			dispAt = off + used;
			dispSz = 2;
			used += 2;
		} else if (mod == 1) {
			dispAt = off + used;
			dispSz = 1;
			used += 1;
		} else if (mod == 2) {
			dispAt = off + used;
			dispSz = 2;
			used += 2;
		}
		return off + used > bytes.size() ? 0 : used;
	}
	if (rm == 4) {
		if (off + used >= bytes.size())
			return 0;
		sib = true;
		sibByte = bytes[off + used];
		used++;
	}
	if (mod == 1) {
		dispAt = off + used;
		dispSz = 1;
		used += 1;
	} else if (mod == 2) {
		dispAt = off + used;
		dispSz = 4;
		used += 4;
	} else if (mod == 0 && rm == 5) {
		dispAt = off + used;
		dispSz = 4;
		used += 4;
		isRip = is64;
	} else if (mod == 0 && sib && (sibByte & 7) == 5) {
		dispAt = off + used;
		dispSz = 4;
		used += 4;
	}
	if (off + used > bytes.size())
		return 0;
	return used;
}

uint8_t map0f(uint8_t op) {
	if (op >= 0x80 && op <= 0x8F)
		return Jz;
	if (op == 0xA4 || op == 0xAC || op == 0xBA)
		return MIb;
	if (op == 0xA5 || op == 0xAD)
		return M;
	if (op == 0x70 || op == 0x71 || op == 0x72 || op == 0x73 || op == 0xC2 || op == 0xC4 || op == 0xC5
		|| op == 0xC6)
		return MIb;
	if (op == 0x05 || op == 0x06 || op == 0x07 || op == 0x08 || op == 0x09 || op == 0x0B || op == 0x30
		|| op == 0x31 || op == 0x32 || op == 0x33 || op == 0x34 || op == 0x35 || op == 0x37 || op == 0xA0
		|| op == 0xA1 || op == 0xA2 || op == 0xA8 || op == 0xA9 || op == 0xAA || op == 0xC8 || op == 0xC9
		|| op == 0xCA || op == 0xCB || op == 0xCC || op == 0xCD || op == 0xCE || op == 0xCF)
		return N;
	return M;
}

} // namespace

Insn decodeX86(std::span<const uint8_t> bytes, bool is64) {
	Insn insn;
	if (bytes.empty())
		return insn;
	size_t i = 0;
	bool opsize16 = false;
	bool addr32 = is64;
	bool rexW = false;
	while (i < bytes.size() && i < 14 && isX86Prefix(bytes[i], is64)) {
		if (bytes[i] == 0x66)
			opsize16 = true;
		if (bytes[i] == 0x67)
			addr32 = !is64;
		if (is64 && bytes[i] >= 0x40 && bytes[i] <= 0x4F)
			rexW = (bytes[i] & 8) != 0;
		i++;
	}
	if (i >= bytes.size())
		return insn;
	if (bytes[i] == 0x62 && is64) {
		if (i + 5 > bytes.size())
			return insn;
		i += 4;
		const uint8_t op = bytes[i++];
		bool isRip = false;
		size_t dispAt = 0, dispSz = 0;
		const size_t m = parseModrm(bytes, i, true, true, isRip, dispAt, dispSz);
		if (m == 0)
			return insn;
		i += m;
		if (op == 0x70 || op == 0xC2)
			i += 1;
		if (i > 15)
			i = 15;
		insn.fillExact(static_cast<uint8_t>(i));
		if (isRip)
			insn.wildRange(static_cast<uint8_t>(dispAt), static_cast<uint8_t>(dispSz));
		return insn;
	}
	if ((bytes[i] == 0xC4 || bytes[i] == 0xC5) && is64) {
		const size_t vexLen = bytes[i] == 0xC4 ? 3 : 2;
		if (i + vexLen + 1 > bytes.size())
			return insn;
		i += vexLen;
		const uint8_t op = bytes[i++];
		bool isRip = false;
		size_t dispAt = 0, dispSz = 0;
		const size_t m = parseModrm(bytes, i, true, true, isRip, dispAt, dispSz);
		if (m == 0)
			return insn;
		i += m;
		if (op == 0x70 || op == 0xC2 || op == 0xC4 || op == 0xC5 || op == 0xC6)
			i += 1;
		if (i > 15)
			i = 15;
		insn.fillExact(static_cast<uint8_t>(i));
		if (isRip)
			insn.wildRange(static_cast<uint8_t>(dispAt), static_cast<uint8_t>(dispSz));
		return insn;
	}
	uint8_t op = bytes[i++];
	uint8_t kind = kPrimary[op];
	if (kind == Esc) {
		if (i >= bytes.size())
			return insn;
		if (bytes[i] == 0x38 || bytes[i] == 0x3A) {
			const bool hasImm = bytes[i] == 0x3A;
			i++;
			if (i >= bytes.size())
				return insn;
			i++;
			bool isRip = false;
			size_t dispAt = 0, dispSz = 0;
			const size_t m = parseModrm(bytes, i, is64, addr32, isRip, dispAt, dispSz);
			if (m == 0)
				return insn;
			i += m;
			if (hasImm)
				i += 1;
			if (i > 15)
				return insn;
			insn.fillExact(static_cast<uint8_t>(i));
			if (isRip)
				insn.wildRange(static_cast<uint8_t>(dispAt), static_cast<uint8_t>(dispSz));
			return insn;
		}
		op = bytes[i++];
		kind = map0f(op);
	}
	bool isRip = false;
	size_t dispAt = 0, dispSz = 0;
	if (kind == M || kind == MIb || kind == MIz) {
		const size_t m = parseModrm(bytes, i, is64, addr32, isRip, dispAt, dispSz);
		if (m == 0)
			return insn;
		if ((op == 0xF6 || op == 0xF7) && i < bytes.size()) {
			const uint8_t reg = static_cast<uint8_t>((bytes[i] >> 3) & 7);
			if (reg == 0)
				kind = op == 0xF6 ? MIb : MIz;
		}
		i += m;
	}
	if (op == 0xA0 || op == 0xA1 || op == 0xA2 || op == 0xA3) {
		const size_t asz = addr32 ? (is64 ? 8 : 4) : 2;
		if (i + asz > bytes.size())
			return insn;
		const size_t at = i;
		i += asz;
		insn.fillExact(static_cast<uint8_t>(i));
		insn.wildRange(static_cast<uint8_t>(at), static_cast<uint8_t>(asz));
		return insn;
	}
	size_t imm = 0;
	bool wildImm = false;
	switch (kind) {
	case Ib:
	case MIb:
	case Jb:
		imm = 1;
		wildImm = kind == Jb;
		break;
	case Iw:
		imm = 2;
		break;
	case Ibw:
		imm = 3;
		break;
	case Iz:
	case MIz:
	case Jz:
		imm = opsize16 ? 2 : 4;
		wildImm = kind == Jz;
		break;
	case Iv:
		if (rexW)
			imm = 8;
		else
			imm = opsize16 ? 2 : 4;
		wildImm = rexW;
		break;
	default:
		break;
	}
	if (i + imm > bytes.size() || i + imm > 15)
		return insn;
	const size_t immAt = i;
	i += imm;
	insn.fillExact(static_cast<uint8_t>(i));
	if (isRip)
		insn.wildRange(static_cast<uint8_t>(dispAt), static_cast<uint8_t>(dispSz));
	if (wildImm)
		insn.wildRange(static_cast<uint8_t>(immAt), static_cast<uint8_t>(imm));
	return insn;
}

}
