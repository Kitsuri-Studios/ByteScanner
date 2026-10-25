#include "bytescanner/func.hpp"
#include "internal.hpp"

namespace bscan {

namespace {

Vtable readVtable(const Binary& bin, uint64_t methodPtrOff) {
	const size_t n = bin.ptrWidth();
	uint64_t slot0 = methodPtrOff;
	int back = 0;
	while (back < 256 && slot0 >= n && fp::isExecPtr(bin, slot0 - n)) {
		slot0 -= n;
		back++;
	}
	Vtable vt;
	vt.fileOff = slot0;
	uint64_t off = slot0;
	while (vt.methods.size() < 256 && fp::isExecPtr(bin, off)) {
		vt.methods.push_back(*bin.readPtr(off));
		off += n;
	}
	return vt;
}

std::string itaniumClass(std::string_view n) {
	if (n.size() < 4 || n[0] != '_' || n[1] != 'Z')
		return {};
	size_t i = 2;
	if (n[i] == 'T') {
		const size_t p = n.find('N', i);
		if (p == std::string_view::npos)
			return {};
		i = p;
	}
	if (i >= n.size() || n[i] != 'N')
		return {};
	i++;
	while (i < n.size() && (n[i] == 'K' || n[i] == 'V' || n[i] == 'r'))
		i++;
	std::string key = "_ZN";
	int parts = 0;
	size_t lastPart = key.size();
	while (i < n.size() && n[i] >= '0' && n[i] <= '9') {
		const size_t numAt = i;
		size_t len = 0;
		while (i < n.size() && n[i] >= '0' && n[i] <= '9') {
			len = len * 10 + static_cast<size_t>(n[i] - '0');
			i++;
		}
		if (len == 0 || i + len > n.size())
			break;
		lastPart = key.size();
		key.append(n.data() + numAt, (i - numAt) + len);
		i += len;
		parts++;
	}
	if (parts == 0)
		return {};
	if (parts >= 2)
		key.resize(lastPart);
	return key;
}

std::string msvcClass(std::string_view n) {
	if (n.empty() || n[0] != '?')
		return {};
	size_t i = 1;
	while (i < n.size() && n[i] == '?')
		i++;
	while (i < n.size() && n[i] != '@')
		i++;
	if (i >= n.size())
		return {};
	i++;
	const size_t classAt = i;
	const size_t end = n.find("@@", i);
	if (end == std::string_view::npos || end == classAt)
		return {};
	return std::string(n.substr(classAt, end - classAt));
}

std::vector<std::string> classNeedles(std::string_view key) {
	std::vector<std::string> out;
	if (key.size() > 3 && key.substr(0, 3) == "_ZN") {
		const std::string rest(key.substr(3));
		out.push_back("_ZTS" + rest);
		out.push_back("_ZTI" + rest);
		out.push_back("_ZTV" + rest);
		out.push_back(rest);
	} else if (!key.empty()) {
		out.push_back(".?AV" + std::string(key) + "@@");
		out.push_back(".?AU" + std::string(key) + "@@");
	}
	return out;
}

std::optional<Vtable> vtableFromTypeInfo(const Binary& bin, uint64_t typeInfoVa) {
	auto tiPtrs = fp::findPtrHitsCap(bin, typeInfoVa, 32, bin.ptrWidth());
	std::optional<Vtable> best;
	const size_t n = bin.ptrWidth();
	for (uint64_t tp : tiPtrs) {
		auto loc = bin.resolve(tp, AddressKind::File);
		if (!loc || bin.isExecVa(loc->va))
			continue;
		if (!fp::isExecPtr(bin, tp + n))
			continue;
		Vtable vt = readVtable(bin, tp + n);
		if (vt.methods.empty())
			continue;
		if (!best || vt.methods.size() > best->methods.size())
			best = std::move(vt);
	}
	return best;
}

} // namespace

std::string classKey(std::string_view name) {
	if (name.size() >= 2 && name[0] == '_' && name[1] == 'Z')
		return itaniumClass(name);
	if (!name.empty() && name[0] == '?')
		return msvcClass(name);
	return {};
}

int vtableSlot(const Vtable& vt, uint64_t methodVa) {
	for (int i = 0; i < static_cast<int>(vt.methods.size()); i++) {
		if (vt.methods[static_cast<size_t>(i)] == methodVa)
			return i;
	}
	return -1;
}

std::vector<Vtable> findVtables(const Binary& bin, uint64_t methodVa) {
	std::vector<Vtable> out;
	auto hits = fp::findPtrHitsCap(bin, methodVa, 64, bin.ptrWidth());
	for (uint64_t off : hits) {
		auto at = bin.resolve(off, AddressKind::File);
		if (!at || bin.isExecVa(at->va))
			continue;
		Vtable vt = readVtable(bin, off);
		if (vt.methods.empty())
			continue;
		bool dup = false;
		for (const Vtable& old : out) {
			if (old.fileOff == vt.fileOff) {
				dup = true;
				break;
			}
		}
		if (!dup)
			out.push_back(std::move(vt));
	}
	return out;
}

std::optional<Vtable> findClassVtable(const Binary& bin, std::string_view key, bool allowMany) {
	if (key.empty())
		return std::nullopt;
	const size_t n = bin.ptrWidth();
	std::optional<Vtable> best;
	for (const std::string& s : classNeedles(key)) {
		auto strHits = fp::findNeedle(bin, s);
		std::vector<uint64_t> bounded;
		for (uint64_t off : strHits) {
			if (fp::isCStringAt(bin, off, s.size()))
				bounded.push_back(off);
		}
		if (bounded.empty() || (!allowMany && bounded.size() != 1))
			continue;
		for (uint64_t boff : bounded) {
			auto r = bin.resolve(boff, AddressKind::File);
			if (!r)
				continue;
			auto namePtrs = fp::findPtrHitsCap(bin, r->va, 32, n);
			for (uint64_t np : namePtrs) {
				auto at = bin.resolve(np, AddressKind::File);
				if (!at || bin.isExecVa(at->va))
					continue;
				for (size_t back : {n, n * 2}) {
					if (at->va < back)
						continue;
					auto vt = vtableFromTypeInfo(bin, at->va - back);
					if (!vt)
						continue;
					if (!best || vt->methods.size() > best->methods.size())
						best = std::move(vt);
				}
			}
		}
		if (best && !allowMany)
			return best;
	}
	return best;
}

std::optional<uint64_t> mapVtableTarget(const Vtable* oldVt, uint64_t oldTarget, uint64_t oldAnchor,
	const Vtable& neuVt, uint64_t newAnchor) {
	if (neuVt.methods.empty())
		return std::nullopt;
	int slot = -1;
	if (oldVt) {
		const int t = vtableSlot(*oldVt, oldTarget);
		if (t < 0)
			return std::nullopt;
		if (oldAnchor != 0 && newAnchor != 0) {
			const int oa = vtableSlot(*oldVt, oldAnchor);
			const int na = vtableSlot(neuVt, newAnchor);
			if (oa < 0 || na < 0)
				return std::nullopt;
			slot = t - oa + na;
		} else
			slot = t;
	} else if (newAnchor != 0 && neuVt.methods.size() == 2) {
		const int na = vtableSlot(neuVt, newAnchor);
		if (na < 0)
			return std::nullopt;
		slot = na == 0 ? 1 : 0;
	}
	if (slot < 0 || slot >= static_cast<int>(neuVt.methods.size()))
		return std::nullopt;
	return neuVt.methods[static_cast<size_t>(slot)];
}

std::optional<Vtable> pickVtable(const std::vector<Vtable>& vts, const std::vector<uint64_t>& anchors) {
	if (vts.empty())
		return std::nullopt;
	if (vts.size() == 1)
		return vts[0];
	int best = -1;
	int second = -1;
	int bestI = -1;
	for (int i = 0; i < static_cast<int>(vts.size()); i++) {
		int hit = 0;
		for (uint64_t va : anchors) {
			if (vtableSlot(vts[static_cast<size_t>(i)], va) >= 0)
				hit++;
		}
		if (hit > best) {
			second = best;
			best = hit;
			bestI = i;
		} else if (hit > second)
			second = hit;
	}
	if (bestI < 0 || best == 0 || best == second)
		return std::nullopt;
	return vts[static_cast<size_t>(bestI)];
}

std::optional<uint64_t> huntClassMethod(const Binary& neu, const Binary* origin, std::string_view key,
	uint64_t oldTargetVa, const std::vector<uint64_t>& newAnchors, const std::vector<uint64_t>& oldAnchors,
	const std::vector<uint64_t>& takenVas, bool allowMany) {
	std::optional<Vtable> oldVt;
	if (origin && oldTargetVa != 0) {
		oldVt = pickVtable(findVtables(*origin, oldTargetVa), oldAnchors);
		if (!oldVt && oldAnchors.empty()) {
			auto ov = findVtables(*origin, oldTargetVa);
			if (ov.size() == 1)
				oldVt = ov[0];
		}
	}
	std::optional<Vtable> neuVt;
	for (uint64_t a : newAnchors) {
		neuVt = pickVtable(findVtables(neu, a), newAnchors);
		if (neuVt)
			break;
	}
	if (!neuVt)
		neuVt = findClassVtable(neu, key, allowMany);
	if (!neuVt)
		return std::nullopt;
	const uint64_t newAnchor = newAnchors.empty() ? 0 : newAnchors[0];
	const uint64_t oldAnchor = oldAnchors.empty() ? 0 : oldAnchors[0];
	auto va = mapVtableTarget(oldVt ? &*oldVt : nullptr, oldTargetVa, oldAnchor, *neuVt, newAnchor);
	if (!va || !neu.isExecVa(*va))
		return std::nullopt;
	if (contains(takenVas, *va))
		return std::nullopt;
	return va;
}

}
