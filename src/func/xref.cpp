#include "bytescanner/func.hpp"
#include "internal.hpp"

namespace bscan {

std::optional<uint64_t> locateByTypeInfo(const Binary& bin, const FuncMap& map, std::string_view typeInfo,
	bool wantData) {
	return fp::locateByLiteral(bin, map, typeInfo, wantData, false, 1);
}

std::optional<uint64_t> locateByStringXref(const Binary& bin, const FuncMap& map, const Fingerprint& origin,
	bool wantData) {
	std::optional<uint64_t> pick;
	for (const auto& s : origin.strings) {
		if (!origin.typeInfo.empty() && s == origin.typeInfo)
			continue;
		auto hit = fp::locateByLiteral(bin, map, s, wantData, true, 8);
		if (!hit)
			continue;
		if (pick && *pick != *hit)
			return std::nullopt;
		pick = hit;
	}
	return pick;
}

}
