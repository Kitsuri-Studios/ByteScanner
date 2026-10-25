#include "bytescanner/mem.hpp"

#include "bytescanner/bytes.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <iostream>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <io.h>
#include <windows.h>
#include <psapi.h>
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#else
#include <fstream>
#include <unistd.h>
#include <sys/sysinfo.h>
#endif

namespace bscan {

uint64_t physAvail() {
#if defined(_WIN32)
	MEMORYSTATUSEX st{};
	st.dwLength = sizeof(st);
	if (!GlobalMemoryStatusEx(&st))
		return 0;
	return static_cast<uint64_t>(st.ullAvailPhys);
#else
	std::ifstream in("/proc/meminfo");
	std::string key;
	uint64_t kb = 0;
	while (in >> key) {
		if (key == "MemAvailable:") {
			in >> kb;
			return kb * 1024ull;
		}
		std::string rest;
		std::getline(in, rest);
	}
	struct sysinfo si {};
	if (sysinfo(&si) != 0)
		return 0;
	return static_cast<uint64_t>(si.freeram) * si.mem_unit;
#endif
}

uint64_t physTotal() {
#if defined(_WIN32)
	MEMORYSTATUSEX st{};
	st.dwLength = sizeof(st);
	if (!GlobalMemoryStatusEx(&st))
		return 0;
	return static_cast<uint64_t>(st.ullTotalPhys);
#else
	struct sysinfo si {};
	if (sysinfo(&si) != 0)
		return 0;
	return static_cast<uint64_t>(si.totalram) * si.mem_unit;
#endif
}

uint64_t rssBytes() {
#if defined(_WIN32)
	PROCESS_MEMORY_COUNTERS pmc{};
	if (!GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc)))
		return 0;
	return static_cast<uint64_t>(pmc.WorkingSetSize);
#else
	std::ifstream in("/proc/self/statm");
	uint64_t pages = 0;
	if (!(in >> pages))
		return 0;
	const long pg = sysconf(_SC_PAGESIZE);
	if (pg <= 0)
		return 0;
	return pages * static_cast<uint64_t>(pg);
#endif
}

uint64_t parseMemSize(std::string_view s, uint64_t avail) {
	while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
		s.remove_prefix(1);
	while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
		s.remove_suffix(1);
	if (s.empty() || s == "auto" || s == "default")
		return 0;
	if (!s.empty() && s.back() == '%') {
		const uint64_t pct = parseHexU64(s.substr(0, s.size() - 1));
		if (pct > 90)
			throw ScanError("mem percent max 90");
		if (avail == 0)
			return kDefaultMemCap;
		return avail / 100 * pct;
	}
	uint64_t mul = 1;
	if (s.size() >= 2) {
		const char a = static_cast<char>(std::tolower(static_cast<unsigned char>(s[s.size() - 2])));
		const char b = static_cast<char>(std::tolower(static_cast<unsigned char>(s.back())));
		if (b == 'b' && (a == 'k' || a == 'm' || a == 'g')) {
			if (a == 'k')
				mul = 1024ull;
			else if (a == 'm')
				mul = 1024ull * 1024ull;
			else
				mul = 1024ull * 1024ull * 1024ull;
			s.remove_suffix(2);
		}
	}
	if (mul == 1 && !s.empty()) {
		const char u = static_cast<char>(std::tolower(static_cast<unsigned char>(s.back())));
		if (u == 'k') {
			mul = 1024ull;
			s.remove_suffix(1);
		} else if (u == 'm') {
			mul = 1024ull * 1024ull;
			s.remove_suffix(1);
		} else if (u == 'g') {
			mul = 1024ull * 1024ull * 1024ull;
			s.remove_suffix(1);
		}
	}
	const uint64_t n = parseHexU64(s);
	if (n > UINT64_MAX / mul)
		throw ScanError("mem size overflow");
	return n * mul;
}

std::string formatMem(uint64_t n) {
	char buf[64];
	if (n >= 1024ull * 1024ull * 1024ull && n % (1024ull * 1024ull * 1024ull) == 0)
		std::snprintf(buf, sizeof(buf), "%lluG", static_cast<unsigned long long>(n / (1024ull * 1024ull * 1024ull)));
	else if (n >= 1024ull * 1024ull * 1024ull)
		std::snprintf(buf, sizeof(buf), "%.1fG", static_cast<double>(n) / (1024.0 * 1024.0 * 1024.0));
	else if (n >= 1024ull * 1024ull && n % (1024ull * 1024ull) == 0)
		std::snprintf(buf, sizeof(buf), "%lluM", static_cast<unsigned long long>(n / (1024ull * 1024ull)));
	else if (n >= 1024ull * 1024ull)
		std::snprintf(buf, sizeof(buf), "%.1fM", static_cast<double>(n) / (1024.0 * 1024.0));
	else if (n >= 1024ull)
		std::snprintf(buf, sizeof(buf), "%lluK", static_cast<unsigned long long>(n / 1024ull));
	else
		std::snprintf(buf, sizeof(buf), "%lluB", static_cast<unsigned long long>(n));
	return buf;
}

uint64_t pickBudget(uint64_t avail, uint64_t want) {
	uint64_t cap = want ? want : kDefaultMemCap;
	if (avail == 0)
		return cap;
	const uint64_t half = avail / 2;
	if (cap > half)
		cap = half;
	if (cap < kMinMemCap && half >= kMinMemCap)
		cap = kMinMemCap;
	const uint64_t floor = 16ull * 1024 * 1024;
	if (cap < floor)
		cap = std::min(half, floor);
	if (cap == 0)
		cap = floor;
	return cap;
}

MemBudget::MemBudget(uint64_t cap) : cap_(cap) {}

bool MemBudget::tryReserve(uint64_t n) {
	if (n == 0)
		return true;
	if (n > left())
		return false;
	used_ += n;
	return true;
}

void MemBudget::release(uint64_t n) {
	if (n > used_)
		used_ = 0;
	else
		used_ -= n;
}

bool streamIsTty(FILE* f) {
	if (!f)
		return false;
#if defined(_WIN32)
	return _isatty(_fileno(f)) != 0;
#else
	return isatty(fileno(f)) != 0;
#endif
}

void enableVt(FILE* f) {
#if defined(_WIN32)
	HANDLE h = INVALID_HANDLE_VALUE;
	if (f == stderr)
		h = GetStdHandle(STD_ERROR_HANDLE);
	else if (f == stdout)
		h = GetStdHandle(STD_OUTPUT_HANDLE);
	else
		h = reinterpret_cast<HANDLE>(_get_osfhandle(_fileno(f)));
	if (h == INVALID_HANDLE_VALUE || h == nullptr)
		return;
	DWORD mode = 0;
	if (!GetConsoleMode(h, &mode))
		return;
	SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#else
	(void)f;
#endif
}

bool wantColor(FILE* f) {
	if (std::getenv("NO_COLOR"))
		return false;
	if (std::getenv("FORCE_COLOR") || std::getenv("CLICOLOR_FORCE"))
		return true;
	return streamIsTty(f);
}

const char* Logger::paint(const char* code) const {
	return color ? code : "";
}

void Logger::finish() const {
	if (!spin_)
		return;
	spin_ = false;
	std::cerr << "\n";
}

void Logger::say(const char* tagCol, std::string_view msg) const {
	if (silent)
		return;
	finish();
	std::cerr << paint(tagCol) << "[bscan]" << paint("\033[0m") << " " << msg << paint("\033[2m")
		<< "  rss=" << formatMem(rssBytes()) << paint("\033[0m") << "\n";
	std::cerr.flush();
}

void Logger::info(std::string_view msg) const {
	say("\033[36m", msg);
}

void Logger::ok(std::string_view msg) const {
	say("\033[32m", msg);
}

void Logger::warn(std::string_view msg) const {
	say("\033[33m", msg);
}

void Logger::progress(size_t i, size_t n, std::string_view name) const {
	if (silent)
		return;
	std::string line = std::to_string(i) + "/" + std::to_string(n) + " " + std::string(name);
	if (!streamIsTty(stderr)) {
		info(line);
		return;
	}
	std::cerr << "\r" << paint("\033[36m") << "[bscan]" << paint("\033[0m") << " " << line
		<< paint("\033[2m") << "  rss=" << formatMem(rssBytes()) << paint("\033[0m") << "\033[K"
		<< std::flush;
	spin_ = true;
}

}
