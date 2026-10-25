#pragma once

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

inline int gFails = 0;
inline int gPass = 0;

struct TestFail {};

struct TestCase {
	const char* name = nullptr;
	void (*fn)() = nullptr;
};

inline std::vector<TestCase>& allTests() {
	static std::vector<TestCase> t;
	return t;
}

struct TestReg {
	TestReg(const char* name, void (*fn)()) { allTests().push_back({name, fn}); }
};

template<class T>
std::string toStr(const T& v) {
	using U = std::decay_t<T>;
	if constexpr (std::is_convertible_v<T, std::string_view> && !std::is_arithmetic_v<U>)
		return std::string(std::string_view(v));
	else if constexpr (std::is_enum_v<U>)
		return std::to_string(static_cast<long long>(v));
	else if constexpr (std::is_same_v<U, bool>)
		return v ? "true" : "false";
	else if constexpr (std::is_same_v<U, uint8_t> || std::is_same_v<U, int8_t> || std::is_same_v<U, char>)
		return std::to_string(static_cast<int>(v));
	else {
		std::ostringstream os;
		os << v;
		return os.str();
	}
}

inline bool check(bool cond, const char* expr, const char* file, int line) {
	if (cond) {
		gPass++;
		return true;
	}
	gFails++;
	std::fprintf(stderr, "FAIL %s:%d %s\n", file, line, expr);
	return false;
}

template<class A, class B>
bool checkEq(const A& a, const B& b, const char* ea, const char* eb, const char* file, int line) {
	if (a == b) {
		gPass++;
		return true;
	}
	gFails++;
	std::fprintf(stderr, "FAIL %s:%d %s == %s\n", file, line, ea, eb);
	std::fprintf(stderr, "  lhs %s\n  rhs %s\n", toStr(a).c_str(), toStr(b).c_str());
	return false;
}

#define CHECK(x) check(!!(x), #x, __FILE__, __LINE__)
#define CHECK_EQ(a, b) checkEq((a), (b), #a, #b, __FILE__, __LINE__)
#define CHECK_NE(a, b) check((a) != (b), #a " != " #b, __FILE__, __LINE__)
#define REQUIRE(x)                                                                                         \
	do {                                                                                                   \
		if (!check(!!(x), #x, __FILE__, __LINE__))                                                         \
			throw TestFail{};                                                                              \
	} while (0)
#define REQUIRE_EQ(a, b)                                                                                   \
	do {                                                                                                   \
		if (!checkEq((a), (b), #a, #b, __FILE__, __LINE__))                                                \
			throw TestFail{};                                                                              \
	} while (0)
#define CHECK_THROWS(expr)                                                                                 \
	do {                                                                                                   \
		try {                                                                                              \
			(void)(expr);                                                                                  \
			check(false, "expected throw " #expr, __FILE__, __LINE__);                                     \
		} catch (const TestFail&) {                                                                        \
			throw;                                                                                         \
		} catch (...) {                                                                                    \
			check(true, #expr, __FILE__, __LINE__);                                                        \
		}                                                                                                  \
	} while (0)

#define TEST(suite, name)                                                                                  \
	static void test_##suite##_##name();                                                                   \
	[[maybe_unused]] static const TestReg test_##suite##_##name##_reg{#suite "." #name,                    \
		&test_##suite##_##name};                                                                           \
	static void test_##suite##_##name()

inline int runTests() {
	auto& tests = allTests();
	std::sort(tests.begin(), tests.end(), [](const TestCase& a, const TestCase& b) {
		return std::string(a.name) < std::string(b.name);
	});
	std::printf("[==========] %zu tests\n", tests.size());
	int failedTests = 0;
	for (const TestCase& t : tests) {
		const int before = gFails;
		std::printf("[ RUN      ] %s\n", t.name);
		try {
			t.fn();
		} catch (const TestFail&) {
		}
		if (gFails > before) {
			std::printf("[  FAILED  ] %s\n", t.name);
			failedTests++;
		} else
			std::printf("[       OK ] %s\n", t.name);
	}
	std::printf("[==========] %d pass, %d fail, %d tests failed\n", gPass, gFails, failedTests);
	return gFails ? 1 : 0;
}
