#include "harness.hpp"
#include "bytescanner/func.hpp"
#include "bytescanner/relocate.hpp"
#include "bytescanner/siggen.hpp"
#include "x64bin.hpp"

#include <cstring>
#include <span>

using namespace bscan;
using namespace tfix;

namespace {

const char* kFooRtti = ".?AVFoo@@";
const char* kPeer = "16LocalNetworkPeer";

SymbolRow peerSend(uint64_t addr, std::string sig) {
	return fileRow("_ZN16LocalNetworkPeer10sendPacketEv", addr, std::move(sig));
}

SymbolRow peerRecv(uint64_t addr, std::string sig) {
	return fileRow("_ZN16LocalNetworkPeer14_receivePacketEv", addr, std::move(sig));
}

}

TEST(Func, ClassifyStartMid) {
	auto old = cc(256);
	const uint8_t real[] = {0x55, 0x48, 0x89, 0xE5, 0xE8, 0x11, 0x22, 0x33, 0x44, 0x48, 0x89, 0xC3, 0xC3};
	std::memcpy(old.data() + 32, real, sizeof(real));
	Binary ob = loadX64(old);
	FuncMap map;
	map.build(ob);
	auto at = ob.resolve(32, AddressKind::File);
	REQUIRE(at.has_value());
	CHECK(map.classify(ob, *at).kind == SiteKind::FuncStart);
	auto midA = ob.resolve(36, AddressKind::File);
	REQUIRE(midA.has_value());
	SiteInfo mid = map.classify(ob, *midA);
	CHECK(mid.kind == SiteKind::MidFunc);
	CHECK(mid.hasParent);
	CHECK_EQ(mid.parentFile, 32ull);
}

TEST(Func, OutOfRange) {
	Binary ob = loadX64(cc(256));
	auto miss = fileRow("gone", 0xFFFFFF);
	auto bad = generateSigs(ob, {miss}, genAll());
	REQUIRE_EQ(bad.size(), size_t{1});
	CHECK_EQ(bad[0].status, std::string("out_of_range"));
	CHECK_EQ(bad[0].row.siteKind, std::string("out_of_range"));
}

TEST(Func, MidFuncSig) {
	auto old = cc(256);
	const uint8_t real[] = {0x55, 0x48, 0x89, 0xE5, 0xE8, 0x11, 0x22, 0x33, 0x44, 0x48, 0x89, 0xC3, 0xC3};
	std::memcpy(old.data() + 32, real, sizeof(real));
	Binary ob = loadX64(old);
	auto midRow = fileRow("mid", 36);
	auto genMid = generateSigs(ob, {midRow}, genAll());
	REQUIRE_EQ(genMid.size(), size_t{1});
	CHECK_EQ(genMid[0].row.siteKind, std::string("mid_func"));
	CHECK(!genMid[0].row.parent.empty());
	CHECK_EQ(genMid[0].row.callCount, 1u);
}

TEST(Hunt, AmbiguousThenResolve) {
	auto old = cc(256);
	const uint8_t real[] = {0x55, 0x48, 0x89, 0xE5, 0xE8, 0x11, 0x22, 0x33, 0x44, 0x48, 0x89, 0xC3, 0xC3};
	const uint8_t fake[] = {0x55, 0x48, 0x89, 0xE5, 0x90, 0x90, 0x90, 0x90, 0xC3};
	std::memcpy(old.data() + 32, real, sizeof(real));
	Binary ob = loadX64(old);
	auto neu = cc(256);
	std::memcpy(neu.data() + 32, real, sizeof(real));
	std::memcpy(neu.data() + 128, fake, sizeof(fake));
	Binary nb = loadX64(neu);
	auto sig = fileRow("fn", 32, "55 48 89 E5");
	FindOptions fo = hunt(nullptr);
	auto amb = relocateSigs(nb, {sig}, fo);
	REQUIRE_EQ(amb.size(), size_t{1});
	CHECK_EQ(amb[0].status, std::string("ambiguous"));
	CHECK(amb[0].hits >= 2);
	fo.resolveConflicts = true;
	fo.origin = &ob;
	auto rec = relocateSigs(nb, {sig}, fo);
	REQUIRE_EQ(rec.size(), size_t{1});
	CHECK_EQ(rec[0].status, std::string("resolved"));
	CHECK_EQ(rec[0].row.address, 32ull);
	Insn call = decodeInsn(Arch::X64, std::span<const uint8_t>(real + 4, 5));
	CHECK(call.cls == InsnClass::Call);
	CHECK(isPrelude(Arch::X64, std::span<const uint8_t>(real, sizeof(real))));
}

TEST(Hunt, FingerprintPicksFat) {
	auto old = cc(320);
	putCalls(old, 32, 4, 200);
	Binary ob = loadX64(old);
	FuncMap map;
	map.build(ob);
	Fingerprint ofp = makeFingerprint(ob, map, 32, 24);
	CHECK_EQ(ofp.callCount, 4u);
	CHECK_EQ(ofp.callUnique, 4u);
	auto neu = cc(320);
	putCalls(neu, 32, 1, 200);
	putCalls(neu, 96, 4, 240);
	auto got = relocateSigs(loadX64(neu), {fileRow("fat", 32, "55 48 89 E5")}, hunt(&ob));
	REQUIRE_EQ(got.size(), size_t{1});
	CHECK_EQ(got[0].status, std::string("resolved"));
	CHECK_EQ(got[0].row.address, 96ull);
}

TEST(Hunt, StubMismatch) {
	auto old = cc(320);
	putCalls(old, 32, 4, 200);
	Binary ob = loadX64(old);
	auto stub = cc(160);
	putProlog(stub, 32);
	stub[36] = 0xC3;
	auto miss = relocateSigs(loadX64(stub), {fileRow("fat", 32, "55 48 89 E5")}, hunt(&ob));
	REQUIRE_EQ(miss.size(), size_t{1});
	CHECK_EQ(miss[0].status, std::string("mismatch"));
}

TEST(Hunt, CalleeCountClose) {
	auto old = cc(320);
	putCalls(old, 32, 4, 200);
	Binary ob = loadX64(old);
	auto close = cc(320);
	putCalls(close, 32, 5, 200);
	auto ok = relocateSigs(loadX64(close), {fileRow("fat", 32, "55 48 89 E5 E8")}, hunt(&ob));
	REQUIRE_EQ(ok.size(), size_t{1});
	CHECK_EQ(ok[0].status, std::string("matched"));
	CHECK(ok[0].row.note.find("close") != std::string::npos);
}

TEST(Hunt, TypeInfo) {
	auto ti = cc(320);
	putProlog(ti, 32);
	putLea(ti, 36, 200);
	ti[43] = 0xC3;
	putCstr(ti, 200, kFooRtti);
	Binary tib = loadX64(ti);
	FuncMap tim;
	tim.build(tib);
	CHECK_EQ(makeFingerprint(tib, tim, 32, 24).typeInfo, std::string(kFooRtti));
	auto tnew = cc(320);
	putProlog(tnew, 32);
	putLea(tnew, 36, 220);
	tnew[43] = 0xC3;
	putCstr(tnew, 220, "hello_world");
	putProlog(tnew, 64);
	putLea(tnew, 68, 200);
	tnew[75] = 0xC3;
	putCstr(tnew, 200, kFooRtti);
	auto tiHit = relocateSigs(loadX64(tnew), {fileRow("meth", 32, "55 48 89 E5")}, hunt(&tib));
	REQUIRE_EQ(tiHit.size(), size_t{1});
	CHECK_EQ(tiHit[0].status, std::string("resolved"));
	CHECK_EQ(tiHit[0].row.address, 64ull);
}

TEST(Hunt, NamedCalleeGraph) {
	auto gimg = cc(256);
	putProlog(gimg, 32);
	putCall(gimg, 36, 64);
	gimg[41] = 0xC3;
	putProlog(gimg, 64);
	gimg[68] = 0xC3;
	putProlog(gimg, 96);
	putCall(gimg, 100, 180);
	gimg[105] = 0xC3;
	Binary gb = loadX64(gimg);
	auto graph = relocateSigs(gb, {fileRow("b", 64, "55 48 89 E5 C3"), fileRow("a", 32, "55 48 89 E5 E8")},
		hunt(&gb));
	REQUIRE_EQ(graph.size(), size_t{2});
	CHECK_EQ(graph[0].status, std::string("matched"));
	CHECK_EQ(graph[1].status, std::string("resolved"));
	CHECK_EQ(graph[1].row.address, 32ull);
	auto js = formatJson(graph, summarize(graph), false);
	CHECK(js.find("\"name\": \"b\"") != std::string::npos);
	CHECK(js.find("\"calls\": 1") != std::string::npos);
	CHECK(js.find("\"name\": \"a\"") != std::string::npos);
}

TEST(Hunt, FingerprintLocate) {
	auto oldFp = cc(320);
	putCalls(oldFp, 32, 4, 200);
	Binary ob2 = loadX64(oldFp);
	auto newFp = cc(320);
	putCalls(newFp, 32, 1, 200);
	putCalls(newFp, 96, 4, 240);
	auto located = relocateSigs(loadX64(newFp), {fileRow("fat", 32, "DE AD BE EF")}, hunt(&ob2));
	REQUIRE_EQ(located.size(), size_t{1});
	CHECK_EQ(located[0].status, std::string("resolved"));
	CHECK_EQ(located[0].row.address, 96ull);
	CHECK(located[0].row.note.find("fingerprint") != std::string::npos);
}

TEST(Hunt, LocateByTypeInfoPtr) {
	auto ptrs = cc(256);
	putProlog(ptrs, 32);
	ptrs[36] = 0x48;
	ptrs[37] = 0xB8;
	const uint64_t strVa = 200;
	std::memcpy(ptrs.data() + 38, &strVa, 8);
	ptrs[46] = 0xC3;
	putCstr(ptrs, 200, kFooRtti);
	Binary pb = loadX64(ptrs);
	FuncMap pm;
	pm.build(pb);
	auto foundTi = locateByTypeInfo(pb, pm, kFooRtti, false);
	REQUIRE(foundTi.has_value());
	CHECK_EQ(*foundTi, 32ull);
}

TEST(Hunt, VtableSlotHint) {
	auto vt = zeros(256);
	putProlog(vt, 32);
	vt[36] = 0xC3;
	putCstr(vt, 80, kFooRtti);
	put64(vt, 96, 0);
	put64(vt, 104, 80);
	put64(vt, 112, 96);
	put64(vt, 120, 32);
	put64(vt, 128, 32);
	put64(vt, 136, 32);
	Binary vb = loadX64(vt);
	splitExecData(vb, 80);
	FuncMap vm;
	vm.build(vb);
	Fingerprint vfp = makeFingerprint(vb, vm, 136, 8);
	CHECK_EQ(vfp.vtableSlot, 2);
	CHECK_EQ(vfp.typeInfo, std::string(kFooRtti));
	Fingerprint shifted = vfp;
	shifted.vtableSlot = 3;
	CHECK(scoreFingerprint(vfp, shifted) >= 4);
}

TEST(Hunt, ClassKey) {
	CHECK_EQ(classKey("_ZN16LocalNetworkPeer10sendPacketEv"), std::string("_ZN16LocalNetworkPeer"));
	CHECK_EQ(classKey("_ZN16LocalNetworkPeer14_receivePacketEv"), std::string("_ZN16LocalNetworkPeer"));
	CHECK_EQ(classKey("_ZNK16LocalNetworkPeer3fooEv"), std::string("_ZN16LocalNetworkPeer"));
	CHECK_EQ(classKey("?sendPacket@LocalNetworkPeer@@UEAAXXZ"), std::string("LocalNetworkPeer"));
	CHECK(classKey("MinecraftGame::update").empty());
}

TEST(Hunt, ShrinkDoesNotCommitUniquePrefix) {
	auto shOld = cc(256);
	putProlog(shOld, 32);
	shOld[36] = 0x90;
	shOld[37] = 0x90;
	shOld[38] = 0x90;
	shOld[39] = 0xC3;
	Binary shOb = loadX64(shOld);
	auto shNew = cc(256);
	putProlog(shNew, 32);
	shNew[36] = 0x90;
	shNew[37] = 0xC3;
	auto shHit = relocateSigs(loadX64(shNew), {fileRow("shrunk", 32, "55 48 89 E5 90 90 90 C3")}, hunt(&shOb));
	REQUIRE_EQ(shHit.size(), size_t{1});
	CHECK_EQ(shHit[0].status, std::string("resolved"));
	CHECK_EQ(shHit[0].row.address, 32ull);
	CHECK(shHit[0].row.note.find("sig shrink") == std::string::npos);
	CHECK(shHit[0].row.note.find("fingerprint") != std::string::npos);
}

TEST(Hunt, FuzzRejectsUniqueStub) {
	auto fatOld = cc(320);
	putCalls(fatOld, 32, 4, 200);
	Binary fatOb = loadX64(fatOld);
	auto stubNew = cc(160);
	putProlog(stubNew, 32);
	stubNew[36] = 0xC3;
	auto fatRow = fileRow("fat", 32, "55 48 89 E5 E8 11 22 33 44 48 89 C3 C3");
	auto fatMiss = relocateSigs(loadX64(stubNew), {fatRow}, hunt(&fatOb));
	REQUIRE_EQ(fatMiss.size(), size_t{1});
	CHECK_NE(fatMiss[0].status, std::string("matched"));
	CHECK_NE(fatMiss[0].status, std::string("resolved"));
	auto fatFuzzMiss = relocateSigs(loadX64(stubNew), {fatRow}, hunt(&fatOb, true));
	REQUIRE_EQ(fatFuzzMiss.size(), size_t{1});
	CHECK_NE(fatFuzzMiss[0].status, std::string("matched"));
	CHECK_NE(fatFuzzMiss[0].status, std::string("resolved"));
}

TEST(Hunt, FuzzShrinkPicksFat) {
	auto fatOld = cc(320);
	putCalls(fatOld, 32, 4, 200);
	Binary fatOb = loadX64(fatOld);
	auto mixNew = cc(256);
	putCalls(mixNew, 32, 4, 200);
	putProlog(mixNew, 96);
	mixNew[100] = 0xC3;
	auto fatRow = fileRow("fat", 32, "55 48 89 E5 E8 11 22 33 44 48 89 C3 C3");
	auto fuzzHit = relocateSigs(loadX64(mixNew), {fatRow}, hunt(&fatOb, true));
	REQUIRE_EQ(fuzzHit.size(), size_t{1});
	CHECK_EQ(fuzzHit[0].status, std::string("resolved"));
	CHECK_EQ(fuzzHit[0].row.address, 32ull);
	CHECK(fuzzHit[0].row.note.find("fuzz shrink") != std::string::npos);
}

TEST(Hunt, VtableSibling) {
	auto vtOld = zeros(320);
	putTagged(vtOld, 32, 1);
	putTagged(vtOld, 48, 2);
	putCstr(vtOld, 128, kPeer);
	put64(vtOld, 160, 0);
	put64(vtOld, 168, 128);
	put64(vtOld, 192, 0);
	put64(vtOld, 200, 160);
	put64(vtOld, 208, 32);
	put64(vtOld, 216, 48);
	Binary vtOb = loadX64(vtOld);
	splitExecData(vtOb, 128);
	auto vtNew = zeros(320);
	putTagged(vtNew, 32, 1);
	putTagged(vtNew, 80, 99);
	putCstr(vtNew, 128, kPeer);
	put64(vtNew, 160, 0);
	put64(vtNew, 168, 128);
	put64(vtNew, 192, 0);
	put64(vtNew, 200, 160);
	put64(vtNew, 208, 32);
	put64(vtNew, 216, 80);
	Binary vtNb = loadX64(vtNew);
	splitExecData(vtNb, 128);
	auto sib = relocateSigs(vtNb, {peerSend(32, "55 48 89 E5 B8 01"), peerRecv(48, "55 48 89 E5 B8 02")},
		hunt(&vtOb));
	REQUIRE_EQ(sib.size(), size_t{2});
	CHECK_EQ(sib[0].status, std::string("matched"));
	CHECK_EQ(sib[0].row.address, 32ull);
	CHECK_EQ(sib[1].status, std::string("resolved"));
	CHECK_EQ(sib[1].row.address, 80ull);
	CHECK(sib[1].row.note.find("vtable sibling") != std::string::npos);
}

TEST(Hunt, VtableRankShift) {
	auto vtShiftOld = zeros(320);
	putTagged(vtShiftOld, 32, 1);
	putCalls(vtShiftOld, 48, 2, 200);
	putCstr(vtShiftOld, 128, kPeer);
	put64(vtShiftOld, 160, 0);
	put64(vtShiftOld, 168, 128);
	put64(vtShiftOld, 192, 0);
	put64(vtShiftOld, 200, 160);
	put64(vtShiftOld, 208, 32);
	put64(vtShiftOld, 216, 48);
	Binary vtShiftOb = loadX64(vtShiftOld);
	splitExecData(vtShiftOb, 128);
	auto vtShiftNew = zeros(320);
	putTagged(vtShiftNew, 32, 1);
	putTagged(vtShiftNew, 64, 7);
	putCalls(vtShiftNew, 80, 2, 200);
	putCalls(vtShiftNew, 96, 2, 200);
	putCstr(vtShiftNew, 128, kPeer);
	put64(vtShiftNew, 160, 0);
	put64(vtShiftNew, 168, 128);
	put64(vtShiftNew, 192, 0);
	put64(vtShiftNew, 200, 160);
	put64(vtShiftNew, 208, 32);
	put64(vtShiftNew, 216, 64);
	put64(vtShiftNew, 224, 80);
	Binary vtShiftNb = loadX64(vtShiftNew);
	splitExecData(vtShiftNb, 128);
	FindOptions shiftFo = hunt(&vtShiftOb);
	shiftFo.resolveInsns = 0;
	auto shiftHit = relocateSigs(vtShiftNb,
		{peerSend(32, "55 48 89 E5 B8 01"), peerRecv(48, "DE AD BE EF 11")}, shiftFo);
	REQUIRE_EQ(shiftHit.size(), size_t{2});
	CHECK_EQ(shiftHit[0].status, std::string("matched"));
	CHECK_EQ(shiftHit[0].row.address, 32ull);
	CHECK_EQ(shiftHit[1].status, std::string("resolved"));
	CHECK_EQ(shiftHit[1].row.address, 80ull);
	CHECK(shiftHit[1].row.note.find("vtable") != std::string::npos);
}

TEST(Hunt, ClassCluster) {
	auto vtNew = zeros(320);
	putTagged(vtNew, 32, 1);
	putTagged(vtNew, 80, 99);
	putCstr(vtNew, 128, kPeer);
	put64(vtNew, 160, 0);
	put64(vtNew, 168, 128);
	put64(vtNew, 192, 0);
	put64(vtNew, 200, 160);
	put64(vtNew, 208, 32);
	put64(vtNew, 216, 80);
	Binary vtNb = loadX64(vtNew);
	splitExecData(vtNb, 128);
	auto vtOld = zeros(320);
	putTagged(vtOld, 32, 1);
	putTagged(vtOld, 48, 2);
	putCstr(vtOld, 128, kPeer);
	put64(vtOld, 160, 0);
	put64(vtOld, 168, 128);
	put64(vtOld, 192, 0);
	put64(vtOld, 200, 160);
	put64(vtOld, 208, 32);
	put64(vtOld, 216, 48);
	Binary vtOb = loadX64(vtOld);
	splitExecData(vtOb, 128);
	auto cluster = relocateSigs(vtNb, {peerSend(32, "DE AD BE EF 00"), peerRecv(48, "DE AD BE EF 11")},
		hunt(&vtOb));
	REQUIRE_EQ(cluster.size(), size_t{2});
	CHECK_EQ(cluster[0].status, std::string("resolved"));
	CHECK_EQ(cluster[1].status, std::string("resolved"));
	CHECK_EQ(cluster[0].row.address, 32ull);
	CHECK_EQ(cluster[1].row.address, 80ull);
	CHECK(cluster[0].row.note.find("class cluster") != std::string::npos
		|| cluster[1].row.note.find("class cluster") != std::string::npos);
}

TEST(Hunt, ResolvedAsAnchor) {
	auto vtRes = zeros(320);
	putTagged(vtRes, 32, 1);
	putTagged(vtRes, 80, 99);
	vtRes[48] = 0x55;
	vtRes[49] = 0x48;
	vtRes[50] = 0x89;
	vtRes[51] = 0xE5;
	vtRes[52] = 0xB8;
	vtRes[53] = 0x01;
	vtRes[54] = 0;
	vtRes[55] = 0;
	vtRes[56] = 0;
	vtRes[57] = 0xE8;
	vtRes[58] = 0;
	vtRes[59] = 0;
	vtRes[60] = 0;
	vtRes[61] = 0;
	vtRes[62] = 0xC3;
	putCstr(vtRes, 128, kPeer);
	putCstr(vtRes, 240, kPeer);
	put64(vtRes, 160, 0);
	put64(vtRes, 168, 128);
	put64(vtRes, 192, 0);
	put64(vtRes, 200, 160);
	put64(vtRes, 208, 32);
	put64(vtRes, 216, 80);
	Binary vtRb = loadX64(vtRes);
	splitExecData(vtRb, 128);
	auto vtOld = zeros(320);
	putTagged(vtOld, 32, 1);
	putTagged(vtOld, 48, 2);
	putCstr(vtOld, 128, kPeer);
	put64(vtOld, 160, 0);
	put64(vtOld, 168, 128);
	put64(vtOld, 192, 0);
	put64(vtOld, 200, 160);
	put64(vtOld, 208, 32);
	put64(vtOld, 216, 48);
	Binary vtOb = loadX64(vtOld);
	splitExecData(vtOb, 128);
	auto fromRes = relocateSigs(vtRb, {peerSend(32, "55 48 89 E5 B8 01"), peerRecv(48, "DE AD BE EF 11")},
		hunt(&vtOb));
	REQUIRE_EQ(fromRes.size(), size_t{2});
	CHECK_EQ(fromRes[0].status, std::string("resolved"));
	CHECK_EQ(fromRes[0].row.address, 32ull);
	CHECK_EQ(fromRes[0].hits, size_t{2});
	CHECK_EQ(fromRes[1].status, std::string("resolved"));
	CHECK_EQ(fromRes[1].row.address, 80ull);
	CHECK(fromRes[1].row.note.find("vtable sibling") != std::string::npos);
}

TEST(Hunt, FpGateRejectsStub) {
	auto vtBad = cc(320);
	putTagged(vtBad, 32, 1);
	putTagged(vtBad, 64, 3);
	vtBad[80] = 0x31;
	vtBad[81] = 0xC0;
	vtBad[82] = 0xC3;
	putCstr(vtBad, 128, kPeer);
	put64(vtBad, 160, 0);
	put64(vtBad, 168, 128);
	put64(vtBad, 192, 0);
	put64(vtBad, 200, 160);
	put64(vtBad, 208, 32);
	put64(vtBad, 216, 80);
	Binary vtBb = loadX64(vtBad);
	splitExecData(vtBb, 128);
	auto vtOld = zeros(320);
	putTagged(vtOld, 32, 1);
	putTagged(vtOld, 48, 2);
	putCstr(vtOld, 128, kPeer);
	put64(vtOld, 160, 0);
	put64(vtOld, 168, 128);
	put64(vtOld, 192, 0);
	put64(vtOld, 200, 160);
	put64(vtOld, 208, 32);
	put64(vtOld, 216, 48);
	Binary vtOb = loadX64(vtOld);
	splitExecData(vtOb, 128);
	auto gated = relocateSigs(vtBb, {peerSend(32, "55 48 89 E5 B8 01"), peerRecv(48, "DE AD BE EF 11")},
		hunt(&vtOb));
	REQUIRE_EQ(gated.size(), size_t{2});
	CHECK_EQ(gated[0].status, std::string("matched"));
	CHECK_EQ(gated[0].row.address, 32ull);
	CHECK_NE(gated[1].status, std::string("matched"));
	CHECK_NE(gated[1].status, std::string("resolved"));
	CHECK(!gated[1].row.hasAddress);
}

TEST(Hunt, AllowManyWithoutFuzz) {
	auto vtRes = zeros(320);
	putTagged(vtRes, 32, 1);
	putTagged(vtRes, 80, 99);
	vtRes[48] = 0x55;
	vtRes[49] = 0x48;
	vtRes[50] = 0x89;
	vtRes[51] = 0xE5;
	vtRes[52] = 0xB8;
	vtRes[53] = 0x01;
	vtRes[54] = 0;
	vtRes[55] = 0;
	vtRes[56] = 0;
	vtRes[57] = 0xE8;
	vtRes[58] = 0;
	vtRes[59] = 0;
	vtRes[60] = 0;
	vtRes[61] = 0;
	vtRes[62] = 0xC3;
	putCstr(vtRes, 128, kPeer);
	putCstr(vtRes, 240, kPeer);
	put64(vtRes, 160, 0);
	put64(vtRes, 168, 128);
	put64(vtRes, 192, 0);
	put64(vtRes, 200, 160);
	put64(vtRes, 208, 32);
	put64(vtRes, 216, 80);
	Binary vtRb = loadX64(vtRes);
	splitExecData(vtRb, 128);
	auto vtOld = zeros(320);
	putTagged(vtOld, 32, 1);
	putTagged(vtOld, 48, 2);
	putCstr(vtOld, 128, kPeer);
	put64(vtOld, 160, 0);
	put64(vtOld, 168, 128);
	put64(vtOld, 192, 0);
	put64(vtOld, 200, 160);
	put64(vtOld, 208, 32);
	put64(vtOld, 216, 48);
	Binary vtOb = loadX64(vtOld);
	splitExecData(vtOb, 128);
	auto fuzzCluster = relocateSigs(vtRb, {peerSend(32, "DE AD BE EF 00"), peerRecv(48, "DE AD BE EF 11")},
		hunt(&vtOb, false));
	REQUIRE_EQ(fuzzCluster.size(), size_t{2});
	CHECK_EQ(fuzzCluster[0].status, std::string("resolved"));
	CHECK_EQ(fuzzCluster[1].status, std::string("resolved"));
	CHECK_EQ(fuzzCluster[0].row.address, 32ull);
	CHECK_EQ(fuzzCluster[1].row.address, 80ull);
}

TEST(Hunt, StringXref) {
	auto sxOld = cc(320);
	putProlog(sxOld, 32);
	putLea(sxOld, 36, 200);
	const uint64_t rareVa = 200;
	std::memcpy(sxOld.data() + 44, &rareVa, 8);
	sxOld[52] = 0xC3;
	putCstr(sxOld, 200, "rare_tag_zz");
	Binary sxOb = loadX64(sxOld);
	auto sxNew = cc(320);
	putProlog(sxNew, 32);
	sxNew[36] = 0xC3;
	putProlog(sxNew, 64);
	putLea(sxNew, 68, 200);
	std::memcpy(sxNew.data() + 76, &rareVa, 8);
	sxNew[84] = 0xC3;
	putCstr(sxNew, 200, "rare_tag_zz");
	auto sxHit = relocateSigs(loadX64(sxNew), {fileRow("rarefn", 32, "DE AD BE EF 00")}, hunt(&sxOb));
	REQUIRE_EQ(sxHit.size(), size_t{1});
	CHECK_EQ(sxHit[0].status, std::string("resolved"));
	CHECK_EQ(sxHit[0].row.address, 64ull);
	CHECK(sxHit[0].row.note.find("string xref") != std::string::npos);
}

TEST(Hunt, ParentDelta) {
	auto pdOld = cc(160);
	putTagged(pdOld, 32, 1);
	pdOld[42] = 0x90;
	pdOld[43] = 0x90;
	pdOld[44] = 0x90;
	pdOld[45] = 0x90;
	pdOld[46] = 0x90;
	pdOld[47] = 0x90;
	pdOld[48] = 0x90;
	pdOld[49] = 0xC3;
	Binary pdOb = loadX64(pdOld);
	auto pdNew = cc(160);
	putTagged(pdNew, 80, 1);
	pdNew[90] = 0x90;
	pdNew[91] = 0x90;
	pdNew[92] = 0x90;
	pdNew[93] = 0x90;
	pdNew[94] = 0x90;
	pdNew[95] = 0x90;
	pdNew[96] = 0x90;
	pdNew[97] = 0xC3;
	auto pdFn = fileRow("_ZN3Foo3barEv", 32, "55 48 89 E5 B8 01");
	auto pdPtr = fileRow("_ZN3Foo3barEv_ptr", 48, "DE AD BE EF");
	pdPtr.group = "Pointers";
	auto pdHit = relocateSigs(loadX64(pdNew), {pdFn, pdPtr}, hunt(&pdOb));
	REQUIRE_EQ(pdHit.size(), size_t{2});
	CHECK_EQ(pdHit[0].status, std::string("matched"));
	CHECK_EQ(pdHit[0].row.address, 80ull);
	CHECK_EQ(pdHit[1].status, std::string("resolved"));
	CHECK_EQ(pdHit[1].row.address, 96ull);
	CHECK(pdHit[1].row.note.find("parent delta") != std::string::npos);
}

TEST(Hunt, Arm64ExactBeatsFrameDecoy) {
	auto aold = std::vector<uint8_t>(128, 0x1F);
	putU32(aold, 16, 0xD10043FF);
	putU32(aold, 20, 0x52800020);
	putU32(aold, 24, 0xD65F03C0);
	putU32(aold, 48, 0xD10043FF);
	putU32(aold, 52, 0x52800040);
	putU32(aold, 56, 0xD65F03C0);
	Binary aob = loadArm64(aold);
	auto arow = fileRow("exactfn", 16);
	auto agen = generateSigs(aob, {arow}, genAll(8, 32));
	REQUIRE_EQ(agen.size(), size_t{1});
	auto anew = std::vector<uint8_t>(128, 0x1F);
	putU32(anew, 16, 0xD10043FF);
	putU32(anew, 20, 0x52800020);
	putU32(anew, 24, 0xD65F03C0);
	putU32(anew, 48, 0xD10043FF);
	putU32(anew, 52, 0x52800040);
	putU32(anew, 56, 0xD65F03C0);
	putU32(anew, 80, 0xD10083FF);
	putU32(anew, 84, 0x52800020);
	putU32(anew, 88, 0xD65F03C0);
	SymbolRow asig = agen[0].row;
	asig.kind = AddressKind::File;
	auto ahit = relocateSigs(loadArm64(anew), {asig}, hunt(&aob));
	REQUIRE_EQ(ahit.size(), size_t{1});
	CHECK_EQ(ahit[0].status, std::string("matched"));
	CHECK_EQ(ahit[0].row.address, 16ull);
}
