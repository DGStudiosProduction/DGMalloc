// Stress test for DGMalloc's chunked large blocks (src/DGMalloc.cpp LargeAlloc / LargeFree / DGMalloc_WriteWatchRegions).
// Build: test\build_test.bat. Compiles the real DGMalloc.cpp with DGMALLOC_TEST (no exe checks, no GMalloc install).
#define DGMALLOC_TEST 1
#include "../src/DGMalloc.cpp"

#include <atomic>
#include <random>
#include <thread>
#include <vector>

namespace
{
    std::atomic<long long> g_Fail{ 0 }, g_Ops{ 0 }, g_Null{ 0 }, g_Size{ 0 }, g_Pattern{ 0 }, g_FreeFail{ 0 };

    // One word at every page start that has 8 bytes inside the block, and the block's last 8 bytes when they do not
    // overlap the last page word (an overlapping second write corrupted the first in the first version of this test).
    bool TailSeparate(size_t n) { return (n - 8) % 4096 >= 8 && (n - 8) / 4096 * 4096 + 8 <= n - 8; }
    void Fill(uint8_t* p, size_t n, uint64_t tag)
    {
        for (size_t i = 0; i + 8 <= n; i += 4096) memcpy(p + i, &tag, 8);   // touches every page
        if (TailSeparate(n)) memcpy(p + n - 8, &tag, 8);
    }
    bool Check(const uint8_t* p, size_t n, uint64_t tag)
    {
        for (size_t i = 0; i + 8 <= n; i += 4096) if (memcmp(p + i, &tag, 8) != 0) return false;
        return !TailSeparate(n) || memcmp(p + n - 8, &tag, 8) == 0;
    }

    void Worker(int id, int ops)
    {
        std::mt19937_64 rng(1234 + id);
        struct Blk { uint8_t* p; size_t n; uint64_t tag; };
        std::vector<Blk> live;
        for (int i = 0; i < ops; ++i)
        {
            const bool alloc = live.empty() || (rng() % 100) < 55;
            if (alloc && live.size() < 400)
            {
                const uint64_t r = rng() % 1000;
                size_t n = r < 900 ? 32769 + rng() % (2u << 20) : r < 995 ? (4u << 20) + rng() % (60u << 20) : (256u << 20) + rng() % (40u << 20);
                auto* p = static_cast<uint8_t*>(LargeAlloc(n));
                if (!p) { ++g_Null; continue; }   // out of memory: not a defect
                size_t got = 0;
                if (!LargeSize(p, got) || got < n) { ++g_Fail; ++g_Size; }
                const uint64_t tag = (static_cast<uint64_t>(id) << 48) ^ static_cast<uint64_t>(i) ^ reinterpret_cast<uint64_t>(p);
                Fill(p, n, tag);
                live.push_back({ p, n, tag });
            }
            else if (!live.empty())
            {
                const size_t k = rng() % live.size();
                if (!Check(live[k].p, live[k].n, live[k].tag)) { ++g_Fail; ++g_Pattern; }   // overlapping blocks would have overwritten it
                if (!LargeFree(live[k].p)) { ++g_Fail; ++g_FreeFail; }
                live[k] = live.back();
                live.pop_back();
            }
            ++g_Ops;
        }
        for (auto& b : live) { if (!Check(b.p, b.n, b.tag)) { ++g_Fail; ++g_Pattern; } LargeFree(b.p); }
    }
}

int main()
{
    TestInitLarge();
    std::vector<std::thread> ts;
    for (int t = 0; t < 4; ++t) ts.emplace_back(Worker, t, 20000);
    for (auto& t : ts) t.join();

    // regions and the cost of reading them
    std::vector<DGMallocRegion> regs(4096);
    unsigned long long gen = 0;
    size_t n = DGMalloc_WriteWatchRegions(regs.data(), regs.size(), &gen);
    LARGE_INTEGER f, a, b;
    QueryPerformanceFrequency(&f);
    std::vector<ULONG_PTR> buf(1 << 16);
    QueryPerformanceCounter(&a);
    unsigned long long pages = 0, failed = 0;
    for (size_t i = 0; i < n && i < regs.size(); ++i)
    {
        ULONG_PTR count = buf.size();
        DWORD gran = 0;
        if (GetWriteWatch(WRITE_WATCH_FLAG_RESET, regs[i].base, static_cast<SIZE_T>(regs[i].size), reinterpret_cast<PVOID*>(buf.data()), &count, &gran) != 0) ++failed;
        else pages += count;
    }
    QueryPerformanceCounter(&b);
    const double ms = 1000.0 * static_cast<double>(b.QuadPart - a.QuadPart) / static_cast<double>(f.QuadPart);
    printf("null (out of memory) %lld, size %lld, pattern %lld, free %lld\n", g_Null.load(), g_Size.load(), g_Pattern.load(), g_FreeFail.load());
    printf("ops %lld, failures %lld, regions %zu (chunks %zu), dirty pages read %llu (%llu failed) in %.2f ms, free extents %zu\n",
           g_Ops.load(), g_Fail.load(), n, g_Chunks->size(), pages, failed, ms, g_FreeByAddr->size());
    // after every block is freed each chunk must be one free extent again
    const bool merged = g_FreeByAddr->size() == g_Chunks->size();
    printf("chunks fully merged back: %s, live blocks left: %zu\n", merged ? "yes" : "NO", g_Large->size());
    return (g_Fail.load() == 0 && merged && g_Large->empty()) ? 0 : 1;
}
