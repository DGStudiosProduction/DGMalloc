#include <windows.h>
#include <cstdint>
#include <cstring>
#include <new>
#include <intrin.h>
#include <psapi.h>
#include <cstdarg>
#include <cstdio>
#include <cwchar>

#include "mimalloc.h"

#include <unordered_map>
#include <map>
#include <vector>

namespace
{
    constexpr DWORD     kExeTimeDateStamp = 0x65FF427D;
    constexpr DWORD     kExeSizeOfImage   = 0x04B54000;
    constexpr uintptr_t kRvaGMalloc       = 0x0470BBB8;
    constexpr uintptr_t kRvaGCreateMalloc = 0x01DA4F40;
    constexpr uintptr_t kRvaGMallocLoad   = 0x01DA4FFD;
    constexpr uint8_t   kGCreateMallocHead[] = {
        0x40, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x48, 0xC7, 0x44, 0x24, 0x20, 0xFE, 0xFF, 0xFF, 0xFF, 0x48,
        0x89, 0x5C, 0x24, 0x48, 0xB9, 0x08, 0x0E, 0x04, 0x00, 0xFF, 0x15, 0x69, 0xCA, 0x9B, 0x01, 0x48,
    };

    constexpr DWORD kExcOutOfMemory  = 0xE0D60001;
    constexpr DWORD kExcForeignBlock = 0xE0D60002;
    constexpr DWORD kExcHeapError    = 0xE0D60003;

#ifdef DGMALLOC_DIAGNOSTIC
    void HeapErrorHandler(int err, void*)
    {
        const ULONG_PTR args[1] = { static_cast<ULONG_PTR>(err) };
        RaiseException(kExcHeapError, EXCEPTION_NONCONTINUABLE, 1, args);
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    }
    constexpr wchar_t kDescriptiveName[] = L"DGMalloc (mimalloc 2.1.7, diagnostic)";
    constexpr char    kOnStatus[] = "on (diagnostic)";
#else
    constexpr wchar_t kDescriptiveName[] = L"DGMalloc (mimalloc 2.1.7)";
    constexpr char    kOnStatus[] = "on";
#endif
    constexpr uint32_t kMinAlign = 16;

    struct UWorld;
    struct FOutputDevice;
    struct FGenericMemoryStats;

    volatile LONG g_Installed = 0;
    volatile LONG g_ForeignFrees = 0;
    char          g_Status[96] = "not installed";

    inline size_t Round16(size_t n) { return (n + 15) & ~static_cast<size_t>(15); }

    [[noreturn]] __declspec(noinline) void Fatal(DWORD code, size_t size, uint32_t align, const void* p)
    {
        const ULONG_PTR args[3] = { static_cast<ULONG_PTR>(size), static_cast<ULONG_PTR>(align),
                                    reinterpret_cast<ULONG_PTR>(p) };
        RaiseException(code, EXCEPTION_NONCONTINUABLE, 3, args);
        __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    }

    constexpr uint64_t kLargeMin = 32768 + 1;
    constexpr uint32_t kLargeAlignMax = 64 * 1024;

    /// One reservation the engine side may ask about: base, size and the order it was made in (a region reserved after
    /// a consumer's last look is wholly new to it, even at an address reused since).
    struct Region { size_t size; unsigned long long gen; };
    volatile LONG64 g_RegionGen = 0;

    SRWLOCK g_LargeLock = SRWLOCK_INIT;
    std::unordered_map<void*, Region>* g_Large = nullptr;

    // mimalloc's own reservations (prim.c reports them); created before mimalloc reserves anything, so none is missed
    // after that - one made before it exists is simply unknown (callers treat unknown memory as written).
    SRWLOCK g_RegionLock = SRWLOCK_INIT;
    std::unordered_map<void*, Region>* g_Regions = nullptr;
    volatile LONG64 g_LargeBytes = 0;
    volatile LONG64 g_LargePeakBytes = 0;

    inline size_t RoundPage(uint64_t n) { return static_cast<size_t>((n + 4095) & ~static_cast<uint64_t>(4095)); }

    bool LargeSize(void* p, size_t& size)
    {
        if (!g_Large) return false;
        AcquireSRWLockShared(&g_LargeLock);
        auto it = g_Large->find(p);
        const bool found = it != g_Large->end();
        if (found) size = it->second.size;
        ReleaseSRWLockShared(&g_LargeLock);
        return found;
    }

    // ---- large blocks from write-watched chunks ------------------------------------------------------------------------
    // Blocks over 32 KB used to be one VirtualAlloc each (FMallocBinned does the same): with MEM_WRITE_WATCH that made
    // 63k regions, and reading them cost 14 us each (837 ms at a boot GC, 526). Now they are placed in 1 GiB chunks
    // reserved with MEM_WRITE_WATCH, in 64 KB units (the waste the VirtualAlloc granularity had anyway); the block's pages
    // are committed when it is handed out and decommitted when it is freed, so freed memory still goes back to the OS. A
    // block of 256 MB or more keeps its own reservation. The engine side then reads a dozen regions instead of 60k.
    constexpr size_t kChunkSize = size_t(1) << 30;
    constexpr size_t kUnit = 64 * 1024;
    constexpr size_t kOwnRegionMin = size_t(256) << 20;

    struct Chunk { uintptr_t base; unsigned long long gen; };
    SRWLOCK g_FreeLock = SRWLOCK_INIT;
    std::vector<Chunk>* g_Chunks = nullptr;
    std::map<uintptr_t, size_t>* g_FreeByAddr = nullptr;       // extent start -> length (bytes, whole units)
    std::multimap<size_t, uintptr_t>* g_FreeBySize = nullptr;  // length -> start (best fit)
    std::unordered_map<void*, size_t>* g_Extent = nullptr;     // chunk block -> its extent length (own regions: absent)

    size_t ChunkOf(uintptr_t a)
    {
        for (size_t i = 0; i < g_Chunks->size(); ++i)
            if (a >= (*g_Chunks)[i].base && a < (*g_Chunks)[i].base + kChunkSize) return i;
        return SIZE_MAX;
    }

    void AddFree(uintptr_t at, size_t len)
    {
        (*g_FreeByAddr)[at] = len;
        g_FreeBySize->emplace(len, at);
    }

    void RemoveFree(std::map<uintptr_t, size_t>::iterator it)
    {
        auto range = g_FreeBySize->equal_range(it->second);
        for (auto j = range.first; j != range.second; ++j)
            if (j->second == it->first) { g_FreeBySize->erase(j); break; }
        g_FreeByAddr->erase(it);
    }

    /// An extent of `len` bytes (whole units), or 0. g_FreeLock held.
    uintptr_t TakeExtent(size_t len)
    {
        auto best = g_FreeBySize->lower_bound(len);
        if (best == g_FreeBySize->end())
        {
            void* c = VirtualAlloc(nullptr, kChunkSize, MEM_RESERVE | MEM_WRITE_WATCH, PAGE_READWRITE);
            if (!c) return 0;
            const unsigned long long gen = static_cast<unsigned long long>(InterlockedIncrement64(&g_RegionGen));
            g_Chunks->push_back(Chunk{ reinterpret_cast<uintptr_t>(c), gen });
            AddFree(reinterpret_cast<uintptr_t>(c), kChunkSize);
            best = g_FreeBySize->lower_bound(len);
            if (best == g_FreeBySize->end()) return 0;
        }
        const uintptr_t at = best->second;
        const size_t have = best->first;
        RemoveFree(g_FreeByAddr->find(at));
        if (have > len) AddFree(at + len, have - len);
        return at;
    }

    /// Back into the free lists, merged with its neighbours inside the same chunk. g_FreeLock held.
    void GiveExtent(uintptr_t at, size_t len)
    {
        const size_t chunk = ChunkOf(at);
        auto next = g_FreeByAddr->lower_bound(at);
        if (next != g_FreeByAddr->end() && next->first == at + len && ChunkOf(next->first) == chunk)
        {
            len += next->second;
            RemoveFree(next);
        }
        auto prev = g_FreeByAddr->lower_bound(at);
        if (prev != g_FreeByAddr->begin())
        {
            --prev;
            if (prev->first + prev->second == at && ChunkOf(prev->first) == chunk)
            {
                at = prev->first;
                len += prev->second;
                RemoveFree(prev);
            }
        }
        AddFree(at, len);
    }

    void* LargeAlloc(uint64_t count)
    {
        const size_t size = RoundPage(count);
        void* p = nullptr;
        size_t extent = 0;
        if (size >= kOwnRegionMin)
        {
            p = VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE);
            if (!p) return nullptr;
        }
        else
        {
            extent = (size + kUnit - 1) & ~(kUnit - 1);
            AcquireSRWLockExclusive(&g_FreeLock);
            const uintptr_t at = TakeExtent(extent);
            ReleaseSRWLockExclusive(&g_FreeLock);
            if (!at) return nullptr;
            p = VirtualAlloc(reinterpret_cast<void*>(at), size, MEM_COMMIT, PAGE_READWRITE);
            if (!p)
            {
                AcquireSRWLockExclusive(&g_FreeLock);
                GiveExtent(at, extent);
                ReleaseSRWLockExclusive(&g_FreeLock);
                return nullptr;
            }
        }
        // gen 0 = a chunk block (its chunk is the region); an own reservation is a region of its own
        const unsigned long long gen = extent ? 0ull : static_cast<unsigned long long>(InterlockedIncrement64(&g_RegionGen));
        AcquireSRWLockExclusive(&g_LargeLock);
        (*g_Large)[p] = Region{ size, gen };
        if (extent) (*g_Extent)[p] = extent;
        ReleaseSRWLockExclusive(&g_LargeLock);
        const LONG64 now = InterlockedAdd64(&g_LargeBytes, static_cast<LONG64>(size));
        LONG64 peak = g_LargePeakBytes;
        while (now > peak && InterlockedCompareExchange64(&g_LargePeakBytes, now, peak) != peak) peak = g_LargePeakBytes;
        return p;
    }

    bool LargeFree(void* p)
    {
        if (!g_Large) return false;
        size_t size = 0, extent = 0;
        AcquireSRWLockExclusive(&g_LargeLock);
        auto it = g_Large->find(p);
        const bool found = it != g_Large->end();
        if (found)
        {
            size = it->second.size;
            g_Large->erase(it);
            auto e = g_Extent->find(p);
            if (e != g_Extent->end()) { extent = e->second; g_Extent->erase(e); }
        }
        ReleaseSRWLockExclusive(&g_LargeLock);
        if (!found) return false;
        if (!extent) VirtualFree(p, 0, MEM_RELEASE);
        else
        {
            VirtualFree(p, size, MEM_DECOMMIT);
            AcquireSRWLockExclusive(&g_FreeLock);
            GiveExtent(reinterpret_cast<uintptr_t>(p), extent);
            ReleaseSRWLockExclusive(&g_FreeLock);
        }
        InterlockedAdd64(&g_LargeBytes, -static_cast<LONG64>(size));
        return true;
    }

    void* DoMalloc(uint64_t count, uint32_t align)
    {
        void* p = nullptr;
        if (count >= kLargeMin && align <= kLargeAlignMax && g_Large) p = LargeAlloc(count);
        else p = align <= kMinAlign ? mi_malloc(Round16(count)) : mi_malloc_aligned(count, align);
        if (!p) Fatal(kExcOutOfMemory, count, align, nullptr);
        return p;
    }

    constexpr size_t   kQuarantineMax = 64;
    constexpr uint32_t kQuarantineLen = 8192;
    constexpr uint64_t kPattern = 0xD6F4EE5DD6F4EE5DULL;

    struct QEntry { void* p; void* from; };
    struct Quarantine { QEntry ring[kQuarantineLen]; uint32_t head; uint32_t count; };
    thread_local Quarantine* t_Quarantine = nullptr;

    volatile LONG64 g_Quarantined = 0;
    volatile LONG   g_FindingCount = 0;
    volatile LONG   g_CutCount = 0;

    struct Finding { void* block; void* from; uint64_t value; uint32_t offset; uint32_t size; };
    constexpr LONG kMaxFindings = 64;
    Finding g_Findings[kMaxFindings];
    volatile LONG g_FindingsWritten = 0;

    struct Cut { const void* block; const void* next; size_t blockSize; };
    constexpr LONG kMaxCuts = 32;
    Cut g_Cuts[kMaxCuts];
    volatile LONG g_CutsWritten = 0;

    inline void StampPattern(void* p, size_t usable)
    {
        auto* q = static_cast<uint64_t*>(p);
        q[0] = kPattern;
        if (usable >= 16) q[1] = kPattern;
    }

    void CheckAndRelease(const QEntry& e)
    {
        const size_t usable = mi_usable_size(e.p);
        const auto* q = static_cast<const uint64_t*>(e.p);
        const uint32_t words = usable >= 16 ? 2 : 1;
        for (uint32_t i = 0; i < words; ++i)
        {
            if (q[i] == kPattern) continue;
            InterlockedIncrement(&g_FindingCount);
            const LONG slot = InterlockedIncrement(&g_FindingsWritten) - 1;
            if (slot < kMaxFindings)
                g_Findings[slot] = Finding{ e.p, e.from, q[i], i * 8, static_cast<uint32_t>(usable) };
            else
                InterlockedDecrement(&g_FindingsWritten);
            break;
        }
        mi_free(e.p);
    }

    Quarantine* ThreadQuarantine()
    {
        if (!t_Quarantine) t_Quarantine = static_cast<Quarantine*>(mi_zalloc(sizeof(Quarantine)));
        return t_Quarantine;
    }

    void DoFree(void* p, void* from)
    {
        if (!p) return;
        if (LargeFree(p)) return;
        if (!mi_is_in_heap_region(p)) { InterlockedIncrement(&g_ForeignFrees); return; }
        const size_t usable = mi_usable_size(p);
        Quarantine* qu = usable <= kQuarantineMax ? ThreadQuarantine() : nullptr;
        if (!qu) { mi_free(p); return; }
        StampPattern(p, usable);
        InterlockedIncrement64(&g_Quarantined);
        if (qu->count < kQuarantineLen)
        {
            qu->ring[(qu->head + qu->count) % kQuarantineLen] = QEntry{ p, from };
            ++qu->count;
            return;
        }
        const QEntry oldest = qu->ring[qu->head];
        qu->ring[qu->head] = QEntry{ p, from };
        qu->head = (qu->head + 1) % kQuarantineLen;
        CheckAndRelease(oldest);
    }

    void FlushThreadQuarantine()
    {
        Quarantine* qu = t_Quarantine;
        if (!qu) return;
        t_Quarantine = nullptr;
        for (uint32_t i = 0; i < qu->count; ++i) CheckAndRelease(qu->ring[(qu->head + i) % kQuarantineLen]);
        mi_free(qu);
    }

    void* DoRealloc(void* p, uint64_t count, uint32_t align, void* from)
    {
        if (!p) return DoMalloc(count, align);
        if (count == 0) { DoFree(p, from); return nullptr; }
        size_t largeSize = 0;
        if (LargeSize(p, largeSize))
        {
            if (count <= largeSize && count >= largeSize / 2) return p;
            void* q = DoMalloc(count, align);
            memcpy(q, p, largeSize < count ? largeSize : static_cast<size_t>(count));
            LargeFree(p);
            return q;
        }
        if (!mi_is_in_heap_region(p)) Fatal(kExcForeignBlock, count, align, p);

        const size_t usable = mi_usable_size(p);
        const size_t want = align <= kMinAlign ? Round16(count) : count;
        const bool aligned = align <= kMinAlign || (reinterpret_cast<uintptr_t>(p) % align) == 0;
        if (want <= usable && want >= usable / 2 && aligned) return p;
        void* q = DoMalloc(count, align);
        memcpy(q, p, usable < count ? usable : static_cast<size_t>(count));
        DoFree(p, from);
        return q;
    }

    class DGMallocImpl
    {
    public:
        virtual ~DGMallocImpl() {}
        virtual bool Exec(UWorld*, const wchar_t*, FOutputDevice*) { return false; }
        virtual uint64_t QuantizeSize(uint64_t count, uint32_t align)
        {
            if (count >= kLargeMin && align <= kLargeAlignMax) return RoundPage(count);
            return align <= kMinAlign ? mi_good_size(Round16(count)) : count;
        }
        virtual void* Malloc(uint64_t count, uint32_t align) { return DoMalloc(count, align); }
        virtual void* Realloc(void* p, uint64_t count, uint32_t align) { return DoRealloc(p, count, align, _ReturnAddress()); }
        virtual void  Free(void* p) { DoFree(p, _ReturnAddress()); }
        virtual void* MallocTrack(uint64_t count, bool*, uint32_t align) { return DoMalloc(count, align); }
        virtual void* ReallocTrack(void* p, uint64_t count, uint8_t*, uint32_t align)
        {
            return DoRealloc(p, count, align, _ReturnAddress());
        }
        virtual void  FreeTrack(void* p, bool*) { DoFree(p, _ReturnAddress()); }
        virtual void  UpdateStats() {}
        virtual void  GetAllocatorStats(FGenericMemoryStats*) {}
        virtual void  DumpAllocatorStats(FOutputDevice*) {}
        virtual bool  IsInternallyThreadSafe() const { return true; }
        virtual bool  ValidateHeap() { return true; }
        virtual bool  GetAllocationSize(void* p, uint64_t* sizeOut)
        {
            if (!p) return false;
            size_t large = 0;
            if (LargeSize(p, large)) { *sizeOut = large; return true; }
            if (!mi_is_in_heap_region(p)) return false;
            *sizeOut = mi_usable_size(p);
            return true;
        }
        virtual void  SetupTLSCachesOnCurrentThread() {}
        virtual void  ClearAndDisableTLSCachesOnCurrentThread() {}
        virtual void  Trim() {}
        virtual const wchar_t* GetDescriptiveName() { return kDescriptiveName; }
    };

    alignas(16) unsigned char g_Storage[sizeof(DGMallocImpl)];

    const IMAGE_NT_HEADERS* NtHeaders(const uint8_t* base)
    {
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        return nt->Signature == IMAGE_NT_SIGNATURE ? nt : nullptr;
    }

    void SetStatus(const char* s) { strncpy_s(g_Status, s, _TRUNCATE); }

#ifdef DGMALLOC_TEST
    /// test/LargeBlocksTest.cpp: the large-block containers without the exe checks of Install.
    void TestInitLarge()
    {
        g_Chunks = new std::vector<Chunk>();
        g_FreeByAddr = new std::map<uintptr_t, size_t>();
        g_FreeBySize = new std::multimap<size_t, uintptr_t>();
        g_Extent = new std::unordered_map<void*, size_t>();
        g_Large = new std::unordered_map<void*, Region>();
    }
#endif

    void Install()
    {
        if (!g_Regions)
        {
            auto* regions = new std::unordered_map<void*, Region>();
            regions->reserve(4096);
            g_Regions = regions;
        }
        const auto* base = reinterpret_cast<const uint8_t*>(GetModuleHandleW(nullptr));
        const IMAGE_NT_HEADERS* nt = base ? NtHeaders(base) : nullptr;
        if (!nt) { SetStatus("off: no exe image"); return; }
        if (nt->FileHeader.TimeDateStamp != kExeTimeDateStamp || nt->OptionalHeader.SizeOfImage != kExeSizeOfImage)
        {
            SetStatus("off: different ShooterGameServer build");
            return;
        }
        if (memcmp(base + kRvaGCreateMalloc, kGCreateMallocHead, sizeof(kGCreateMallocHead)) != 0)
        {
            SetStatus("off: GCreateMalloc does not match");
            return;
        }
        const uint8_t* load = base + kRvaGMallocLoad;
        if (load[0] != 0x48 || load[1] != 0x8B || load[2] != 0x0D)
        {
            SetStatus("off: FMemory::Malloc does not match");
            return;
        }
        int32_t disp = 0;
        memcpy(&disp, load + 3, sizeof(disp));
        if (kRvaGMallocLoad + 7 + static_cast<intptr_t>(disp) != kRvaGMalloc)
        {
            SetStatus("off: GMalloc address does not match");
            return;
        }
        void** gmalloc = reinterpret_cast<void**>(const_cast<uint8_t*>(base) + kRvaGMalloc);
        if (*gmalloc != nullptr)
        {
            SetStatus("off: engine allocator already created");
            return;
        }

#ifdef DGMALLOC_DIAGNOSTIC
        mi_option_enable(mi_option_show_errors);
        mi_register_error(&HeapErrorHandler, nullptr);
#endif
        mi_option_set(mi_option_eager_commit, 0);
        mi_option_set(mi_option_arena_eager_commit, 0);
        mi_option_set(mi_option_purge_delay, 0);

        mi_free(mi_malloc(16));
        g_Chunks = new std::vector<Chunk>();
        g_Chunks->reserve(64);
        g_FreeByAddr = new std::map<uintptr_t, size_t>();
        g_FreeBySize = new std::multimap<size_t, uintptr_t>();
        g_Extent = new std::unordered_map<void*, size_t>();
        g_Extent->reserve(1 << 17);
        auto* large = new std::unordered_map<void*, Region>();
        large->reserve(1 << 17);
        g_Large = large;

        DGMallocImpl* alloc = new (g_Storage) DGMallocImpl();
        InterlockedExchangePointer(gmalloc, alloc);
        InterlockedExchange(&g_Installed, 1);
        SetStatus(kOnStatus);
    }

    using CreateFXFn = HRESULT (__cdecl*)(const GUID*, void**, const void*, UINT32);
    CreateFXFn volatile g_RealCreateFX = nullptr;

    HANDLE g_LogFile = INVALID_HANDLE_VALUE;
    DWORD g_StartTick = 0;
    uintptr_t g_ExeBase = 0;
    uintptr_t g_ExeEnd = 0;

    void LogLine(const char* fmt, ...)
    {
        if (g_LogFile == INVALID_HANDLE_VALUE) return;
        char buf[1024];
        SYSTEMTIME st;
        GetLocalTime(&st);
        int n = snprintf(buf, sizeof(buf), "%04u-%02u-%02u %02u:%02u:%02u ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        va_list args;
        va_start(args, fmt);
        const int m = vsnprintf(buf + n, sizeof(buf) - n - 2, fmt, args);
        va_end(args);
        if (m > 0) n += (m < static_cast<int>(sizeof(buf)) - n - 2) ? m : static_cast<int>(sizeof(buf)) - n - 3;
        buf[n++] = '\r';
        buf[n++] = '\n';
        DWORD written = 0;
        WriteFile(g_LogFile, buf, static_cast<DWORD>(n), &written, nullptr);
    }

    bool InExe(uint64_t v) { return v >= g_ExeBase && v < g_ExeEnd; }

    uint64_t ReadQword(uint64_t addr)
    {
        uint64_t v = 0;
        __try { v = *reinterpret_cast<const volatile uint64_t*>(addr); }
        __except (EXCEPTION_EXECUTE_HANDLER) { v = 0; }
        return v;
    }

    void DescribeValue(uint64_t v, char* out, size_t outSize)
    {
        if (InExe(v)) { snprintf(out, outSize, "0x%016llX (exe+0x%llX)", v, v - g_ExeBase); return; }
        const uint64_t vptr = (v >= 0x10000 && (v & 7) == 0) ? ReadQword(v) : 0;
        if (InExe(vptr)) snprintf(out, outSize, "0x%016llX (object, vtable exe+0x%llX)", v, vptr - g_ExeBase);
        else snprintf(out, outSize, "0x%016llX", v);
    }

    void OpenLog()
    {
        wchar_t path[MAX_PATH];
        const DWORD len = GetModuleFileNameW(nullptr, path, MAX_PATH);
        if (len == 0 || len >= MAX_PATH) return;
        for (int up = 0; up < 3; ++up)
        {
            wchar_t* slash = wcsrchr(path, L'\\');
            if (!slash) return;
            *slash = 0;
        }
        if (wcslen(path) + 32 >= MAX_PATH) return;
        wcscat_s(path, L"\\Saved\\Logs");
        CreateDirectoryW(path, nullptr);
        wcscat_s(path, L"\\DGMalloc.log");
        g_LogFile = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    }

    void LogMemory()
    {
        size_t elapsed = 0, user = 0, sys = 0, rss = 0, peakRss = 0, commit = 0, peakCommit = 0, faults = 0;
        mi_process_info(&elapsed, &user, &sys, &rss, &peakRss, &commit, &peakCommit, &faults);
        PROCESS_MEMORY_COUNTERS_EX pmc{};
        pmc.cb = sizeof(pmc);
        K32GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc));
        LogLine("memory | process private %llu MB, working set %llu MB | mimalloc commit %llu MB (peak %llu MB), "
                "rss %llu MB | large blocks %lld MB (peak %lld MB) | quarantined %lld blocks total",
                static_cast<unsigned long long>(pmc.PrivateUsage >> 20), static_cast<unsigned long long>(pmc.WorkingSetSize >> 20),
                static_cast<unsigned long long>(commit >> 20), static_cast<unsigned long long>(peakCommit >> 20),
                static_cast<unsigned long long>(rss >> 20), static_cast<long long>(g_LargeBytes >> 20),
                static_cast<long long>(g_LargePeakBytes >> 20), static_cast<long long>(g_Quarantined));
    }

    DWORD WINAPI Reporter(LPVOID)
    {
        OpenLog();
        LogLine("DGMalloc %s", g_Status);
        LONG findingsSeen = 0, cutsSeen = 0, foreignSeen = 0;
        DWORD lastMemory = 0;
        for (;;)
        {
            Sleep(GetTickCount() - g_StartTick < 300000 ? 5000 : 30000);
            const LONG findings = g_FindingsWritten < kMaxFindings ? g_FindingsWritten : kMaxFindings;
            for (; findingsSeen < findings; ++findingsSeen)
            {
                const Finding& f = g_Findings[findingsSeen];
                char value[160];
                DescribeValue(f.value, value, sizeof(value));
                LogLine("write after free in quarantine | block %p (%u bytes) offset %u | value %s | freed from exe+0x%llX",
                        f.block, f.size, f.offset, value,
                        InExe(reinterpret_cast<uint64_t>(f.from)) ? reinterpret_cast<uint64_t>(f.from) - g_ExeBase : 0ULL);
            }
            if (g_FindingCount > findings && findingsSeen == kMaxFindings)
                LogLine("write after free in quarantine | %ld total (first %ld listed)", g_FindingCount, kMaxFindings);
            const LONG cuts = g_CutsWritten < kMaxCuts ? g_CutsWritten : kMaxCuts;
            for (; cutsSeen < cuts; ++cutsSeen)
            {
                const Cut& c = g_Cuts[cutsSeen];
                char value[160];
                DescribeValue(reinterpret_cast<uint64_t>(c.next), value, sizeof(value));
                LogLine("free list cut | block %p (%llu bytes) | link %s", c.block, static_cast<unsigned long long>(c.blockSize), value);
            }
            if (g_ForeignFrees != foreignSeen)
            {
                foreignSeen = g_ForeignFrees;
                LogLine("foreign frees %ld", foreignSeen);
            }
            const DWORD now = GetTickCount();
            if (lastMemory == 0 || now - lastMemory >= (now - g_StartTick < 300000 ? 5000u : 600000u))
            {
                lastMemory = now;
                LogMemory();
            }
        }
    }

    void StartReporter()
    {
        const auto* base = reinterpret_cast<const uint8_t*>(GetModuleHandleW(nullptr));
        const IMAGE_NT_HEADERS* nt = base ? NtHeaders(base) : nullptr;
        if (!nt) return;
        g_ExeBase = reinterpret_cast<uintptr_t>(base);
        g_ExeEnd = g_ExeBase + nt->OptionalHeader.SizeOfImage;
        g_StartTick = GetTickCount();
        HANDLE t = CreateThread(nullptr, 64 * 1024, &Reporter, nullptr, STACK_SIZE_PARAM_IS_A_RESERVATION, nullptr);
        if (t)
        {
            SetThreadPriority(t, THREAD_PRIORITY_LOWEST);
            CloseHandle(t);
        }
    }
}

extern "C" HRESULT __cdecl CreateFX(const GUID* clsid, void** effect, const void* initData, UINT32 initDataSize)
{
    CreateFXFn real = g_RealCreateFX;
    if (!real)
    {
        wchar_t path[MAX_PATH];
        const UINT n = GetSystemDirectoryW(path, MAX_PATH);
        if (n == 0 || n > MAX_PATH - 20) return E_FAIL;
        wcscat_s(path, L"\\XAPOFX1_5.dll");
        HMODULE m = LoadLibraryW(path);
        real = m ? reinterpret_cast<CreateFXFn>(reinterpret_cast<void*>(GetProcAddress(m, "CreateFX"))) : nullptr;
        if (!real) return E_FAIL;
        g_RealCreateFX = real;
    }
    return real(clsid, effect, initData, initDataSize);
}

extern "C" const char* DGMalloc_Status() { return g_Status; }

// ---- write watch ----------------------------------------------------------------------------------------------------
// Every DGMalloc reservation (mimalloc's arenas / segments, our large blocks) is made with MEM_WRITE_WATCH. The engine side
// (DGServerHealthMonitor DirtyPages.cpp) takes the regions here and asks GetWriteWatch itself, so it owns the reset policy.
extern "C" void dgmalloc_region_reserved(void* base, size_t size)
{
    if (!base || !g_Regions) return;
    const unsigned long long gen = static_cast<unsigned long long>(InterlockedIncrement64(&g_RegionGen));
    AcquireSRWLockExclusive(&g_RegionLock);
    (*g_Regions)[base] = Region{ size, gen };
    ReleaseSRWLockExclusive(&g_RegionLock);
}

extern "C" void dgmalloc_region_released(void* base)
{
    if (!base || !g_Regions) return;
    AcquireSRWLockExclusive(&g_RegionLock);
    g_Regions->erase(base);
    ReleaseSRWLockExclusive(&g_RegionLock);
}

struct DGMallocRegion { void* base; unsigned long long size; unsigned long long gen; };

/// The write-watched regions now: up to `max` written to `out`; returns how many there are (call again with more room
/// when it exceeds `max`). `*generation` = the newest generation handed out so far.
extern "C" size_t DGMalloc_WriteWatchRegions(DGMallocRegion* out, size_t max, unsigned long long* generation)
{
    size_t n = 0;
    if (generation) *generation = static_cast<unsigned long long>(g_RegionGen);
    if (g_Regions)
    {
        AcquireSRWLockShared(&g_RegionLock);
        for (const auto& r : *g_Regions)
        {
            if (out && n < max) out[n] = DGMallocRegion{ r.first, r.second.size, r.second.gen };
            ++n;
        }
        ReleaseSRWLockShared(&g_RegionLock);
    }
    if (g_Chunks)
    {
        AcquireSRWLockShared(&g_FreeLock);
        for (const Chunk& c : *g_Chunks)
        {
            if (out && n < max) out[n] = DGMallocRegion{ reinterpret_cast<void*>(c.base), kChunkSize, c.gen };
            ++n;
        }
        ReleaseSRWLockShared(&g_FreeLock);
    }
    if (g_Large)
    {
        // own reservations only (256 MB and more); chunk blocks (gen 0) are covered by their chunk
        AcquireSRWLockShared(&g_LargeLock);
        for (const auto& r : *g_Large)
        {
            if (r.second.gen == 0) continue;
            if (out && n < max) out[n] = DGMallocRegion{ r.first, r.second.size, r.second.gen };
            ++n;
        }
        ReleaseSRWLockShared(&g_LargeLock);
    }
    return n;
}

extern "C" long DGMalloc_ForeignFrees() { return g_ForeignFrees; }

extern "C" void dgmalloc_freelist_cut(const void* block, const void* next, size_t blockSize)
{
    InterlockedIncrement(&g_CutCount);
    const LONG slot = InterlockedIncrement(&g_CutsWritten) - 1;
    if (slot < kMaxCuts) g_Cuts[slot] = Cut{ block, next, blockSize };
    else InterlockedDecrement(&g_CutsWritten);
}

struct DGMallocStats { long long quarantined; long findings; long cuts; long foreignFrees; long findingsKept; long cutsKept; };
extern "C" void DGMalloc_Stats(DGMallocStats* out)
{
    if (!out) return;
    out->quarantined = g_Quarantined;
    out->findings = g_FindingCount;
    out->cuts = g_CutCount;
    out->foreignFrees = g_ForeignFrees;
    out->findingsKept = g_FindingsWritten < kMaxFindings ? g_FindingsWritten : kMaxFindings;
    out->cutsKept = g_CutsWritten < kMaxCuts ? g_CutsWritten : kMaxCuts;
}

extern "C" void DGMalloc_ProcessInfo(unsigned long long* rss, unsigned long long* peakRss,
                                     unsigned long long* commit, unsigned long long* peakCommit)
{
    size_t elapsed = 0, user = 0, sys = 0, r = 0, pr = 0, c = 0, pc = 0, faults = 0;
    mi_process_info(&elapsed, &user, &sys, &r, &pr, &c, &pc, &faults);
    if (rss) *rss = r;
    if (peakRss) *peakRss = pr;
    if (commit) *commit = c;
    if (peakCommit) *peakCommit = pc;
}

extern "C" bool DGMalloc_Finding(long i, void** block, unsigned* offset, unsigned long long* value, void** freedFrom, unsigned* size)
{
    if (i < 0 || i >= kMaxFindings || i >= g_FindingsWritten) return false;
    const Finding& f = g_Findings[i];
    *block = f.block; *offset = f.offset; *value = f.value; *freedFrom = f.from; *size = f.size;
    return true;
}

extern "C" bool DGMalloc_Cut(long i, const void** block, const void** next, unsigned long long* blockSize)
{
    if (i < 0 || i >= kMaxCuts || i >= g_CutsWritten) return false;
    *block = g_Cuts[i].block; *next = g_Cuts[i].next; *blockSize = g_Cuts[i].blockSize;
    return true;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        Install();
        if (g_Installed) StartReporter();
    }
    if (reason == DLL_THREAD_DETACH && g_Installed) FlushThreadQuarantine();

    return TRUE;
}
