#include <windows.h>
#include <cstdint>
#include <cstring>
#include <new>
#include <intrin.h>

#include "mimalloc.h"

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

    void* DoMalloc(uint64_t count, uint32_t align)
    {
        void* p = align <= kMinAlign ? mi_malloc(Round16(count)) : mi_malloc_aligned(count, align);
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
            if (!p || !mi_is_in_heap_region(p)) return false;
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

    void Install()
    {
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

        DGMallocImpl* alloc = new (g_Storage) DGMallocImpl();
        InterlockedExchangePointer(gmalloc, alloc);
        InterlockedExchange(&g_Installed, 1);
        SetStatus(kOnStatus);
    }

    using CreateFXFn = HRESULT (__cdecl*)(const GUID*, void**, const void*, UINT32);
    CreateFXFn volatile g_RealCreateFX = nullptr;
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
    if (reason == DLL_PROCESS_ATTACH) Install();
    if (reason == DLL_THREAD_DETACH && g_Installed) FlushThreadQuarantine();

    return TRUE;
}
