#include "msmon.h"
#include <aux_klib.h>

static KSPIN_LOCK gAttributionLock;
static ULONG_PTR gBlackCatBase;
static ULONG gBlackCatSize;
static BOOLEAN gBlackCatLoaded;
static BOOLEAN gRefreshCompleted;

NTSTATUS MsMonAttributionInitialize(VOID)
{
    KeInitializeSpinLock(&gAttributionLock);
    gBlackCatBase = 0;
    gBlackCatSize = 0;
    gBlackCatLoaded = FALSE;
    gRefreshCompleted = FALSE;
    return AuxKlibInitialize();
}

VOID MsMonAttributionStop(VOID)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&gAttributionLock, &oldIrql);
    gBlackCatBase = 0;
    gBlackCatSize = 0;
    gBlackCatLoaded = FALSE;
    gRefreshCompleted = FALSE;
    KeReleaseSpinLock(&gAttributionLock, oldIrql);
}

static CHAR MsMonLowerChar(CHAR Value)
{
    return Value >= 'A' && Value <= 'Z' ? Value + ('a' - 'A') : Value;
}

static BOOLEAN MsMonBlackCatName(PCSTR Path)
{
    static const CHAR prefix[] = "blackcat";
    static const CHAR suffix[] = ".sys";
    PCSTR base = Path;
    PCSTR cursor;
    ULONG index;
    if (Path == NULL) return FALSE;
    for (cursor = Path; cursor - Path < AUX_KLIB_MODULE_PATH_LEN && *cursor != '\0'; cursor++) {
        if (*cursor == '\\' || *cursor == '/') base = cursor + 1;
    }
    if (cursor - Path == AUX_KLIB_MODULE_PATH_LEN) return FALSE;
    for (index = 0; index < ARRAYSIZE(prefix) - 1; index++) {
        if (base[index] == '\0' || MsMonLowerChar(base[index]) != prefix[index]) return FALSE;
    }
    cursor = base + ARRAYSIZE(prefix) - 1;
    if (*cursor < '0' || *cursor > '9') return FALSE;
    while (*cursor >= '0' && *cursor <= '9') cursor++;
    for (index = 0; index < ARRAYSIZE(suffix); index++) {
        if (cursor[index] == '\0' || MsMonLowerChar(cursor[index]) != suffix[index]) return FALSE;
    }
    return TRUE;
}

NTSTATUS MsMonAttributionRefresh(VOID)
{
    ULONG bytes = 0;
    NTSTATUS status = AuxKlibQueryModuleInformation(&bytes, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
    PAUX_MODULE_EXTENDED_INFO modules;
    ULONG count;
    ULONG index;
    ULONG_PTR base = 0;
    ULONG imageSize = 0;
    BOOLEAN loaded = FALSE;
    BOOLEAN changed;
    WCHAR moduleName[64] = L"";
    KIRQL oldIrql;

    if (!NT_SUCCESS(status) && status != STATUS_BUFFER_TOO_SMALL) return status;
    if (bytes == 0) return STATUS_INVALID_BUFFER_SIZE;
    modules = ExAllocatePool2(POOL_FLAG_PAGED, bytes, MSMON_POOL_TAG);
    if (modules == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    status = AuxKlibQueryModuleInformation(&bytes, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(modules, MSMON_POOL_TAG);
        return status;
    }
    count = bytes / sizeof(AUX_MODULE_EXTENDED_INFO);
    for (index = 0; index < count; index++) {
        PCSTR path = (PCSTR)modules[index].FullPathName;
        if (MsMonBlackCatName(path)) {
            PCSTR name = path;
            PCSTR cursor;
            for (cursor = path; *cursor != '\0'; cursor++) {
                if (*cursor == '\\' || *cursor == '/') name = cursor + 1;
            }
            (VOID)RtlStringCchPrintfW(moduleName, RTL_NUMBER_OF(moduleName), L"%hs", name);
            base = (ULONG_PTR)modules[index].BasicInfo.ImageBase;
            imageSize = modules[index].ImageSize;
            loaded = TRUE;
            break;
        }
    }
    ExFreePoolWithTag(modules, MSMON_POOL_TAG);

    KeAcquireSpinLock(&gAttributionLock, &oldIrql);
    changed = !gRefreshCompleted || loaded != gBlackCatLoaded ||
              base != gBlackCatBase || imageSize != gBlackCatSize;
    gRefreshCompleted = TRUE;
    gBlackCatLoaded = loaded;
    gBlackCatBase = base;
    gBlackCatSize = imageSize;
    KeReleaseSpinLock(&gAttributionLock, oldIrql);

    if (changed) {
        WCHAR detail[160];
        UNICODE_STRING text;
        UNICODE_STRING detailString;
        RtlInitUnicodeString(&text, loaded ? L"blackcat_loaded" : L"blackcat_not_loaded");
        (VOID)RtlStringCchPrintfW(detail, RTL_NUMBER_OF(detail), L"name=%ws;base=0x%p;size=0x%lx",
                                  moduleName, (PVOID)base, imageSize);
        RtlInitUnicodeString(&detailString, detail);
        (VOID)MsMonLogEvent(MsMonCoverage, PsGetCurrentProcessId(), NULL, PsGetCurrentThreadId(),
                            NULL, 0, MsMonFlagObserverRecord, STATUS_SUCCESS, 0,
                            MsMonCategoryUnknown, base, imageSize, &text, &detailString);
    }
    return STATUS_SUCCESS;
}

BOOLEAN MsMonCurrentIsBlackCat(VOID)
{
    ULONG_PTR base;
    ULONG size;
    PVOID frames[32];
    USHORT count;
    USHORT index;
    KIRQL oldIrql;

    KeAcquireSpinLock(&gAttributionLock, &oldIrql);
    base = gBlackCatBase;
    size = gBlackCatSize;
    KeReleaseSpinLock(&gAttributionLock, oldIrql);
    if (base == 0 || size == 0) return FALSE;
    count = RtlCaptureStackBackTrace(1, RTL_NUMBER_OF(frames), frames, NULL);
    for (index = 0; index < count; index++) {
        ULONG_PTR address = (ULONG_PTR)frames[index];
        if (address >= base && address - base < size) return TRUE;
    }
    return FALSE;
}
