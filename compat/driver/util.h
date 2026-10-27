/* util.h - tiny helpers so the driver needs no C runtime library at all. */
#pragma once
#include <ntddk.h>
#include <intrin.h>

static __inline size_t SysinfoStrLenA(_In_z_ const char *text)
{
    size_t length = 0;
    while (text[length] != 0) length++;
    return length;
}

static __inline size_t SysinfoStrLenW(_In_z_ const WCHAR *text)
{
    size_t length = 0;
    while (text[length] != 0) length++;
    return length;
}

/* Not exported by this WDK's ntoskrnl.lib; KeInvalidateAllCaches is. */

/* Forces the current core to re-read the instruction stream. */
static __inline void SysinfoSerializeCore(VOID)
{
    int registers[4];
    __cpuid(registers, 0);
}
