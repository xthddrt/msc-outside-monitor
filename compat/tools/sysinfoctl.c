/*
 * sysinfoctl.c - control tool for SysInfo.sys.
 *
 *   sysinfoctl install [path\to\SysInfo.sys]   copy + register the service
 *   sysinfoctl uninstall                          stop + delete the service
 *   sysinfoctl start | stop                       start/stop the driver
 *   sysinfoctl unload                             force NtUnloadDriver (reloads fine)
 *   sysinfoctl status                             driver state (needs the driver)
 *   sysinfoctl random [seed] [key=value ...]      generate, apply and persist
 *   sysinfoctl show                               dump the live configuration
 *   sysinfoctl clear                              stop remapping everything
 *   sysinfoctl verify                             read the IDs back through the OS
 *
 * key=value overrides for `random`: machineguid, hwprofileguid, uuid, serial,
 * boardserial, chassis, bios, disk, volume, mac.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <ctype.h>
#include <intrin.h>

#include "../shared/sysinfo.h"

#define SERVICE_KEY L"SYSTEM\\CurrentControlSet\\Services\\" SYSINFO_SERVICE_NAME

/*
 * Kernel modules, for turning an event's Caller address into "WdFilter.sys+0x1a2".
 * EnumDeviceDrivers gives the bases; the next base bounds each image.
 */
typedef struct _KMOD {
    ULONG64 Base;
    ULONG64 Size;
    CHAR    Name[64];
} KMOD;

static KMOD  g_KMods[512];
static int   g_KModCount;

static int
CmpMod(const void *a, const void *b)
{
    ULONG64 x = ((const KMOD *)a)->Base, y = ((const KMOD *)b)->Base;
    return (x < y) ? -1 : (x > y) ? 1 : 0;
}

static void
LoadKernelModules(VOID)
{
    LPVOID bases[512];
    DWORD  needed = 0;
    int    n, i;

    if (g_KModCount != 0) return;
    if (!EnumDeviceDrivers(bases, sizeof(bases), &needed)) return;

    n = (int)(needed / sizeof(LPVOID));
    if (n > (int)(sizeof(g_KMods) / sizeof(g_KMods[0]))) n = (int)(sizeof(g_KMods) / sizeof(g_KMods[0]));
    if (n <= 0) return;

    for (i = 0; i < n; i++) {
        g_KMods[i].Base = (ULONG64)(ULONG_PTR)bases[i];
        GetDeviceDriverBaseNameA(bases[i], g_KMods[i].Name, sizeof(g_KMods[i].Name));
    }
    qsort(g_KMods, (size_t)n, sizeof(g_KMods[0]), CmpMod);
    for (i = 0; i < n; i++) {
        g_KMods[i].Size = (i + 1 < n)
            ? g_KMods[i + 1].Base - g_KMods[i].Base
            : 0x10000000ULL;      /* last image: open-ended for formatting */
    }
    g_KModCount = n;
}

static const char *
CallerModule(ULONG64 pc, ULONG64 *offset)
{
    int lo = 0, hi, found = -1;

    LoadKernelModules();
    hi = g_KModCount - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (g_KMods[mid].Base <= pc) { found = mid; lo = mid + 1; }
        else hi = mid - 1;
    }
    if (found < 0) return NULL;
    if (pc >= g_KMods[found].Base + g_KMods[found].Size) return NULL;
    if (offset != NULL) *offset = pc - g_KMods[found].Base;
    return g_KMods[found].Name;
}

/*
 * nt!NtReadVirtualMemory has no exported stub, so the only reliable way to
 * find it is the syscall number in the user-mode ntdll stub:
 *   4C 8B D1        mov r10, rcx
 *   B8 xx xx xx xx  mov eax, <ssn>
 */
static ULONG
NtdllSsn(const char *name)
{
    HMODULE      ntdll = GetModuleHandleA("ntdll.dll");
    const BYTE  *p;
    int          i;

    if (ntdll == NULL) return 0;
    p = (const BYTE *)GetProcAddress(ntdll, name);
    if (p == NULL) return 0;

    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) {
        return *(const ULONG *)(p + 4);
    }
    for (i = 0; i + 5 <= 32; i++) {
        if (p[i] == 0xB8) return *(const ULONG *)(p + i + 1);
    }
    return 0;
}

/*
 * CPUID leaf 1, ECX bit 31: a hypervisor is present.  With VBS this means
 * HyperGuard is hash-verifying kernel code pages, so inline hooks cannot be
 * used.  (Plain Hyper-V sets the same bit; either way, don't patch.)
 */
static int
CpuHypervisorPresent(VOID)
{
    int registers[4];

    __cpuid(registers, 1);
    return (registers[2] & (1 << 31)) != 0;
}

static int CmdUnload(PCSTR only);   /* used by CmdInstall before its definition */
static void RefreshWmi(VOID);       /* used by CmdApply/CmdClear before its definition */

static ULONGLONG g_rng;

/* "\Registry\Machine\SYSTEM\ControlSet00N".  The object manager resolves
 * CurrentControlSet, so NtQueryKey never reports that name back - the
 * overrides have to use the numbered form to match. */
static WCHAR g_ControlSetPath[96] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet";

static void
ResolveControlSetPath(VOID)
{
    HKEY  key;
    DWORD current = 1, size = sizeof(current), type = 0;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\Select", 0, KEY_QUERY_VALUE, &key) == ERROR_SUCCESS) {
        RegQueryValueExW(key, L"Current", NULL, &type, (BYTE *)&current, &size);
        RegCloseKey(key);
    }
    if (current > 999) current = 1;
    swprintf_s(g_ControlSetPath, 96, L"\\Registry\\Machine\\SYSTEM\\ControlSet%03u", current);
}

/* ------------------------------------------------------------------ random */

static ULONGLONG
NextRandom(VOID)
{
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 7;
    g_rng ^= g_rng << 17;
    return g_rng;
}

static ULONG
NextRandom32(VOID)
{
    return (ULONG)(NextRandom() >> 11);
}

static const char g_alnum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

static void
RandomCode(char *out, int length)
{
    int i;
    for (i = 0; i < length; i++) out[i] = g_alnum[NextRandom32() % 36];
    out[length] = 0;
}

static void
RandomGuid(char *out, int upper)
{
    static const char *fmt = "%08X-%04X-%04X-%04X-%012llX";
    ULONGLONG hi;
    ULONG a, b, c, d;

    a = NextRandom32();
    b = (ULONG)(NextRandom32() & 0xFFFF);
    c = (ULONG)((NextRandom32() & 0x0FFF) | 0x4000);
    d = (ULONG)((NextRandom32() & 0x3FFF) | 0x8000);
    hi = (ULONGLONG)NextRandom32() << 16 | (NextRandom32() & 0xFFFF);

    sprintf_s(out, 40, fmt, a, b, c, d, hi);
    if (!upper) {
        size_t i;
        for (i = 0; out[i]; i++) {
            if (out[i] >= 'A' && out[i] <= 'F') out[i] = (char)(out[i] - 'A' + 'a');
        }
    }
}

/* ------------------------------------------------------------------ config */

static SYSINFO_REG_ENTRY *
AddEntry(SYSINFO_CONFIG *cfg, const WCHAR *keyPath, const WCHAR *valueName, ULONG type)
{
    SYSINFO_REG_ENTRY *e;

    if (cfg->RegCount >= SYSINFO_MAX_REG) return NULL;
    e = &cfg->Reg[cfg->RegCount++];
    wcsncpy_s(e->KeyPath, SYSINFO_MAX_PATH, keyPath, _TRUNCATE);
    wcsncpy_s(e->ValueName, SYSINFO_MAX_VALUE, valueName, _TRUNCATE);
    e->Type = type;
    return e;
}

static void
AddString(SYSINFO_CONFIG *cfg, const WCHAR *keyPath, const WCHAR *valueName, const char *value)
{
    SYSINFO_REG_ENTRY *e = AddEntry(cfg, keyPath, valueName, REG_SZ);
    WCHAR wide[64];

    if (e == NULL) return;
    MultiByteToWideChar(CP_ACP, 0, value, -1, wide, 64);
    e->DataLength = (ULONG)((wcslen(wide) + 1) * sizeof(WCHAR));
    if (e->DataLength > SYSINFO_MAX_DATA) e->DataLength = SYSINFO_MAX_DATA;
    memcpy(e->Data, wide, e->DataLength);
}

static void
AddDword(SYSINFO_CONFIG *cfg, const WCHAR *keyPath, const WCHAR *valueName, ULONG value)
{
    SYSINFO_REG_ENTRY *e = AddEntry(cfg, keyPath, valueName, REG_DWORD);

    if (e == NULL) return;
    e->DataLength = sizeof(ULONG);
    memcpy(e->Data, &value, sizeof(ULONG));
}

/* ------------------------------------------------------------------- EDID */

/*
 * One valid EDID 1.3 base block.  Only the identity fields vary: manufacturer,
 * product code, serial, week/year and the three text descriptors.  The timing
 * data is fixed and checksum-correct, so every EDID parser accepts it.
 */
static void
BuildFakeEdid(SYSINFO_CONFIG *cfg)
{
    static const char *pnps[]  = { "DEL", "SAM", "ACR", "GSM", "AUS", "BNQ" };
    static const char *names[] = {
        "DELL U2723QE",
        "SAMSUNG S27R65",
        "ACER XB273K",
        "LG ULTRAGEAR",
        "ASUS VG279Q",
        "BENQ EX2710Q"
    };
    /* A 1920x1080@60 detailed timing descriptor. */
    static const BYTE dtd[18] = {
        0x02, 0x3A, 0x80, 0x18, 0x71, 0x38, 0x2D, 0x40, 0x58,
        0x2C, 0x45, 0x00, 0x09, 0x25, 0x21, 0x00, 0x00, 0x1E
    };
    /* Range limits: 50-75 Hz, 30-83 kHz, 170 MHz. */
    static const BYTE range[18] = {
        0x00, 0x00, 0x00, 0xFD, 0x00, 0x32, 0x4B, 0x1E, 0x53,
        0x11, 0x00, 0x0A, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20
    };
    static const BYTE chroma[10] = {
        0xEE, 0x91, 0xA3, 0x54, 0x4C, 0x99, 0x26, 0x0F, 0x50, 0x54
    };
    UCHAR *e = cfg->Edid;
    ULONG product = NextRandom32() & 0xFFFF;
    ULONG serial = NextRandom32();
    DWORD pick = NextRandom32() % 6;
    WORD mfg;
    int i;
    UCHAR sum;

    memset(e, 0, SYSINFO_MAX_EDID);
    e[0] = 0x00;
    for (i = 1; i <= 6; i++) e[i] = 0xFF;
    e[7] = 0x00;

    mfg = (WORD)(((pnps[pick][0] - 'A' + 1) << 10) |
                 ((pnps[pick][1] - 'A' + 1) << 5) |
                  (pnps[pick][2] - 'A' + 1));
    e[8]  = (UCHAR)(mfg >> 8);
    e[9]  = (UCHAR)mfg;
    e[10] = (UCHAR)product;
    e[11] = (UCHAR)(product >> 8);
    e[12] = (UCHAR)serial;
    e[13] = (UCHAR)(serial >> 8);
    e[14] = (UCHAR)(serial >> 16);
    e[15] = (UCHAR)(serial >> 24);
    e[16] = (UCHAR)(1 + (NextRandom32() % 52));        /* week   */
    e[17] = (UCHAR)(2021 - 1990 + (NextRandom32() % 5)); /* year  */

    e[18] = 1; e[19] = 3;         /* EDID 1.3            */
    e[20] = 0x80;                 /* digital input       */
    e[21] = 60; e[22] = 34;       /* 60 x 34 cm          */
    e[23] = 120;                  /* gamma 2.2           */
    e[24] = 0x0A;                 /* RGB, preferred timing */
    memcpy(e + 25, chroma, sizeof(chroma));
    e[35] = 0x21; e[36] = 0x08;   /* established timings */
    e[38] = 0x81; e[39] = 0x80;   /* standard timings    */
    e[40] = 0x95; e[41] = 0x00;
    e[42] = 0xA9; e[43] = 0x40;
    e[44] = 0xB3; e[45] = 0x00;

    memcpy(e + 54, dtd, sizeof(dtd));

    /* Descriptor: monitor name. */
    e[72] = 0x00; e[73] = 0x00; e[74] = 0x00; e[75] = 0xFC; e[76] = 0x00;
    for (i = 0; i < 13; i++) e[77 + i] = 0x20;
    for (i = 0; i < 13 && names[pick][i] != 0; i++) e[77 + i] = (UCHAR)names[pick][i];
    e[89] = 0x0A;

    /* Descriptor: serial number. */
    e[90] = 0x00; e[91] = 0x00; e[92] = 0x00; e[93] = 0xFF; e[94] = 0x00;
    {
        char text[14];
        sprintf_s(text, sizeof(text), "%08X%04X", serial, NextRandom32() & 0xFFFF);
        for (i = 0; i < 13; i++) e[95 + i] = 0x20;
        for (i = 0; i < 12 && text[i] != 0; i++) e[95 + i] = (UCHAR)text[i];
    }
    e[107] = 0x0A;

    memcpy(e + 108, range, sizeof(range));
    e[126] = 1;                   /* one CTA-861 extension block */

    sum = 0;
    for (i = 0; i < 127; i++) sum = (UCHAR)(sum + e[i]);
    e[127] = (UCHAR)(0 - sum);

    /* Minimal, empty CTA-861 block: parsers accept it and it keeps the value
     * the same length as a monitor that ships an extension block. */
    e[128] = 0x02;
    e[129] = 0x03;
    e[130] = 0x04;
    e[131] = 0x00;
    sum = 0;
    for (i = 128; i < 255; i++) sum = (UCHAR)(sum + e[i]);
    e[255] = (UCHAR)(0 - sum);

    cfg->EdidLength = 256;
}

/*
 * Win32_DiskDrive.Model and the storage stack's friendly names come from the
 * device's PnP key, not from a live IOCTL, so override that value too.
 */
static void
AddDiskFriendlyNames(SYSINFO_CONFIG *cfg, const char *model)
{
    static const WCHAR *roots[] = { L"Enum\\SCSI", L"Enum\\USBSTOR", L"Enum\\NVME" };
    ULONG r;

    for (r = 0; r < RTL_NUMBER_OF(roots); r++) {
        WCHAR regPath[96];
        HKEY root;

        swprintf_s(regPath, 96, L"SYSTEM\\CurrentControlSet\\%s", roots[r]);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, KEY_READ, &root) != ERROR_SUCCESS) continue;

        for (DWORD i = 0; ; i++) {
            WCHAR vendor[128];
            DWORD vlen = RTL_NUMBER_OF(vendor);
            HKEY vk;

            if (RegEnumKeyExW(root, i, vendor, &vlen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
            if (RegOpenKeyExW(root, vendor, 0, KEY_READ, &vk) != ERROR_SUCCESS) continue;
            if (r < 2 && _wcsnicmp(vendor, L"Disk", 4) != 0) {   /* skip CD-ROM devices */
                RegCloseKey(vk);
                continue;
            }

            for (DWORD j = 0; ; j++) {
                WCHAR inst[128];
                DWORD ilen = RTL_NUMBER_OF(inst);
                WCHAR native[SYSINFO_MAX_PATH];
                HKEY ik;
                DWORD type = 0;

                if (RegEnumKeyExW(vk, j, inst, &ilen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
                if (RegOpenKeyExW(vk, inst, 0, KEY_READ, &ik) != ERROR_SUCCESS) continue;
                if (RegQueryValueExW(ik, L"FriendlyName", NULL, &type, NULL, NULL) != ERROR_SUCCESS) {
                    RegCloseKey(ik);
                    continue;
                }
                RegCloseKey(ik);

                swprintf_s(native, SYSINFO_MAX_PATH, L"%ls\\%ls\\%ls\\%ls",
                           g_ControlSetPath, roots[r], vendor, inst);
                AddString(cfg, native, L"FriendlyName", model);
            }
            RegCloseKey(vk);
        }
        RegCloseKey(root);
    }
}

static void
BuildConfig(ULONGLONG seed, SYSINFO_CONFIG *cfg)
{
    char v[64], guid[40];
    int i;

    memset(cfg, 0, sizeof(*cfg));
    cfg->Size = sizeof(SYSINFO_CONFIG);
    cfg->Flags = SYSINFO_F_ALL;
    cfg->Seed = (ULONG)seed;
    g_rng = seed ? seed : 0x9E3779B97F4A7C15ULL;

    /* --- SMBIOS --- */
    for (i = 0; i < 16; i++) cfg->SmbiosUuid[i] = (BYTE)NextRandom32();

    RandomCode(cfg->SmbiosSerial, 12);
    RandomCode(cfg->SmbiosSku, 10);
    RandomCode(cfg->BoardSerial, 12);
    RandomCode(cfg->BoardAsset, 10);
    RandomCode(cfg->ChassisSerial, 12);
    RandomCode(cfg->ChassisAsset, 10);
    sprintf_s(cfg->BiosDate, SYSINFO_MAX_STR, "%02u/%02u/%04u",
              (NextRandom32() % 12) + 1, (NextRandom32() % 28) + 1, 2019 + (NextRandom32() % 6));
    sprintf_s(cfg->BiosVersion, SYSINFO_MAX_STR, "%u.%u%u", 1 + (NextRandom32() % 9),
              NextRandom32() % 10, NextRandom32() % 10);
    strcpy_s(cfg->BiosVendor, SYSINFO_MAX_STR, "American Megatrends Inc.");
    strcpy_s(cfg->SmbiosVersion, SYSINFO_MAX_STR, "1.0");
    strcpy_s(cfg->SmbiosFamily, SYSINFO_MAX_STR, "Desktop");
    strcpy_s(cfg->BoardVersion, SYSINFO_MAX_STR, "1.0");
    strcpy_s(cfg->ChassisManufacturer, SYSINFO_MAX_STR, "System manufacturer");
    strcpy_s(cfg->ChassisVersion, SYSINFO_MAX_STR, "1.0");

    /* --- storage / volume / network --- */
    RandomCode(cfg->DiskSerial, 12);
    sprintf_s(cfg->DiskFirmware, SYSINFO_MAX_STR, "%08X", NextRandom32());
    for (i = 0; i < 8; i++) cfg->DiskEui64[i] = (BYTE)NextRandom32();
    for (i = 0; i < 16; i++) cfg->DiskNguid[i] = (BYTE)NextRandom32();
    cfg->VolumeSerial = NextRandom32();
    for (i = 0; i < 6; i++) cfg->Mac[i] = (BYTE)NextRandom32();
    cfg->Mac[0] = (BYTE)((cfg->Mac[0] | 0x02) & 0xFE);    /* locally administered, unicast */

    /* --- registry SYSINFOs --- */
    RandomCode(v, 16);

    /* The SMBIOS strings must match what the registry overrides below say,
     * otherwise WMI's model/manufacturer would disagree with the registry. */
    strcpy_s(cfg->SmbiosManufacturer, SYSINFO_MAX_STR, "System manufacturer");
    strcpy_s(cfg->BoardManufacturer, SYSINFO_MAX_STR, "Base Board Manufacturer");
    strcpy_s(cfg->SmbiosProduct, SYSINFO_MAX_STR, v);
    strcpy_s(cfg->BoardProduct, SYSINFO_MAX_STR, v);

    /* Disk model / vendor, as STORAGE_DEVICE_DESCRIPTOR reports them. */
    {
        static const char *vendors[] = { "Samsung", "WDC", "KINGSTON", "Crucial", "SK hynix" };
        static const char *models[] = {
            "Samsung SSD 990 PRO 2TB",
            "WDC PC SN770 1TB",
            "KINGSTON SNV2S1000G",
            "Crucial P3 Plus 1TB",
            "SK hynix Platinum P41 1TB"
        };
        /* Real EUI-64s embed the vendor OUI, so keep them consistent. */
        static const BYTE ouis[][3] = {
            { 0x00, 0x25, 0x38 }, { 0x00, 0x1B, 0x44 }, { 0x00, 0x26, 0xB9 },
            { 0x00, 0xA0, 0x75 }, { 0x00, 0x25, 0x38 }
        };
        DWORD pick = NextRandom32() % 5;

        strcpy_s(cfg->DiskVendor, SYSINFO_MAX_STR, vendors[pick]);
        strcpy_s(cfg->DiskModel, SYSINFO_MAX_STR, models[pick]);
        memcpy(cfg->DiskEui64, ouis[pick], 3);
    }

    /* Memory modules: real SMBIOS serials look like 8 hex digits. */
    strcpy_s(cfg->DimmManufacturer, SYSINFO_MAX_STR, "Samsung");
    sprintf_s(cfg->DimmSerial, SYSINFO_MAX_STR, "%08X", NextRandom32());
    strcpy_s(cfg->DimmAsset, SYSINFO_MAX_STR, "");
    strcpy_s(cfg->DimmPart, SYSINFO_MAX_STR, "M378A1K43DB2-CTD");

    RandomGuid(guid, FALSE);

    AddString(cfg, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography",
              L"MachineGuid", guid);

    /* Windows Product ID: shown by Win32_OperatingSystem.SerialNumber too. */
    {
        char productId[40];
        sprintf_s(productId, sizeof(productId), "00342-%05u-%05u-AAOEM",
                  NextRandom32() % 100000, NextRandom32() % 100000);
        AddString(cfg, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                  L"ProductId", productId);
    }

    RandomGuid(guid, TRUE);
    /* Native paths never contain "CurrentControlSet": the object manager
     * resolves it to ControlSet00N, so the overrides have to use the same
     * shape or NtQueryKey's answer can never match. */
    ResolveControlSetPath();
    AddDiskFriendlyNames(cfg, cfg->DiskModel);

    {
        WCHAR key[160];

        swprintf_s(key, 160, L"%ls\\Control\\IDConfigDB\\Hardware Profiles\\0001", g_ControlSetPath);
        AddString(cfg, key, L"HwProfileGuid", guid);
    }

    /* keep the visible manufacturer text stable, vary what identifies the box */
    {
        WCHAR key[160];

        swprintf_s(key, 160, L"%s\\Control\\SystemInformation", g_ControlSetPath);
        AddString(cfg, key, L"SystemManufacturer", "System manufacturer");
        AddString(cfg, key, L"SystemProductName", v);
        AddString(cfg, key, L"SystemSerialNumber", cfg->SmbiosSerial);
        AddString(cfg, key, L"BIOSVersion", cfg->BiosVersion);
        AddString(cfg, key, L"BIOSReleaseDate", cfg->BiosDate);
    }

    AddString(cfg, L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS",
              L"SystemManufacturer", "System manufacturer");
    AddString(cfg, L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS",
              L"SystemProductName", v);
    AddString(cfg, L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS",
              L"SystemVersion", cfg->SmbiosVersion);
    AddString(cfg, L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS",
              L"SystemFamily", cfg->SmbiosFamily);
    AddString(cfg, L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS",
              L"SystemSerialNumber", cfg->SmbiosSerial);
    AddString(cfg, L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS",
              L"SystemSKU", cfg->SmbiosSku);
    AddString(cfg, L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS",
              L"BaseBoardManufacturer", "Base Board Manufacturer");
    AddString(cfg, L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS",
              L"BaseBoardProduct", v);
    AddString(cfg, L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS",
              L"BaseBoardVersion", cfg->BoardVersion);
    AddString(cfg, L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS",
              L"BIOSVendor", cfg->BiosVendor);
    AddString(cfg, L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS",
              L"BIOSVersion", cfg->BiosVersion);
    AddString(cfg, L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS",
              L"BIOSReleaseDate", cfg->BiosDate);

    /* One valid EDID base block; the driver serves it for every monitor read. */
    BuildFakeEdid(cfg);
}

static void GenerateDerivedRegs(SYSINFO_CONFIG *cfg);

static BOOL
ApplyOverride(SYSINFO_CONFIG *cfg, const char *key, const char *value)
{
    #define IS(k) (_stricmp(key, k) == 0)

    if (IS("seed")) { return TRUE; }
    else if (IS("machineguid")) {
        SYSINFO_REG_ENTRY *e;
        WCHAR wide[64];
        MultiByteToWideChar(CP_ACP, 0, value, -1, wide, 64);
        for (e = cfg->Reg, (void)0; e < cfg->Reg + cfg->RegCount; e++) {
            if (wcscmp(e->ValueName, L"MachineGuid") == 0) {
                e->DataLength = (ULONG)((wcslen(wide) + 1) * sizeof(WCHAR));
                if (e->DataLength > SYSINFO_MAX_DATA) e->DataLength = SYSINFO_MAX_DATA;
                memcpy(e->Data, wide, e->DataLength);
                return TRUE;
            }
        }
        return FALSE;
    }
    else if (IS("uuid")) {
        int a[16], i;
        if (sscanf_s(value, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                     &a[0], &a[1], &a[2], &a[3], &a[4], &a[5], &a[6], &a[7],
                     &a[8], &a[9], &a[10], &a[11], &a[12], &a[13], &a[14], &a[15]) == 16) {
            for (i = 0; i < 16; i++) cfg->SmbiosUuid[i] = (BYTE)a[i];
            return TRUE;
        }
        return FALSE;
    }
    else if (IS("disk"))  { strncpy_s(cfg->DiskSerial, SYSINFO_MAX_STR, value, _TRUNCATE); GenerateDerivedRegs(cfg); return TRUE; }
    else if (IS("serial")) { strncpy_s(cfg->SmbiosSerial, SYSINFO_MAX_STR, value, _TRUNCATE); GenerateDerivedRegs(cfg); return TRUE; }
    else if (IS("boardserial")) { strncpy_s(cfg->BoardSerial, SYSINFO_MAX_STR, value, _TRUNCATE); return TRUE; }
    else if (IS("chassis")) { strncpy_s(cfg->ChassisSerial, SYSINFO_MAX_STR, value, _TRUNCATE); return TRUE; }
    else if (IS("bios")) { strncpy_s(cfg->BiosVersion, SYSINFO_MAX_STR, value, _TRUNCATE); GenerateDerivedRegs(cfg); return TRUE; }
    else if (IS("volume")) { cfg->VolumeSerial = (ULONG)strtoul(value, NULL, 0); return TRUE; }
    else if (IS("mac")) {
        unsigned a[6];
        int i;
        if (sscanf_s(value, "%02x:%02x:%02x:%02x:%02x:%02x", &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]) == 6 ||
            sscanf_s(value, "%02x%02x%02x%02x%02x%02x", &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]) == 6) {
            for (i = 0; i < 6; i++) cfg->Mac[i] = (BYTE)a[i];
            return TRUE;
        }
        return FALSE;
    }
    return FALSE;
    #undef IS
}

/* Re-push values that mirror the SMBIOS strings into the registry list. */
static void
GenerateDerivedRegs(SYSINFO_CONFIG *cfg)
{
    ULONG i;
    for (i = 0; i < cfg->RegCount; i++) {
        SYSINFO_REG_ENTRY *e = &cfg->Reg[i];
        const char *src = NULL;

        if (wcscmp(e->ValueName, L"SystemSerialNumber") == 0) src = cfg->SmbiosSerial;
        if (wcscmp(e->ValueName, L"SystemSKU") == 0) src = cfg->SmbiosSku;
        if (wcscmp(e->ValueName, L"BIOSVersion") == 0) src = cfg->BiosVersion;
        if (wcscmp(e->ValueName, L"BIOSReleaseDate") == 0) src = cfg->BiosDate;
        if (src == NULL) continue;

        {
            WCHAR wide[64];
            MultiByteToWideChar(CP_ACP, 0, src, -1, wide, 64);
            e->DataLength = (ULONG)((wcslen(wide) + 1) * sizeof(WCHAR));
            if (e->DataLength > SYSINFO_MAX_DATA) e->DataLength = SYSINFO_MAX_DATA;
            memcpy(e->Data, wide, e->DataLength);
        }
    }
}

/* ------------------------------------------------------------------ driver I/O */

static HANDLE
OpenDriver(VOID)
{
    return CreateFileW(SYSINFO_WIN32_NAME, GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
}

static BOOL
SendSetConfig(HANDLE device, const SYSINFO_CONFIG *cfg)
{
    DWORD returned = 0;
    return DeviceIoControl(device, SYSINFO_IOCTL_SET_CONFIG, (LPVOID)cfg, sizeof(*cfg),
                           NULL, 0, &returned, NULL);
}

static void
PersistConfig(const SYSINFO_CONFIG *cfg)
{
    HKEY key;
    DWORD disposition;

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\" SYSINFO_SERVICE_NAME L"\\Parameters",
                        0, NULL, 0, KEY_WRITE, NULL, &key, &disposition) != ERROR_SUCCESS) {
        printf("  ! could not open the service Parameters key (run install first)\n");
        return;
    }
    if (RegSetValueExW(key, L"Config", 0, REG_BINARY, (const BYTE *)cfg, sizeof(*cfg)) != ERROR_SUCCESS) {
        printf("  ! could not persist the configuration\n");
    }
    RegCloseKey(key);
}

/* ------------------------------------------------------------------ repair */

/* A string entry that is empty or whitespace-only is a leak: it either exposes
 * the real value or, worse, is an anomaly no normal install has. */
static BOOLEAN
EntryIsEmpty(const SYSINFO_REG_ENTRY *e)
{
    ULONG i;

    if (e->DataLength == 0 || e->DataLength > SYSINFO_MAX_DATA) return TRUE;

    /* An override made of spaces is not a value: it is a blank that would leak
     * through and look like an anomaly.  A trailing NUL is optional here - the
     * broken entries that motivated this check had none. */
    if (e->Type == REG_SZ || e->Type == REG_EXPAND_SZ) {
        for (i = 0; i < e->DataLength; i++) {
            if (e->Data[i] != ' ' && e->Data[i] != 0) return FALSE;
        }
        return TRUE;
    }
    return FALSE;
}

static void
SetEntryString(SYSINFO_REG_ENTRY *e, const char *text)
{
    WCHAR wide[128];
    size_t chars;

    if (MultiByteToWideChar(CP_ACP, 0, text, -1, wide, RTL_NUMBER_OF(wide)) <= 0) return;
    chars = wcslen(wide) + 1;
    if (chars * sizeof(WCHAR) > SYSINFO_MAX_DATA) return;

    e->Type = REG_SZ;
    e->DataLength = (ULONG)(chars * sizeof(WCHAR));
    memset(e->Data, 0, sizeof(e->Data));
    memcpy(e->Data, wide, e->DataLength);
}

static BOOLEAN
FindEntry(SYSINFO_CONFIG *cfg, const WCHAR *valueName, SYSINFO_REG_ENTRY **found)
{
    ULONG i;

    for (i = 0; i < cfg->RegCount && i < SYSINFO_MAX_REG; i++) {
        if (_wcsicmp(cfg->Reg[i].ValueName, valueName) == 0) {
            *found = &cfg->Reg[i];
            return TRUE;
        }
    }
    *found = NULL;
    return FALSE;
}

static void
GuidToNarrow(const WCHAR *guid, char *out, size_t outChars)
{
    WideCharToMultiByte(CP_ACP, 0, guid, -1, out, (int)outChars, NULL, NULL);
}

/*
 * Fill in identity values that are missing rather than regenerating the whole
 * set: a repair must not change values that are already working, because the
 * game would see a brand-new fingerprint on every run.
 */
static int
CmdRepair(VOID)
{
    HANDLE device = OpenDriver();
    SYSINFO_CONFIG cfg;
    DWORD returned = 0;
    ULONG fixed = 0;
    char narrow[80];
    SYSINFO_REG_ENTRY *entry = NULL;

    if (device == INVALID_HANDLE_VALUE) {
        printf("driver: not running (%lu) - run elevated\n", GetLastError());
        return 1;
    }

    memset(&cfg, 0, sizeof(cfg));
    if (!DeviceIoControl(device, SYSINFO_IOCTL_GET_CONFIG, NULL, 0, &cfg, sizeof(cfg),
                         &returned, NULL)) {
        printf("could not read the configuration (%lu)\n", GetLastError());
        CloseHandle(device);
        return 1;
    }
    if (cfg.Size != sizeof(SYSINFO_CONFIG)) {
        printf("driver returned a %lu-byte configuration, expected %lu\n",
               (unsigned long)cfg.Size, (unsigned long)sizeof(SYSINFO_CONFIG));
        CloseHandle(device);
        return 1;
    }

    printf("repair: filling singleton identifiers that are missing\n");

    {
        ULONG i;

        for (i = 0; i < cfg.RegCount && i < SYSINFO_MAX_REG; i++) {
            const SYSINFO_REG_ENTRY *e = &cfg.Reg[i];
            char name[80], key[200];
            ULONG j;

            WideCharToMultiByte(CP_ACP, 0, e->ValueName, -1, name, sizeof(name), NULL, NULL);
            WideCharToMultiByte(CP_ACP, 0, e->KeyPath, -1, key, sizeof(key), NULL, NULL);
            printf("  reg[%02lu] \"%s\" nameLen=%lu type=%lu len=%-4lu\n", i, name,
                   (unsigned long)wcslen(e->ValueName), (unsigned long)e->Type,
                   (unsigned long)e->DataLength);
            printf("           keyLen=%lu key=\"%s\"\n", (unsigned long)wcslen(e->KeyPath), key);
            if (e->DataLength != 0 && e->DataLength <= 80) {
                printf("           data:");
                for (j = 0; j < e->DataLength; j++) printf(" %02X", e->Data[j]);
                printf("\n");
            }
        }
    }

    /*
     * Native key paths never contain "CurrentControlSet": the object manager
     * resolves it to ControlSet00N, and the hook compares what ZwQueryKey
     * returns.  An override stored with the unresolved name can therefore never
     * match - which is exactly how HwProfileGuid ended up serving the real
     * value.  Rewrite the whole class of them.
     */
    ResolveControlSetPath();
    {
        ULONG i;
        WCHAR rebuilt[SYSINFO_MAX_PATH];

        for (i = 0; i < cfg.RegCount && i < SYSINFO_MAX_REG; i++) {
            WCHAR *at = wcsstr(cfg.Reg[i].KeyPath, L"CurrentControlSet");

            if (at == NULL) continue;
            swprintf_s(rebuilt, SYSINFO_MAX_PATH, L"%s%s", g_ControlSetPath,
                       at + wcslen(L"CurrentControlSet"));
            if (_wcsicmp(rebuilt, cfg.Reg[i].KeyPath) != 0) {
                wcscpy_s(cfg.Reg[i].KeyPath, SYSINFO_MAX_PATH, rebuilt);
                printf("  key path      : fixed %ls\n", rebuilt);
                fixed++;
            }
        }
    }

    /* 1. Monitor identity: a monitor serial is unique and never changes. */
    if (cfg.EdidLength < 128 || cfg.EdidLength > SYSINFO_MAX_EDID) {
        ULONG was = cfg.EdidLength;

        BuildFakeEdid(&cfg);
        cfg.Flags |= SYSINFO_F_EDID;
        printf("  edid          : generated (was %lu bytes)\n", (unsigned long)was);
        fixed++;
    } else {
        printf("  edid          : already served (%lu bytes)\n", (unsigned long)cfg.EdidLength);
    }

    /* 2. Per-install GUIDs. */
    if (!FindEntry(&cfg, L"MachineGuid", &entry)) {
        RandomGuid(narrow, FALSE);
        AddString(&cfg, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography",
                  L"MachineGuid", narrow);
        printf("  MachineGuid   : added\n");
        fixed++;
    } else if (EntryIsEmpty(entry)) {
        RandomGuid(narrow, FALSE);
        SetEntryString(entry, narrow);
        printf("  MachineGuid   : regenerated\n");
        fixed++;
    } else {
        printf("  MachineGuid   : already spoofed\n");
    }

    if (!FindEntry(&cfg, L"HwProfileGuid", &entry)) {
        WCHAR key[160];

        RandomGuid(narrow, TRUE);
        ResolveControlSetPath();
        swprintf_s(key, 160, L"%ls\\Control\\IDConfigDB\\Hardware Profiles\\0001", g_ControlSetPath);
        AddString(&cfg, key, L"HwProfileGuid", narrow);
        printf("  HwProfileGuid : added\n");
        fixed++;
    } else if (EntryIsEmpty(entry)) {
        RandomGuid(narrow, TRUE);
        SetEntryString(entry, narrow);
        printf("  HwProfileGuid : regenerated (was blank)\n");
        fixed++;
    } else {
        printf("  HwProfileGuid : already spoofed\n");
    }

    if (fixed == 0) {
        printf("repair: nothing to do\n");
        CloseHandle(device);
        return 0;
    }

    if (!SendSetConfig(device, &cfg)) {
        printf("could not apply the configuration (%lu)\n", GetLastError());
        CloseHandle(device);
        return 1;
    }
    PersistConfig(&cfg);
    printf("repair: %lu identifier(s) filled in and applied\n", (unsigned long)fixed);
    CloseHandle(device);
    return 0;
}

/* Set one override to a known value, so "is the hook actually serving this?"
 * can be answered by reading it back through the normal registry API. */
static int
CmdSetReg(const char *name, const char *value)
{
    HANDLE device = OpenDriver();
    SYSINFO_CONFIG cfg;
    DWORD returned = 0;
    WCHAR wideName[SYSINFO_MAX_VALUE];
    SYSINFO_REG_ENTRY *entry = NULL;

    if (device == INVALID_HANDLE_VALUE) {
        printf("driver: not running (%lu) - run elevated\n", GetLastError());
        return 1;
    }
    if (name == NULL || value == NULL) {
        printf("usage: set <ValueName> <string>\n");
        CloseHandle(device);
        return 1;
    }

    memset(&cfg, 0, sizeof(cfg));
    if (!DeviceIoControl(device, SYSINFO_IOCTL_GET_CONFIG, NULL, 0, &cfg, sizeof(cfg),
                         &returned, NULL)) {
        printf("could not read the configuration (%lu)\n", GetLastError());
        CloseHandle(device);
        return 1;
    }

    MultiByteToWideChar(CP_ACP, 0, name, -1, wideName, SYSINFO_MAX_VALUE);
    if (!FindEntry(&cfg, wideName, &entry)) {
        printf("no override named '%s'\n", name);
        CloseHandle(device);
        return 1;
    }

    SetEntryString(entry, value);
    if (!SendSetConfig(device, &cfg)) {
        printf("could not apply (%lu)\n", GetLastError());
        CloseHandle(device);
        return 1;
    }
    PersistConfig(&cfg);
    printf("%s := %s (read it back to see whether the hook serves it)\n", name, value);
    CloseHandle(device);
    return 0;
}

/* Drop one override, so the real registry value is served instead.  Used for
 * identifiers that are now rotated for real (HwProfileGuid, ProductId): a
 * stale virtual override would keep shadowing the correct value. */
static int
CmdRemoveReg(const char *name)
{
    HANDLE device = OpenDriver();
    SYSINFO_CONFIG cfg;
    DWORD returned = 0;
    WCHAR wideName[SYSINFO_MAX_VALUE];
    ULONG i, found = 0xFFFFFFFFu;

    if (device == INVALID_HANDLE_VALUE) {
        printf("driver: not running (%lu) - start it first\n", GetLastError());
        return 1;
    }
    if (name == NULL) { printf("usage: remove <ValueName>\n"); CloseHandle(device); return 1; }

    memset(&cfg, 0, sizeof(cfg));
    if (!DeviceIoControl(device, SYSINFO_IOCTL_GET_CONFIG, NULL, 0, &cfg, sizeof(cfg),
                         &returned, NULL)) {
        printf("could not read the configuration (%lu)\n", GetLastError());
        CloseHandle(device);
        return 1;
    }

    MultiByteToWideChar(CP_ACP, 0, name, -1, wideName, SYSINFO_MAX_VALUE);
    for (i = 0; i < cfg.RegCount && i < SYSINFO_MAX_REG; i++) {
        if (_wcsicmp(cfg.Reg[i].ValueName, wideName) == 0) { found = i; break; }
    }
    if (found == 0xFFFFFFFFu) {
        printf("no override named '%s'\n", name);
        CloseHandle(device);
        return 1;
    }

    for (i = found; i + 1 < cfg.RegCount && i + 1 < SYSINFO_MAX_REG; i++) {
        cfg.Reg[i] = cfg.Reg[i + 1];
    }
    RtlZeroMemory(&cfg.Reg[cfg.RegCount - 1], sizeof(cfg.Reg[0]));
    cfg.RegCount--;

    if (!SendSetConfig(device, &cfg)) {
        printf("could not apply (%lu)\n", GetLastError());
        CloseHandle(device);
        return 1;
    }
    PersistConfig(&cfg);
    printf("removed override '%s'; the real registry value is now served\n", name);
    CloseHandle(device);
    return 0;
}

/* ------------------------------------------------------------------ commands */

static const char *
StageName(ULONG stage)
{
    switch (stage) {
    case SYSINFO_STAGE_NONE:     return "not attempted";
    case SYSINFO_STAGE_OK:       return "ok";
    case SYSINFO_STAGE_NO_ANCHOR:return "anchor export missing";
    case SYSINFO_STAGE_NO_SSN:   return "could not read a syscall number";
    case SYSINFO_STAGE_NO_IMAGE: return "ntoskrnl base not found";
    case SYSINFO_STAGE_NO_TEXT:  return "ntoskrnl .text not found";
    case SYSINFO_STAGE_IRQL:     return "not at PASSIVE_LEVEL";
    case SYSINFO_STAGE_NO_TABLE: return "no table layout matched";
    case SYSINFO_STAGE_HVCI:     return "blocked by Memory Integrity (HVCI)";
    case SYSINFO_STAGE_WRITE:    return "read-only kernel text could not be written";
    case SYSINFO_STAGE_HYPERVISOR: return "blocked by VBS/HyperGuard (hypervisor running)";
    default:                  return "?";
    }
}

static const char *
PatchMethodName(ULONG method)
{
    switch (method) {
    case SYSINFO_WRITE_MDL: return "writable MDL alias (works with CET)";
    case SYSINFO_WRITE_CR0: return "CR0.WP window";
    default:                return "none yet";
    }
}

/* ---- code integrity, shared by `status`, `preflight` and `install` ---- */

#define CI_QUERY_CLASS            103   /* SystemCodeIntegrityInformation */
#define CI_OPTION_TESTSIGNING     0x00000002u
#define CI_HVCI_KMCI_ENABLED      0x00000400u   /* CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED */
#define CI_HVCI_KMCI_AUDIT        0x00000800u   /* ..._AUDITMODE_ENABLED                 */
#define CI_HVCI_KMCI_STRICT       0x00001000u   /* ..._STRICTMODE_ENABLED                */
#define CI_HVCI_IUM               0x00002000u   /* ..._HVCI_IUM_ENABLED                  */

typedef LONG (NTAPI *PFN_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

static ULONG
QueryCodeIntegrityOptions(void)
{
    typedef struct { ULONG Length; ULONG CodeIntegrityOptions; } CI_INFO;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    PFN_NtQuerySystemInformation query;
    CI_INFO info;

    if (ntdll == NULL) return 0;
    query = (PFN_NtQuerySystemInformation)(void *)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (query == NULL) return 0;

    info.Length = sizeof(info);
    info.CodeIntegrityOptions = 0;
    if (query(CI_QUERY_CLASS, &info, sizeof(info), NULL) < 0) return 0;
    return info.CodeIntegrityOptions;
}

static int
HvciEnforced(ULONG ciOptions)
{
    if ((ciOptions & CI_HVCI_KMCI_ENABLED) && !(ciOptions & CI_HVCI_KMCI_AUDIT)) return 1;
    if (ciOptions & CI_HVCI_KMCI_STRICT) return 1;
    return 0;
}

static int
SecureBootOn(void)
{
    HKEY  key;
    DWORD value = 0, size = sizeof(value), type = 0;
    int   result = -1;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
                      0, KEY_QUERY_VALUE, &key) == ERROR_SUCCESS) {
        if (RegQueryValueExW(key, L"UEFISecureBootEnabled", NULL, &type,
                             (BYTE *)&value, &size) == ERROR_SUCCESS && type == REG_DWORD) {
            result = (int)value;
        }
        RegCloseKey(key);
    }
    return result;
}

static int
CmdStatus(VOID)
{
    HANDLE device = OpenDriver();
    SYSINFO_STATUS status;
    DWORD returned = 0;

    if (device == INVALID_HANDLE_VALUE) {
        printf("driver: not running (%lu)\n", GetLastError());
        return 1;
    }
    if (!DeviceIoControl(device, SYSINFO_IOCTL_STATUS, NULL, 0, &status, sizeof(status), &returned, NULL)) {
        printf("driver: running, but status failed (%lu) - stale .sys?\n", GetLastError());
        CloseHandle(device);
        return 1;
    }
    CloseHandle(device);

    if (status.AbiVersion != SYSINFO_ABI_VERSION) {
        printf("driver: ABI %lu, tool expects %u (stale .sys)\n", status.AbiVersion, SYSINFO_ABI_VERSION);
        return 1;
    }

    printf("driver: running, ABI %lu, hooks %lu/%d, config %s\n",
           status.AbiVersion, status.HooksInstalled, SYSINFO_HOOKS_TOTAL,
           status.HasConfig ? "loaded" : "empty");
    printf("syscall table: %s (stage %lu: %s)\n",
           status.Reserved == SYSINFO_STAGE_OK ? "calibrated" : "NOT found",
           status.Reserved, StageName(status.Reserved));
    printf("patch env:     code integrity 0x%08lX (%s), Memory Integrity %s, CET %s\n",
           (unsigned long)status.CiOptions,
           (status.CiOptions & CI_OPTION_TESTSIGNING) ? "test signing on" : "no test signing",
           status.HvciEnforced ? "ON" : "off",
           status.CetEnabled ? "on" : "off");
    printf("VBS/hypervisor: %s\n",
           CpuHypervisorPresent() ? "RUNNING (HyperGuard - inline hooks refused)" : "not running");
    printf("kernel text:   %s\n", PatchMethodName(status.PatchMethod));

    if (status.Reserved == SYSINFO_STAGE_HYPERVISOR) {
        printf("               a hypervisor is running; VBS/HyperGuard verifies kernel code\n"
               "               pages and any inline hook would bugcheck 0x18B later.\n"
               "               Turn VBS/Hyper-V off and reboot before expecting hooks.\n");
    }

    printf("diag: object %p  unload %p  section %p\n",
           (void *)(ULONG_PTR)status.Diag[0], (void *)(ULONG_PTR)status.Diag[1],
           (void *)(ULONG_PTR)status.Diag[2]);
    printf("      flags at entry 0x%lX  now 0x%lX\n",
           (unsigned long)(status.Diag[3] & 0xFFFFFFFFu),
           (unsigned long)(status.Diag[3] >> 32));
    printf("      ext %p  adddevice %p  start %p\n",
           (void *)(ULONG_PTR)status.Diag[4], (void *)(ULONG_PTR)status.Diag[5],
           (void *)(ULONG_PTR)status.Diag[6]);
    printf("      ssn %lu/%lu  table %p  mode %lu stride %lu\n",
           (unsigned long)(status.Diag[8] >> 32), (unsigned long)(status.Diag[8] & 0xFFFFFFFFu),
           (void *)(ULONG_PTR)status.Diag[9],
           (unsigned long)((status.Diag[7] >> 32) & 0xFF),
           (unsigned long)((status.Diag[7] >> 40) & 0xFF));
    printf("      ntA %p  ntB %p  zwA %p  zwB %p\n",
           (void *)(ULONG_PTR)status.Diag[10], (void *)(ULONG_PTR)status.Diag[11],
           (void *)(ULONG_PTR)status.Diag[12], (void *)(ULONG_PTR)status.Diag[13]);
    printf("      base %p  size 0x%lX  ntA-base 0x%lX  ntB-base 0x%lX\n",
           (void *)(ULONG_PTR)status.Diag[14], (unsigned long)status.Diag[15],
           (unsigned long)status.Diag[16], (unsigned long)status.Diag[17]);
    for (int k = 0; k < 12; k += 4) {
        printf("      +0x%X: %016llX %016llX %016llX %016llX\n",
               0xDB6E0 + 8 * k,
               (unsigned long long)status.Diag[18 + k], (unsigned long long)status.Diag[19 + k],
               (unsigned long long)status.Diag[20 + k], (unsigned long long)status.Diag[21 + k]);
    }
    printf("NtQueryValueKey detour: %lu calls, %lu key-name failures, %lu config misses, %lu rewritten\n",
           (unsigned long)status.Diag[SYSINFO_DIAG_STATS + 0],
           (unsigned long)status.Diag[SYSINFO_DIAG_STATS + 1],
           (unsigned long)status.Diag[SYSINFO_DIAG_STATS + 2],
           (unsigned long)status.Diag[SYSINFO_DIAG_STATS + 3]);
    printf("      last key-name failure: status 0x%08lX, returned %lu\n",
           (unsigned long)status.Diag[SYSINFO_DIAG_KEYSTATUS],
           (unsigned long)status.Diag[SYSINFO_DIAG_KEYRET]);
    printf("      query-key routine: %p (%s)\n",
           (void *)(ULONG_PTR)status.Diag[SYSINFO_DIAG_QKADDR],
           status.Diag[SYSINFO_DIAG_QKVIA] ? "service table" : "exported ZwQueryKey");
    printf("WMI SMBIOS:    mssmbios %p dispatch %p, %lu queries, buffer kind %lu len %lu, "
           "signature offset %ld, %lu rewritten (last status 0x%08lX)\n",
           (void *)(ULONG_PTR)status.Diag[SYSINFO_DIAG_WMI_DEV],
           (void *)(ULONG_PTR)status.Diag[SYSINFO_DIAG_WMI_MJ],
           (unsigned long)status.Diag[SYSINFO_DIAG_WMI_CALLS],
           (unsigned long)status.Diag[SYSINFO_DIAG_WMI_BUFKIND],
           (unsigned long)status.Diag[SYSINFO_DIAG_WMI_BUFLEN],
           (long)(int)status.Diag[SYSINFO_DIAG_WMI_HIT],
           (unsigned long)status.Diag[SYSINFO_DIAG_WMI_APPLIED],
           (unsigned long)status.Diag[SYSINFO_DIAG_WMI_STATUS]);
    printf("MONITOR        enabled %lu, %lu events queued, %lu dropped, "
           "callbacks 0x%lX (1=image 2=process 4=thread 8=handles)\n",
           (unsigned long)status.Diag[SYSINFO_DIAG_MON_ENABLED],
           (unsigned long)status.Diag[SYSINFO_DIAG_MON_EVENTS],
           (unsigned long)status.Diag[SYSINFO_DIAG_MON_DROPPED],
           (unsigned long)status.Diag[SYSINFO_DIAG_MON_HOOKS]);
    printf("               process/thread opens seen %lu, logged %lu\n",
           (unsigned long)status.Diag[SYSINFO_DIAG_MON_OPEN],
           (unsigned long)status.Diag[SYSINFO_DIAG_MON_OPEN_EV]);
    printf("TRACE          %lu syscall hooks (file/key/memory/kernel callbacks); unsafe implemented %s, enabled %s\n",
           (unsigned long)status.Diag[SYSINFO_DIAG_TRACE_HOOKS],
           status.UnsafeHooksImplemented ? "yes" : "no",
           status.UnsafeHooksEnabled ? "yes" : "no");
    printf("EDID           %lu reads served, config length %lu, mfg byte 0x%02lX\n",
           (unsigned long)(status.Diag[79] & 0xFFFF),
           (unsigned long)((status.Diag[79] >> 16) & 0xFF),
           (unsigned long)((status.Diag[79] >> 24) & 0xFF));
    printf("Ob callbacks:  0x%08lX\n", (unsigned long)status.Diag[SYSINFO_DIAG_OB_STATUS]);
    printf("WMI init:      status 0x%08lX, dispatch inside the provider image: %s, "
           "data-device IOCTLs seen: %lu\n",
           (unsigned long)status.Diag[SYSINFO_DIAG_WMI_INIT],
           status.Diag[SYSINFO_DIAG_WMI_INIMAGE] ? "yes" : "no",
           (unsigned long)status.Diag[SYSINFO_DIAG_WMI_IOCTL]);
    {
        WCHAR text[96];
        ULONG i, n = (ULONG)status.Diag[SYSINFO_DIAG_PATHLEN] / sizeof(WCHAR);

        if (n > 63) n = 63;
        for (i = 0; i < n; i++) {
            text[i] = (WCHAR)((status.Diag[SYSINFO_DIAG_PATH + i / 4] >> (16 * (i % 4))) & 0xFFFF);
        }
        text[n] = 0;
        if (n != 0) printf("      last unmatched key   : %ls\n", text);

        n = (ULONG)status.Diag[SYSINFO_DIAG_NAMELEN] / sizeof(WCHAR);
        if (n > 31) n = 31;
        for (i = 0; i < n; i++) {
            text[i] = (WCHAR)((status.Diag[SYSINFO_DIAG_NAME + i / 4] >> (16 * (i % 4))) & 0xFFFF);
        }
        text[n] = 0;
        if (n != 0) printf("      last unmatched value : %ls\n", text);
    }

    if (status.HooksInstalled != SYSINFO_HOOKS_TOTAL) {
        printf("\n");
        if (status.HvciEnforced) {
            printf("Memory Integrity (HVCI) is on.  It enforces W^X in the hypervisor, below\n"
                   "CR0.WP and below PTE permissions, so kernel text cannot be patched at all.\n"
                   "Turn it off, then reboot:\n"
                   "  Windows Security > Device security > Core isolation > Memory integrity = Off\n"
                   "  (or: HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\\n"
                   "       HypervisorEnforcedCodeIntegrity\\Enabled = 0)\n"
                   "Kernel shadow stacks (CET) may stay on - the driver writes through an MDL\n"
                   "alias and no longer needs CR0.WP.\n");
        } else if (status.Reserved == SYSINFO_STAGE_WRITE) {
            printf("Kernel text could not be written although HVCI is off; see DbgPrint.\n");
        } else if (status.Reserved == SYSINFO_STAGE_NO_TABLE) {
            printf("The syscall table layout was not recognised, so NtQueryValueKey/NtQueryKey\n"
                   "(not exported by this ntoskrnl) cannot be resolved.\n");
        }
    }
    return (status.HooksInstalled == SYSINFO_HOOKS_TOTAL) ? 0 : 2;
}

/* Checks the *machine*, not the driver, so it works before anything is
 * installed and tells the user what will block the driver. */
static int
CmdPreflight(VOID)
{
    ULONG ci = QueryCodeIntegrityOptions();
    int   secureBoot = SecureBootOn();
    int   hvci = HvciEnforced(ci);
    int   hv = CpuHypervisorPresent();
    int   testing = (ci & CI_OPTION_TESTSIGNING) != 0;
    int   ready = 1;

    printf("SysInfo preflight (no driver needed)\n\n");
    printf("  code integrity options   0x%08lX\n", (unsigned long)ci);
    printf("  test signing             %s\n", testing ? "on" : "OFF");

    if (secureBoot < 0) printf("  Secure Boot              unknown (state key not readable)\n");
    else                printf("  Secure Boot              %s\n", secureBoot ? "ON" : "off");

    printf("  Memory Integrity (HVCI)  %s\n", hvci ? "ON" : "off");
    printf("  VBS / hypervisor         %s\n",
           hv ? "RUNNING (HyperGuard verifies kernel text)" : "not running");

    if (!testing) {
        ready = 0;
        printf("\n  -> test signing is off: run install.cmd (it needs Secure Boot off).\n");
    }
    if (secureBoot == 1) {
        ready = 0;
        printf("\n  -> Secure Boot is on: bcdedit cannot enable test signing.  Disable\n"
               "     Secure Boot in the firmware and reboot.\n");
    }
    if (hvci) {
        ready = 0;
        printf("\n  -> Memory Integrity is on: the hypervisor keeps executable kernel pages\n"
               "     read-only, so the hooks cannot be installed.  Turn it off and reboot:\n"
               "       Windows Security > Device security > Core isolation > Memory integrity = Off\n");
    }
    if (hv && !hvci) {
        ready = 0;
        printf("\n  -> a hypervisor is running (VBS/HyperGuard).  Kernel code pages are\n"
               "     hash-verified, so an inline hook bugchecks 0x18B later, even if the\n"
               "     write succeeds.  Turn VBS off (and Hyper-V/Virtual Machine Platform if\n"
               "     unused), then reboot:\n"
               "       Windows Security > Device security > Core isolation > all Off\n"
               "       reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\WindowsHello\" /v Enabled /t REG_DWORD /d 0 /f\n"
               "       bcdedit /set hypervisorlaunchtype off\n"
               "       bcdedit /set vsmlaunchtype off\n"
               "     then reboot.  The driver refuses to hook while the hypervisor is present.\n");
    }

    printf("\n%s\n", ready ? "ready: this machine can load the driver and install the hooks."
                           : "NOT ready: fix the items above, then re-run this check.");
    return ready ? 0 : 1;
}

static void
HexDump(const unsigned char *p, ULONG length, ULONG64 address)
{
    ULONG i;
    for (i = 0; i < length; i += 16) {
        ULONG j, n = min(16u, length - i);
        printf("%016llX  ", (unsigned long long)(address + i));
        for (j = 0; j < 16; j++) printf(j < n ? "%02X " : "   ", p[i + j]);
        printf(" ");
        for (j = 0; j < n; j++) printf("%c", (p[i + j] >= 0x20 && p[i + j] < 0x7F) ? p[i + j] : '.');
        printf("\n");
    }
}

/* Read arbitrary kernel virtual memory through the driver.  With <file> the raw
 * bytes are written there, otherwise a hexdump is printed. */
static int
CmdRead(const char *addrText, const char *lenText, const char *file)
{
    HANDLE device;
    HANDLE out = INVALID_HANDLE_VALUE;
    unsigned char *buf;
    SYSINFO_READ_REQ req;
    ULONG64 address;
    ULONG length = 0x100, done = 0;

    if (addrText == NULL) { printf("usage: read <hexaddr> [len] [file]\n"); return 1; }
    address = _strtoui64(addrText, NULL, 16);
    if (lenText != NULL && lenText[0] != 0) length = (ULONG)_strtoui64(lenText, NULL, 0);
    if (length == 0) length = 0x100;

    device = OpenDriver();
    if (device == INVALID_HANDLE_VALUE) { printf("driver: not running (%lu)\n", GetLastError()); return 1; }

    buf = (unsigned char *)malloc(SYSINFO_READ_MAX);
    if (buf == NULL) { CloseHandle(device); return 1; }

    if (file != NULL && file[0] != 0) {
        out = CreateFileA(file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (out == INVALID_HANDLE_VALUE) printf("cannot write '%s' (%lu)\n", file, GetLastError());
    }

    while (done < length) {
        ULONG chunk = min((ULONG)SYSINFO_READ_MAX, length - done);
        DWORD returned = 0;

        req.Address = address + done;
        req.Length  = chunk;
        req.Pad     = 0;

        if (!DeviceIoControl(device, SYSINFO_IOCTL_READ_MEM, &req, sizeof(req),
                             buf, chunk, &returned, NULL)) {
            printf("read 0x%llX failed (%lu)\n", (unsigned long long)(address + done), GetLastError());
            break;
        }
        if (returned == 0) break;

        if (out != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(out, buf, returned, &written, NULL);
        } else {
            HexDump(buf, returned, address + done);
        }
        done += returned;
        if (returned < chunk) break;
    }

    if (out != INVALID_HANDLE_VALUE) { CloseHandle(out); printf("wrote %lu bytes to %s\n", done, file); }
    free(buf);
    CloseHandle(device);
    return 0;
}

static void
PrintConfig(const SYSINFO_CONFIG *cfg)
{
    char guid[40];
    printf("  flags          : 0x%02lX%s\n", cfg->Flags,
           cfg->Flags == SYSINFO_F_ALL ? " (all)" : "");
    sprintf_s(guid, sizeof(guid), "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
              cfg->SmbiosUuid[0], cfg->SmbiosUuid[1], cfg->SmbiosUuid[2], cfg->SmbiosUuid[3],
              cfg->SmbiosUuid[4], cfg->SmbiosUuid[5], cfg->SmbiosUuid[6], cfg->SmbiosUuid[7],
              cfg->SmbiosUuid[8], cfg->SmbiosUuid[9], cfg->SmbiosUuid[10], cfg->SmbiosUuid[11],
              cfg->SmbiosUuid[12], cfg->SmbiosUuid[13], cfg->SmbiosUuid[14], cfg->SmbiosUuid[15]);
    printf("  system uuid    : %s\n", guid);
    printf("  system maker   : %s / %s\n", cfg->SmbiosManufacturer, cfg->SmbiosProduct);
    printf("  system version : %s  family %s\n", cfg->SmbiosVersion, cfg->SmbiosFamily);
    printf("  board maker    : %s / %s (%s)\n", cfg->BoardManufacturer, cfg->BoardProduct, cfg->BoardVersion);
    printf("  system serial  : %s\n", cfg->SmbiosSerial);
    printf("  board serial   : %s\n", cfg->BoardSerial);
    printf("  dimm serial    : %s\n", cfg->DimmSerial);
    printf("  chassis serial : %s  (%s / %s)\n", cfg->ChassisSerial,
           cfg->ChassisManufacturer, cfg->ChassisVersion);
    printf("  bios           : %s %s  (%s)\n", cfg->BiosVendor, cfg->BiosVersion, cfg->BiosDate);
    printf("  disk serial    : %s\n", cfg->DiskSerial);
    printf("  disk model     : %s %s  fw %s\n", cfg->DiskVendor, cfg->DiskModel, cfg->DiskFirmware);
    printf("  disk unique id : eui.%02X%02X%02X%02X%02X%02X%02X%02X\n",
           cfg->DiskEui64[0], cfg->DiskEui64[1], cfg->DiskEui64[2], cfg->DiskEui64[3],
           cfg->DiskEui64[4], cfg->DiskEui64[5], cfg->DiskEui64[6], cfg->DiskEui64[7]);
    printf("  volume serial  : %08lX\n", cfg->VolumeSerial);
    printf("  mac            : %02X:%02X:%02X:%02X:%02X:%02X\n",
           cfg->Mac[0], cfg->Mac[1], cfg->Mac[2], cfg->Mac[3], cfg->Mac[4], cfg->Mac[5]);
    if (cfg->EdidLength >= 128 && cfg->EdidLength % 128 == 0) {
        WORD mfg = (WORD)((cfg->Edid[8] << 8) | cfg->Edid[9]);
        printf("  monitor edid   : %c%c%c%04X  serial %08lX  (%lu bytes)\n",
               '@' + ((mfg >> 10) & 0x1F), '@' + ((mfg >> 5) & 0x1F), '@' + (mfg & 0x1F),
               (unsigned)((cfg->Edid[10] | (cfg->Edid[11] << 8))),
               (unsigned long)(cfg->Edid[12] | (cfg->Edid[13] << 8) |
                               (cfg->Edid[14] << 16) | ((unsigned)cfg->Edid[15] << 24)),
               (unsigned long)cfg->EdidLength);
    } else {
        printf("  monitor edid   : not configured\n");
    }
    printf("  registry values: %lu\n", cfg->RegCount);
}

static int
CmdShow(VOID)
{
    HANDLE device = OpenDriver();
    SYSINFO_CONFIG cfg;
    DWORD returned = 0;

    if (device == INVALID_HANDLE_VALUE) { printf("driver not running\n"); return 1; }
    if (!DeviceIoControl(device, SYSINFO_IOCTL_GET_CONFIG, NULL, 0, &cfg, sizeof(cfg), &returned, NULL)) {
        printf("no configuration loaded (%lu)\n", GetLastError());
        CloseHandle(device);
        return 1;
    }
    CloseHandle(device);
    PrintConfig(&cfg);
    return 0;
}

/* ------------------------------------------------------------------ capture */

static void
DumpHex(FILE *f, const UCHAR *data, ULONG length)
{
    ULONG i, j;

    for (i = 0; i < length; i += 16) {
        fprintf(f, "%04lX  ", (unsigned long)i);
        for (j = 0; j < 16; j++) {
            if (i + j < length) fprintf(f, "%02X ", data[i + j]);
            else                fprintf(f, "   ");
        }
        fprintf(f, " ");
        for (j = 0; j < 16 && i + j < length; j++) {
            UCHAR c = data[i + j];
            fputc((c >= 0x20 && c < 0x7F) ? c : '.', f);
        }
        fputc('\n', f);
    }
}

static int
CmdCapture(const char *path)
{
    HANDLE device = OpenDriver();
    PSYSINFO_CAPTURE cap;
    DWORD returned = 0;
    const char *out = (path != NULL) ? path : "capture.txt";
    FILE *file = NULL;
    ULONG i;

    if (device == INVALID_HANDLE_VALUE) { printf("driver not running\n"); return 1; }

    cap = (PSYSINFO_CAPTURE)malloc(sizeof(*cap));
    if (cap == NULL) { printf("out of memory\n"); CloseHandle(device); return 1; }
    memset(cap, 0, sizeof(*cap));

    if (!DeviceIoControl(device, SYSINFO_IOCTL_CAPTURE, NULL, 0, cap, sizeof(*cap), &returned, NULL)) {
        printf("capture failed (%lu)\n", GetLastError());
        free(cap);
        CloseHandle(device);
        return 1;
    }
    CloseHandle(device);

    printf("%lu captured buffer(s)\n", (unsigned long)cap->Count);
    for (i = 0; i < cap->Count && i < SYSINFO_CAPTURE_SLOTS; i++) {
        PSYSINFO_CAPTURE_ENTRY e = &cap->Entry[i];
        if (e->Kind == 0) continue;
        printf("  [%lu] kind=%lu code=0x%08lX in=%lu out=%lu aux=0x%lX %ls\n",
               (unsigned long)i, (unsigned long)e->Kind, (unsigned long)e->Code,
               (unsigned long)e->InLength, (unsigned long)e->OutLength,
               (unsigned long)e->Aux, e->Path);
    }

    if (fopen_s(&file, out, "w") != 0 || file == NULL) {
        printf("cannot write %s\n", out);
        free(cap);
        return 1;
    }
    for (i = 0; i < cap->Count && i < SYSINFO_CAPTURE_SLOTS; i++) {
        PSYSINFO_CAPTURE_ENTRY e = &cap->Entry[i];
        if (e->Kind == 0) continue;
        fprintf(file, "=== entry %lu: kind=%lu code=0x%08lX in=%lu out=%lu aux=0x%lX path=%ls\n",
                (unsigned long)i, (unsigned long)e->Kind, (unsigned long)e->Code,
                (unsigned long)e->InLength, (unsigned long)e->OutLength,
                (unsigned long)e->Aux, e->Path);
        if (e->InLength != 0) {
            fprintf(file, "--- input (%lu bytes) ---\n", (unsigned long)e->InLength);
            DumpHex(file, e->In, e->InLength);
            fprintf(file, "\n");
        }
        if (e->OutLength != 0) {
            fprintf(file, "--- output (%lu bytes) ---\n", (unsigned long)e->OutLength);
            DumpHex(file, e->Out, e->OutLength);
        }
        fprintf(file, "\n");
    }
    fclose(file);
    free(cap);
    printf("wrote %s\n", out);
    return 0;
}

/* ---------------------------------------------------------------- monitor */

/*
 * The EDID the driver serves for <...>\Enum\DISPLAY\<pnp>\<inst>\Device
 * Parameters\EDID.  WmiMonitorID is a separate path (the monitor class driver
 * takes the descriptor from the display miniport, not from the registry), so
 * this is what registry-reading tools see.
 */
static int
CmdEdid(const char *action, const char *path)
{
    HANDLE device = OpenDriver();
    SYSINFO_CONFIG cfg;
    DWORD returned = 0;
    FILE *file;
    ULONG i;

    if (device == INVALID_HANDLE_VALUE) { printf("driver not running\n"); return 1; }
    if (!DeviceIoControl(device, SYSINFO_IOCTL_GET_CONFIG, NULL, 0, &cfg, sizeof(cfg), &returned, NULL)) {
        printf("no configuration loaded (%lu)\n", GetLastError());
        CloseHandle(device);
        return 1;
    }
    CloseHandle(device);

    if (cfg.EdidLength < 128 || cfg.EdidLength > SYSINFO_MAX_EDID || cfg.EdidLength % 128 != 0) {
        printf("no monitor EDID in the configuration (run 'sysinfoctl random')\n");
        return 1;
    }

    if (action != NULL && _stricmp(action, "save") == 0) {
        const char *out = (path != NULL) ? path : "edid.bin";
        if (fopen_s(&file, out, "wb") != 0 || file == NULL) {
            printf("cannot write %s\n", out);
            return 1;
        }
        fwrite(cfg.Edid, 1, cfg.EdidLength, file);
        fclose(file);
        printf("wrote %lu bytes to %s\n", (unsigned long)cfg.EdidLength, out);
        return 0;
    }

    printf("monitor EDID served by the driver (%lu bytes):\n", (unsigned long)cfg.EdidLength);
    for (i = 0; i < cfg.EdidLength; i++) {
        printf("%02X%s", cfg.Edid[i], ((i & 15) == 15) ? "\n" : " ");
    }
    if (cfg.EdidLength % 16 != 0) printf("\n");
    printf("  manufacturer : %c%c%c\n",
           '@' + (((cfg.Edid[8] << 8 | cfg.Edid[9]) >> 10) & 0x1F),
           '@' + (((cfg.Edid[8] << 8 | cfg.Edid[9]) >> 5) & 0x1F),
           '@' + ((cfg.Edid[8] << 8 | cfg.Edid[9]) & 0x1F));
    printf("  product code : %04X\n", cfg.Edid[10] | (cfg.Edid[11] << 8));
    printf("  serial       : %08lX\n",
           (unsigned long)(cfg.Edid[12] | (cfg.Edid[13] << 8) |
                           (cfg.Edid[14] << 16) | ((unsigned)cfg.Edid[15] << 24)));
    printf("  week/year    : %u / %u\n", cfg.Edid[16], 1990 + cfg.Edid[17]);
    return 0;
}

static int
CmdApply(ULONGLONG seed, int argc, char **argv, BOOL persist)
{
    SYSINFO_CONFIG cfg;
    HANDLE device;
    int i;

    BuildConfig(seed, &cfg);
    for (i = 0; i < argc; i++) {
        char *eq = strchr(argv[i], '=');
        char key[32], value[128];
        if (eq == NULL) { printf("ignoring '%s' (expected key=value)\n", argv[i]); continue; }
        *eq = 0;
        strncpy_s(key, sizeof(key), argv[i], _TRUNCATE);
        strncpy_s(value, sizeof(value), eq + 1, _TRUNCATE);
        *eq = '=';
        if (!ApplyOverride(&cfg, key, value)) printf("  ! unknown or invalid override: %s\n", key);
    }

    device = OpenDriver();
    if (device == INVALID_HANDLE_VALUE) {
        printf("driver not running (%lu)\n", GetLastError());
        return 1;
    }
    if (!SendSetConfig(device, &cfg)) {
        printf("SET_CONFIG failed (%lu)\n", GetLastError());
        CloseHandle(device);
        return 1;
    }
    CloseHandle(device);

    if (persist) PersistConfig(&cfg);
    printf("applied (seed %llu):\n", seed);
    PrintConfig(&cfg);

    /* Win32_* WMI classes cache these values; make them re-read. */
    RefreshWmi();
    return 0;
}

static int
CmdClear(VOID)
{
    SYSINFO_CONFIG cfg;
    HANDLE device;

    memset(&cfg, 0, sizeof(cfg));
    cfg.Size = sizeof(SYSINFO_CONFIG);

    device = OpenDriver();
    if (device == INVALID_HANDLE_VALUE) { printf("driver not running\n"); return 1; }
    if (!SendSetConfig(device, &cfg)) { printf("SET_CONFIG failed (%lu)\n", GetLastError()); CloseHandle(device); return 1; }
    CloseHandle(device);
    PersistConfig(&cfg);
    printf("remapping disabled (real hardware IDs are shown again)\n");
    RefreshWmi();
    return 0;
}

/* ---------------------------------------------------------------- hostname */

/*
 * The computer name is not a spoofable identifier: GetComputerNameEx, the
 * COMPUTERNAME environment block, WMI's Win32_ComputerSystem.Name and the
 * NetBIOS/DNS names all come from the machine's real name, cached in the
 * kernel and in each process's environment.  Changing it for real is the only
 * complete answer - SetComputerNameExW writes it, a reboot applies it.
 */
static int
CmdHostname(const char *name)
{
    WCHAR wide[64];
    DWORD size = 64;
    int ok;

    if (name == NULL || name[0] == 0) {
        if (GetComputerNameExW(ComputerNamePhysicalDnsHostname, wide, &size)) {
            printf("computer name: %ls\n", wide);
            return 0;
        }
        printf("could not read the computer name (%lu)\n", GetLastError());
        return 1;
    }

    if (MultiByteToWideChar(CP_ACP, 0, name, -1, wide, 64) <= 1) {
        printf("bad name '%s'\n", name);
        return 1;
    }

    ok = SetComputerNameExW(ComputerNamePhysicalDnsHostname, wide) != 0;
    if (!ok) {
        printf("SetComputerNameEx failed (%lu)\n", GetLastError());
        return 1;
    }

    printf("computer name set to '%ls' - reboot for it to take effect everywhere\n", wide);
    printf("(this also changes the NetBIOS name, DNS hostname and %%COMPUTERNAME%%)\n");
    return 0;
}

/* --------------------------------------------------------------------- WMI */

/*
 * cimwin32 keeps the SMBIOS-derived Win32_* instances in memory for the life of
 * the WMI service, so a new identity (or turning remapping off) is invisible to
 * Win32_ComputerSystemProduct / BaseBoard / BIOS / PhysicalMemory until the
 * service restarts.  Restart it here so everything agrees immediately.
 */
static void
RefreshWmi(VOID)
{
    SC_HANDLE scm, service;
    SERVICE_STATUS status;
    BOOL restarted = FALSE;

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL) return;

    service = OpenServiceW(scm, L"Winmgmt", SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS);
    if (service != NULL) {
        int i;

        if (ControlService(service, SERVICE_CONTROL_STOP, &status)) {
            for (i = 0; i < 75; i++) {
                Sleep(200);
                if (!QueryServiceStatus(service, &status)) break;
                if (status.dwCurrentState == SERVICE_STOPPED) break;
            }
            restarted = StartServiceW(service, 0, NULL) != FALSE;
            if (!restarted && GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) restarted = TRUE;
        }
        CloseServiceHandle(service);
    }
    CloseServiceHandle(scm);

    if (restarted) {
        printf("  WMI service restarted - Win32_* classes now show this identity\n");
    } else {
        printf("  note: restart the WMI service (or reboot) if Win32_* classes still show the old values\n");
    }
}

/* ------------------------------------------------------------------- verify */

static void
ReadRegString(const WCHAR *subkey, const WCHAR *value, char *out, DWORD outLen)
{
    HKEY key;
    WCHAR wide[256];
    DWORD size = sizeof(wide), type = 0;

    out[0] = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return;
    if (RegQueryValueExW(key, value, NULL, &type, (BYTE *)wide, &size) == ERROR_SUCCESS && type == REG_SZ) {
        WideCharToMultiByte(CP_ACP, 0, wide, -1, out, outLen, NULL, NULL);
    }
    RegCloseKey(key);
}

/* index-th (1-based) string of the structure at `p`. */
static const char *
SmbiosString(const BYTE *p, const BYTE *end, int index, char *buffer, size_t bufferChars)
{
    const BYTE *s;
    int n = 1;
    size_t len;

    buffer[0] = 0;
    if (index == 0) return buffer;

    s = p + p[1];
    while (s < end && *s != 0) {
        if (n == index) {
            const BYTE *q = s;
            while (q < end && *q != 0) q++;
            len = (size_t)(q - s);
            if (len >= bufferChars) len = bufferChars - 1;
            memcpy(buffer, s, len);
            buffer[len] = 0;
            return buffer;
        }
        while (s < end && *s != 0) s++;
        s++;
        n++;
    }
    return buffer;
}

static void
VerifySmbios(VOID)
{
    DWORD size = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    BYTE *table;
    const BYTE *p, *end;
    DWORD got;
    ULONG epLen, tableLen;
    char text[64];

    if (size == 0) { printf("  smbios table   : unavailable\n"); return; }
    table = (BYTE *)malloc(size);
    if (table == NULL) return;
    got = GetSystemFirmwareTable('RSMB', 0, table, size);
    if (got == 0) { free(table); return; }

    /* Same two shapes the driver accepts (see driver/smbios.c). */
    if (memcmp(table, "_SM_", 4) == 0) {
        epLen = table[5];
        tableLen = *(USHORT *)(table + 0x16);
    } else if (got >= 8) {
        epLen = 8;                                  /* mssmbios raw block */
        tableLen = *(ULONG *)(table + 4);
    } else {
        free(table);
        return;
    }
    if (epLen < 8 || epLen >= got) { free(table); return; }
    if (tableLen == 0 || epLen + tableLen > got) tableLen = got - epLen;

    p = table + epLen;
    end = p + tableLen;
    while (p + 4 <= end && p[1] >= 4) {
        const BYTE *next = p + p[1];

        while (next + 2 <= end && !(next[0] == 0 && next[1] == 0)) next++;
        next += 2;

        if (p[0] == 0) {
            char version[64], date[64];

            SmbiosString(p, end, p[5], version, sizeof(version));
            SmbiosString(p, end, p[8], date, sizeof(date));
            printf("  bios version   : %s (%s)\n", version, date);
        } else if (p[0] == 1 && p[1] >= 0x18) {
            char maker[64], product[64], serial[64];

            SmbiosString(p, end, p[4], maker, sizeof(maker));
            SmbiosString(p, end, p[5], product, sizeof(product));
            SmbiosString(p, end, p[7], serial, sizeof(serial));
            printf("  smbios uuid    : %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
                   p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15],
                   p[16], p[17], p[18], p[19], p[20], p[21], p[22], p[23]);
            printf("  smbios maker   : %s / %s\n", maker, product);
            printf("  smbios serial  : %s\n", serial);
        } else if (p[0] == 2) {
            char maker[64], product[64];

            SmbiosString(p, end, p[4], maker, sizeof(maker));
            SmbiosString(p, end, p[5], product, sizeof(product));
            printf("  board maker    : %s / %s\n", maker, product);
            printf("  board serial   : %s\n", SmbiosString(p, end, p[7], text, sizeof(text)));
        } else if (p[0] == 3) {
            printf("  chassis serial : %s\n", SmbiosString(p, end, p[7], text, sizeof(text)));
        } else if (p[0] == 17 && p[1] >= 0x1B) {
            printf("  dimm serial    : %s\n", SmbiosString(p, end, p[0x18], text, sizeof(text)));
        }

        if (next <= p || next > end) break;
        p = next;
    }
    free(table);
}

static void
VerifyDisk(VOID)
{
    HANDLE drive = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    BYTE buffer[1024];
    STORAGE_PROPERTY_QUERY query = { 0, 0, { 0 } };
    DWORD returned = 0;

    if (drive == INVALID_HANDLE_VALUE) { printf("  disk serial    : open failed\n"); return; }
    memset(buffer, 0, sizeof(buffer));
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;
    if (DeviceIoControl(drive, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
                        buffer, sizeof(buffer), &returned, NULL)) {
        STORAGE_DEVICE_DESCRIPTOR *desc = (STORAGE_DEVICE_DESCRIPTOR *)buffer;
        if (desc->SerialNumberOffset != 0 && desc->SerialNumberOffset < sizeof(buffer)) {
            printf("  disk serial    : %s\n", (char *)buffer + desc->SerialNumberOffset);
        if (desc->ProductIdOffset != 0 && desc->ProductIdOffset < sizeof(buffer)) {
            printf("  disk model     : %s\n", (char *)buffer + desc->ProductIdOffset);
        }
        }
    } else {
        printf("  disk serial    : ioctl failed (%lu)\n", GetLastError());
    }
    CloseHandle(drive);
}

static int
CmdVerify(VOID)
{
    char value[256];
    DWORD serial = 0;
    char volumeName[MAX_PATH + 1] = { 0 };
    char fsName[64] = { 0 };

    printf("what the OS reports back through the hooks:\n");

    ReadRegString(L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid", value, sizeof(value));
    printf("  machine guid   : %s\n", value[0] ? value : "(unreadable)");

    VerifySmbios();
    VerifyDisk();

    if (GetVolumeInformationA("C:\\", volumeName, MAX_PATH, &serial, NULL, NULL, fsName, 64)) {
        printf("  volume serial  : %08lX\n", serial);
    } else {
        printf("  volume serial  : unreadable\n");
    }
    return 0;
}

/* ------------------------------------------------------------------ service */

static DWORD
CopyDriverFile(const char *sourcePath, WCHAR *target, DWORD targetChars)
{
    WCHAR systemDir[MAX_PATH];
    DWORD len;

    if (sourcePath == NULL) {
        GetModuleFileNameA(NULL, (char *)target, 0);   /* placeholder, replaced below */
        len = GetModuleFileNameA(NULL, (char *)target, MAX_PATH);
        if (len == 0) return ERROR_FILE_NOT_FOUND;
    }
    GetSystemDirectoryW(systemDir, MAX_PATH);

    if (sourcePath == NULL) {
        char module[MAX_PATH];
        char *slash;
        GetModuleFileNameA(NULL, module, MAX_PATH);
        slash = strrchr(module, '\\');
        if (slash != NULL) {
            strcpy_s(slash + 1, MAX_PATH - (slash - module) - 1, "SysInfo.sys");
        }
        MultiByteToWideChar(CP_ACP, 0, module, -1, target, targetChars);
    } else {
        WCHAR wide[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, sourcePath, -1, wide, MAX_PATH);
        if (!CopyFileW(wide, target, FALSE)) { /* caller checks */ }
        swprintf_s(target, targetChars, L"%s\\drivers\\SysInfo.sys", systemDir);
        MultiByteToWideChar(CP_ACP, 0, sourcePath, -1, wide, MAX_PATH);
        if (!CopyFileW(wide, target, FALSE)) return GetLastError();
        return ERROR_SUCCESS;
    }

    swprintf_s(target, targetChars, L"%s\\drivers\\SysInfo.sys", systemDir);
    {
        WCHAR sib[MAX_PATH];
        swprintf_s(sib, MAX_PATH, L"%s", target);
        sib[wcslen(sib) - 4] = 0;
        wcscat_s(sib, MAX_PATH, L".sys");
    }
    return ERROR_SUCCESS;
}

static int
CmdInstall(const char *source)
{
    WCHAR target[MAX_PATH];
    char module[MAX_PATH];
    WCHAR wide[MAX_PATH];
    SC_HANDLE scm, service;
    DWORD error;

    GetSystemDirectoryW(target, MAX_PATH);
    if (source == NULL) {
        char *slash;
        GetModuleFileNameA(NULL, module, MAX_PATH);
        slash = strrchr(module, '\\');
        if (slash != NULL) strcpy_s(slash + 1, MAX_PATH - (DWORD)(slash - module) - 1, "SysInfo.sys");
    } else {
        strcpy_s(module, MAX_PATH, source);
    }
    MultiByteToWideChar(CP_ACP, 0, module, -1, wide, MAX_PATH);

    {
        WCHAR dest[MAX_PATH];
        swprintf_s(dest, MAX_PATH, L"%s\\drivers\\SysInfo.sys", target);

        if (!CopyFileW(wide, dest, FALSE)) {
            error = GetLastError();
            if (error == ERROR_SHARING_VIOLATION || error == ERROR_ACCESS_DENIED) {
                /* a loaded driver image keeps its .sys open - unload it first */
                printf("'%ls' is in use, unloading the running driver\n", dest);
                CmdUnload(NULL);
                Sleep(200);
            }
        }
        if (!CopyFileW(wide, dest, FALSE)) {
            error = GetLastError();
            printf("copy '%ls' -> '%ls' failed (%lu)\n", wide, dest, error);
            return 1;
        }
        printf("installed %ls\n", dest);
        if (HvciEnforced(QueryCodeIntegrityOptions())) {
            printf("note: Memory Integrity (HVCI) is on - the driver will start but cannot install\n"
                   "      its hooks.  Turn it off and reboot (see: sysinfoctl preflight).\n");
        }
        wcscpy_s(target, MAX_PATH, dest);
    }

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm == NULL) { printf("OpenSCManager failed (%lu) - run elevated\n", GetLastError()); return 1; }

    service = CreateServiceW(scm, SYSINFO_SERVICE_NAME, SYSINFO_SERVICE_NAME, SERVICE_ALL_ACCESS,
                             SERVICE_KERNEL_DRIVER, SERVICE_SYSTEM_START, SERVICE_ERROR_NORMAL,
                             target, NULL, NULL, NULL, NULL, NULL);
    if (service == NULL) {
        error = GetLastError();
        if (error == ERROR_SERVICE_EXISTS) {
            service = OpenServiceW(scm, SYSINFO_SERVICE_NAME, SERVICE_ALL_ACCESS);
            if (service != NULL) ChangeServiceConfigW(service, SERVICE_NO_CHANGE, SERVICE_SYSTEM_START,
                                                      SERVICE_NO_CHANGE, target, NULL, NULL, NULL, NULL, NULL, SYSINFO_SERVICE_NAME);
            printf("service already existed; path updated\n");
        } else {
            printf("CreateService failed (%lu)\n", error);
            CloseServiceHandle(scm);
            return 1;
        }
    } else {
        printf("service created (system start)\n");
    }

    if (service != NULL) {
        if (!StartServiceW(service, 0, NULL)) {
            error = GetLastError();
            printf(error == ERROR_SERVICE_ALREADY_RUNNING ? "driver already running\n"
                                                          : "start failed (%lu)\n", error);
        } else {
            printf("driver started\n");
        }
        CloseServiceHandle(service);
    }
    CloseServiceHandle(scm);
    return 0;
}

static int
CmdService(int start)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    SC_HANDLE service;
    SERVICE_STATUS status;

    if (scm == NULL) { printf("OpenSCManager failed (%lu) - run elevated\n", GetLastError()); return 1; }
    service = OpenServiceW(scm, SYSINFO_SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (service == NULL) { printf("service not installed (%lu)\n", GetLastError()); CloseServiceHandle(scm); return 1; }

    if (start) {
        if (StartServiceW(service, 0, NULL)) printf("started\n");
        else {
            DWORD error = GetLastError();
            printf(error == ERROR_SERVICE_ALREADY_RUNNING ? "already running\n" : "start failed (%lu)\n", error);
        }
    } else {
        if (ControlService(service, SERVICE_CONTROL_STOP, &status)) printf("stopped\n");
        else printf("stop failed (%lu)\n", GetLastError());
    }
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return 0;
}

/*
 * Enable a privilege in the current token.  NtUnloadDriver requires
 * SeLoadDriverPrivilege, which an elevated admin token holds but keeps
 * disabled until asked for.
 */
static int
EnablePrivilege(LPCWSTR name)
{
    HANDLE token;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        printf("OpenProcessToken failed (%lu)\n", GetLastError());
        return 0;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueW(NULL, name, &tp.Privileges[0].Luid)) {
        printf("LookupPrivilegeValue(%ls) failed (%lu)\n", name, GetLastError());
        CloseHandle(token);
        return 0;
    }

    SetLastError(ERROR_SUCCESS);
    if (!AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL) || GetLastError() != ERROR_SUCCESS) {
        printf("could not enable %ls (%lu)\n", name, GetLastError());
        CloseHandle(token);
        return 0;
    }

    CloseHandle(token);
    return 1;
}

/*
 * Force an unload through ntdll, skipping SCM's "controls accepted" check.
 * SCM reports the driver as NOT_STOPPABLE, but NtUnloadDriver works whenever the
 * driver has a DriverUnload routine - which this one does.
 *
 * Two name forms are tried: the service key path (documented) and the driver
 * object path.  A driver with no unload routine answers 0xC0000010.
 */
static int
CmdUnload(_In_opt_ PCSTR only)
{
    typedef LONG (NTAPI *PFN_NtUnloadDriver)(PVOID);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    PFN_NtUnloadDriver unload;
    struct { USHORT Length, MaximumLength; PWSTR Buffer; } name;
    WCHAR path[160];
    WCHAR path2[160];
    LONG status = 0;
    int i, n;

    static const WCHAR *forms[] = {
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" SYSINFO_SERVICE_NAME,
        L"\\Driver\\" SYSINFO_SERVICE_NAME,
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services",
        L"\\Driver\\NoSuchXyz",
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\NoSuchXyz",
    };

    if (ntdll == NULL) { printf("ntdll not loaded\n"); return 1; }
    unload = (PFN_NtUnloadDriver)(void *)GetProcAddress(ntdll, "NtUnloadDriver");
    if (unload == NULL) { printf("NtUnloadDriver not found\n"); return 1; }

    (VOID)status;
    EnablePrivilege(L"SeLoadDriverPrivilege");

    if (only != NULL && only[0] != 0) {
        n = 1;
    } else {
        n = (int)(sizeof(forms) / sizeof(forms[0]));
    }

    for (i = 0; i < n; i++) {
        if (only != NULL && only[0] != 0) {
            MultiByteToWideChar(CP_ACP, 0, only, -1, path2, 160);
            wcscpy_s(path, 160, path2);
        } else {
            wcscpy_s(path, 160, forms[i]);
        }

        name.Buffer = path;
        name.Length = (USHORT)(wcslen(path) * sizeof(WCHAR));
        name.MaximumLength = (USHORT)(name.Length + sizeof(WCHAR));

        status = unload(&name);
        printf("  unload '%ls' -> 0x%08lX\n", path, (unsigned long)status);
        if (status >= 0) { printf("unloaded\n"); return 0; }
    }

    return 1;
}

static int
CmdUninstall(VOID)
{
    WCHAR path[MAX_PATH] = { 0 };
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    SC_HANDLE service;
    SERVICE_STATUS status;
    int result = 0;

    if (scm != NULL) {
        service = OpenServiceW(scm, SYSINFO_SERVICE_NAME, SERVICE_ALL_ACCESS);
        if (service != NULL) {
            ControlService(service, SERVICE_CONTROL_STOP, &status);
            if (DeleteService(service)) printf("service deleted\n");
            else printf("DeleteService failed (%lu)\n", GetLastError());
            CloseServiceHandle(service);
        } else {
            printf("service not installed\n");
        }
        CloseServiceHandle(scm);
    } else {
        printf("OpenSCManager failed (%lu) - run elevated\n", GetLastError());
        result = 1;
    }

    GetSystemDirectoryW(path, MAX_PATH);
    wcscat_s(path, MAX_PATH, L"\\drivers\\SysInfo.sys");
    if (DeleteFileW(path)) printf("removed %ls\n", path);
    else if (GetLastError() != ERROR_FILE_NOT_FOUND) {
        printf("could not delete %ls (%lu) - it may be in use until reboot\n", path, GetLastError());
    }

    RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\" SYSINFO_SERVICE_NAME);
    return result;
}

/* --------------------------------------------------------------------- MAC */

/*
 * The spoofed MAC only covers the legacy NDIS IOCTL.  Everything modern
 * (GetAdaptersAddresses, Get-NetAdapter, Win32_NetworkAdapter) reads the
 * address the miniport actually uses, so the only way to change what they see
 * is to make the adapter use a different address: the documented NDIS
 * "NetworkAddress" value in the adapter's class key, then restart the adapter.
 */
static int
CmdMac(ULONG apply)
{
    static const WCHAR classRoot[] =
        L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}";
    HANDLE device = OpenDriver();
    SYSINFO_CONFIG cfg;
    DWORD returned = 0;
    HKEY root;
    int changed = 0;
    int applied = 0;

    if (device == INVALID_HANDLE_VALUE) {
        printf("driver: not running (%lu) - run elevated\n", GetLastError());
        return 1;
    }
    if (!DeviceIoControl(device, SYSINFO_IOCTL_GET_CONFIG, NULL, 0, &cfg, sizeof(cfg), &returned, NULL)) {
        printf("could not read the configuration (%lu)\n", GetLastError());
        CloseHandle(device);
        return 1;
    }
    CloseHandle(device);

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, classRoot, 0, KEY_READ | KEY_WRITE, &root) != ERROR_SUCCESS) {
        printf("cannot open the network class key (%lu)\n", GetLastError());
        return 1;
    }

    for (unsigned i = 0; i < 32; i++) {
        WCHAR sub[8];
        HKEY  key;
        WCHAR guid[64];
        DWORD guidSize = sizeof(guid), type = 0;

        swprintf_s(sub, 8, L"%04u", i);
        if (RegOpenKeyExW(root, sub, 0, KEY_READ | KEY_WRITE, &key) != ERROR_SUCCESS) continue;

        if (RegQueryValueExW(key, L"NetCfgInstanceId", NULL, &type, (BYTE *)guid, &guidSize) != ERROR_SUCCESS) {
            RegCloseKey(key);
            continue;
        }

        /* Leave WAN miniports, VPN/TUN devices, Bluetooth PAN and virtual
         * adapters alone; NetworkAddress is only meaningful for real NICs. */
        {
            WCHAR desc[160];
            DWORD descSize = sizeof(desc);
            if (RegQueryValueExW(key, L"DriverDesc", NULL, &type, (BYTE *)desc, &descSize) == ERROR_SUCCESS &&
                (wcsstr(desc, L"WAN Miniport") || wcsstr(desc, L"Virtual") ||
                 wcsstr(desc, L"Kernel Debug") || wcsstr(desc, L"TUN") ||
                 wcsstr(desc, L"Bluetooth") || wcsstr(desc, L"Wi-Fi Direct"))) {
                RegCloseKey(key);
                continue;
            }
        }

        if (apply) {
            WCHAR mac[16];
            BYTE  last = (BYTE)(cfg.Mac[5] + applied);

            swprintf_s(mac, 16, L"%02X%02X%02X%02X%02X%02X",
                       cfg.Mac[0], cfg.Mac[1], cfg.Mac[2], cfg.Mac[3], cfg.Mac[4], last);
            if (RegSetValueExW(key, L"NetworkAddress", 0, REG_SZ, (const BYTE *)mac,
                               (DWORD)((wcslen(mac) + 1) * sizeof(WCHAR))) == ERROR_SUCCESS) {
                printf("  %-38ls -> %ls\n", sub, mac);
                changed++;
                applied++;
            }
        } else {
            if (RegDeleteValueW(key, L"NetworkAddress") == ERROR_SUCCESS) {
                printf("  %-38ls -> (hardware address)\n", sub);
                changed++;
            }
        }
        RegCloseKey(key);
    }

    RegCloseKey(root);

    if (changed == 0) {
        printf("no adapters changed\n");
        return 1;
    }

    printf("\n%d adapter(s) %s. Restart them for this to take effect:\n", changed,
           apply ? "configured" : "cleared");
    printf("    Get-NetAdapter | Restart-NetAdapter        (or reboot)\n");
    return 0;
}

/* ----------------------------------------------------------------- monitor */

static const char *
MonTypeName(ULONG type)
{
    switch (type & 0x0FFFFFFFu) {
    case SYSINFO_MON_IMAGE:   return "IMAGE ";
    case SYSINFO_MON_PROCESS: return "PROC  ";
    case SYSINFO_MON_REG:     return "REG   ";
    case SYSINFO_MON_IOCTL:   return "IOCTL ";
    case SYSINFO_MON_SYSINFO: return "QSI   ";
    case SYSINFO_MON_HANDLE:  return "HANDLE";
    case SYSINFO_MON_THREAD:  return "THREAD";
    case SYSINFO_MON_FILE:    return "FILE  ";
    case SYSINFO_MON_KEY:     return "KEY   ";
    case SYSINFO_MON_MEM:     return "MEM   ";
    case SYSINFO_MON_KCB:     return "KCB   ";
    case SYSINFO_MON_DEV:     return "DEV   ";
    default:                  return "?     ";
    }
}

static BOOLEAN
ParseTypes(const char *spec, ULONG *mask)
{
    static const struct { const char *name; ULONG bit; } map[] = {
        { "image",   SYSINFO_MON_BIT_IMAGE },
        { "process", SYSINFO_MON_BIT_PROCESS },
        { "proc",    SYSINFO_MON_BIT_PROCESS },
        { "reg",     SYSINFO_MON_BIT_REG },
        { "value",   SYSINFO_MON_BIT_REG },
        { "ioctl",   SYSINFO_MON_BIT_IOCTL },
        { "qsi",     SYSINFO_MON_BIT_SYSINFO },
        { "handle",  SYSINFO_MON_BIT_HANDLE },
        { "thread",  SYSINFO_MON_BIT_THREAD },
        { "file",    SYSINFO_MON_BIT_FILE },
        { "key",     SYSINFO_MON_BIT_KEY },
        { "mem",     SYSINFO_MON_BIT_MEM },
        { "kcb",     SYSINFO_MON_BIT_KCB },
        { "dev",     SYSINFO_MON_BIT_DEV }
    };
    char work[256];
    char *context = NULL;
    char *token;
    ULONG bits = 0;

    if (spec == NULL || spec[0] == 0) { *mask = SYSINFO_MON_BITS_QUIET; return TRUE; }
    if (_strnicmp(spec, "types=", 6) == 0) spec += 6;
    if (_stricmp(spec, "all") == 0)   { *mask = SYSINFO_MON_BITS_ALL;   return TRUE; }
    if (_stricmp(spec, "quiet") == 0) { *mask = SYSINFO_MON_BITS_QUIET; return TRUE; }

    strncpy_s(work, sizeof(work), spec, _TRUNCATE);

    for (token = strtok_s(work, ", ", &context); token != NULL;
         token = strtok_s(NULL, ", ", &context)) {
        size_t i;
        BOOLEAN hit = FALSE;

        for (i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
            if (_stricmp(token, map[i].name) == 0) { bits |= map[i].bit; hit = TRUE; break; }
        }
        if (!hit) {
            printf("unknown event type '%s'\n", token);
            return FALSE;
        }
    }

    *mask = (bits != 0) ? bits : SYSINFO_MON_BITS_QUIET;
    return TRUE;
}

static int
CmdMonConfig(ULONG enable, const char *filter, ULONG types, const char *ignoreSpec,
             int ioctlBytes, const char *ioctlMatch)
{
    HANDLE device = OpenDriver();
    SYSINFO_MON_CONFIG cfg;
    DWORD returned = 0;
    ULONG pid = 0;

    if (device == INVALID_HANDLE_VALUE) {
        printf("driver: not running (%lu) - run elevated\n", GetLastError());
        return 1;
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.Enable = enable;
    cfg.KernelImages = 1;
    cfg.SsnRead = NtdllSsn("NtReadVirtualMemory");
    cfg.SsnWrite = NtdllSsn("NtWriteVirtualMemory");
    cfg.Types = types;

    /* IOCTL payload capture: tells you what user mode asks a driver to do. */
    {
        const char *match = (ioctlMatch != NULL && ioctlMatch[0] != 0) ? ioctlMatch : "";
        WCHAR wide[32];

        cfg.IoctlDump = (ULONG)((ioctlBytes < 0) ? 0 : (ioctlBytes > 32 ? 32 : ioctlBytes));
        if (MultiByteToWideChar(CP_UTF8, 0, match, -1, wide, 32) > 0) {
            wcscpy_s(cfg.IoctlMatch, 32, wide);
            cfg.IoctlMatchChars = (ULONG)wcslen(cfg.IoctlMatch);
        }
    }

    /*
     * Subjects to fold away instead of storing: a process's own directory is
     * the bulk of a session, and unrooted names are its own files.  Nothing is
     * folded unless ignore= names it.
     */
    {
        const char *spec = ignoreSpec;
        const char *def = "";
        BOOLEAN useDefault = (spec == NULL || spec[0] == 0);

        if (spec != NULL && _stricmp(spec, "none") == 0) {
            cfg.IgnoreCount = 0;
            cfg.IgnoreRelative = 0;
        } else {
            const char *p = useDefault ? def : spec;

            cfg.IgnoreRelative = 1;
            while (*p != 0 && cfg.IgnoreCount < 4) {
                const char *comma = strchr(p, ',');
                size_t len = comma != NULL ? (size_t)(comma - p) : strlen(p);
                WCHAR wide[SYSINFO_MON_IGNORE_CHARS];

                while (len > 0 && (*p == ' ' || *p == '\t')) { p++; len--; }
                while (len > 0 && (p[len - 1] == ' ' || p[len - 1] == '\t')) len--;
                if (len > 0) {
                    char tmp[SYSINFO_MON_IGNORE_CHARS];

                    if (len > sizeof(tmp) - 1) len = sizeof(tmp) - 1;
                    memcpy(tmp, p, len);
                    tmp[len] = 0;
                    if (MultiByteToWideChar(CP_UTF8, 0, tmp, -1, wide, SYSINFO_MON_IGNORE_CHARS) > 0) {
                        wcscpy_s(cfg.SummaryIgnore[cfg.IgnoreCount], SYSINFO_MON_IGNORE_CHARS, wide);
                        cfg.IgnoreCount++;
                    }
                }
                if (comma == NULL) break;
                p = comma + 1;
            }
        }
    }

    if (enable && filter != NULL && filter[0] != 0) {
        char *end = NULL;
        unsigned long value = strtoul(filter, &end, 10);

        if (end != NULL && *end == 0) {
            pid = (ULONG)value;
        } else {
            /* Comma-separated image names, e.g. app.exe,helper.exe */
            const char *p = filter;

            while (*p != 0 && cfg.ImageCount < 4) {
                const char *comma = strchr(p, ',');
                size_t len = comma != NULL ? (size_t)(comma - p) : strlen(p);

                while (len > 0 && (*p == ' ' || *p == '\t')) { p++; len--; }
                while (len > 0 && (p[len - 1] == ' ' || p[len - 1] == '\t')) len--;
                if (len > SYSINFO_MON_IMAGE_CHARS - 1) len = SYSINFO_MON_IMAGE_CHARS - 1;
                if (len > 0) {
                    strncpy_s(cfg.Images[cfg.ImageCount], SYSINFO_MON_IMAGE_CHARS, p, len);
                    cfg.ImageCount++;
                }
                if (comma == NULL) break;
                p = comma + 1;
            }
        }
    }
    cfg.PidFilter = pid;

    if (!DeviceIoControl(device, SYSINFO_IOCTL_MON_CONFIG, &cfg, sizeof(cfg), NULL, 0, &returned, NULL)) {
        printf("monitor config failed (%lu)\n", GetLastError());
        CloseHandle(device);
        return 1;
    }
    CloseHandle(device);

    if (enable) {
        if (pid != 0) {
            printf("monitor: on, filtering to pid %lu\n", (unsigned long)pid);
        } else if (cfg.ImageCount != 0) {
            printf("monitor: on, filtering to image");
            for (ULONG i = 0; i < cfg.ImageCount; i++) printf(" %s", cfg.Images[i]);
            printf("\n");
        } else {
            printf("monitor: on, all processes\n");
        }
        printf("monitor: storing event types 0x%03lX (summary always records all)\n",
               (unsigned long)cfg.Types);
        if (cfg.IgnoreCount != 0) {
            printf("monitor: folding summary subjects matching");
            for (ULONG i = 0; i < cfg.IgnoreCount; i++) printf(" %ls", cfg.SummaryIgnore[i]);
            if (cfg.IgnoreRelative) printf(" (+ relative names folded to their folder)");
            printf("\n");
        }
    } else {
        printf("monitor: off\n");
    }
    return 0;
}

static int
GuardSend(HANDLE device, SYSINFO_GUARD_CONFIG *cfg)
{
    DWORD returned = 0;

    if (!DeviceIoControl(device, SYSINFO_IOCTL_GUARD_CONFIG, cfg, sizeof(*cfg), NULL, 0, &returned, NULL)) {
        printf("guard config failed (%lu)\n", GetLastError());
        return 1;
    }
    return 0;
}

static char *
GuardTrim(char *line)
{
    char *end;

    while (*line == ' ' || *line == '\t' || *line == '\r') line++;
    end = line + strlen(line);
    while (end > line && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n')) *--end = 0;
    return line;
}

/* One directive per line; '#' starts a comment. */
static int
CmdGuardPolicy(HANDLE device, const char *file)
{
    FILE *f = NULL;
    SYSINFO_GUARD_CONFIG cfg;
    char line[512];
    unsigned long lineNo = 0, applied = 0;

    if (fopen_s(&f, file, "r") != 0 || f == NULL) {
        printf("cannot open policy file %s\n", file);
        return 1;
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.Mode = SYSINFO_GUARD_AUDIT;

    while (fgets(line, sizeof(line), f) != NULL) {
        char *text, *arg;

        lineNo++;
        text = GuardTrim(line);
        if (text[0] == 0 || text[0] == '#') continue;
        arg = strpbrk(text, " \t");
        if (arg != NULL) { *arg++ = 0; arg = GuardTrim(arg); }

        if (_stricmp(text, "mode") == 0 && arg != NULL) {
            if (_stricmp(arg, "off") == 0)          cfg.Mode = SYSINFO_GUARD_OFF;
            else if (_stricmp(arg, "audit") == 0)   cfg.Mode = SYSINFO_GUARD_AUDIT;
            else if (_stricmp(arg, "enforce") == 0) cfg.Mode = SYSINFO_GUARD_ENFORCE;
            else { printf("line %lu: unknown mode '%s'\n", lineNo, arg); fclose(f); return 1; }
            applied++;
        } else if (_stricmp(text, "target") == 0 && arg != NULL) {
            if (cfg.TargetCount >= SYSINFO_GUARD_MAX_TARGETS) {
                printf("line %lu: more than %d targets\n", lineNo, SYSINFO_GUARD_MAX_TARGETS);
                fclose(f); return 1;
            }
            strncpy_s(cfg.Targets[cfg.TargetCount], SYSINFO_GUARD_TARGET_CHARS, arg, _TRUNCATE);
            cfg.TargetCount++;
            applied++;
        } else if (_stricmp(text, "process") == 0 && arg != NULL) {
            if (cfg.ProcessCount >= SYSINFO_GUARD_MAX_PROCS) {
                printf("line %lu: more than %d processes\n", lineNo, SYSINFO_GUARD_MAX_PROCS);
                fclose(f); return 1;
            }
            strncpy_s(cfg.Processes[cfg.ProcessCount], SYSINFO_GUARD_TARGET_CHARS, arg, _TRUNCATE);
            cfg.ProcessCount++;
            applied++;
        } else if (_stricmp(text, "path") == 0 && arg != NULL) {
            WCHAR wide[SYSINFO_GUARD_PATH_CHARS];

            if (cfg.PathCount >= SYSINFO_GUARD_MAX_PATHS) {
                printf("line %lu: more than %d paths\n", lineNo, SYSINFO_GUARD_MAX_PATHS);
                fclose(f); return 1;
            }
            if (MultiByteToWideChar(CP_UTF8, 0, arg, -1, wide,
                                    SYSINFO_GUARD_PATH_CHARS) <= 0) {
                printf("line %lu: path is not valid UTF-8\n", lineNo);
                fclose(f); return 1;
            }
            wcscpy_s(cfg.Paths[cfg.PathCount], SYSINFO_GUARD_PATH_CHARS, wide);
            cfg.PathCount++;
            applied++;
        } else {
            printf("line %lu: unknown directive '%s'\n", lineNo, text);
            fclose(f);
            return 1;
        }
    }
    fclose(f);

    if (applied == 0) {
        printf("policy file has no directives\n");
        return 1;
    }
    if (GuardSend(device, &cfg) != 0) return 1;

    printf("guard: policy loaded - mode=%s targets=%lu paths=%lu processes=%lu\n",
           cfg.Mode == SYSINFO_GUARD_ENFORCE ? "enforce" :
           cfg.Mode == SYSINFO_GUARD_AUDIT ? "audit" : "off",
           (unsigned long)cfg.TargetCount, (unsigned long)cfg.PathCount,
           (unsigned long)cfg.ProcessCount);
    return 0;
}

static int
CmdGuard(int argc, char **argv)
{
    HANDLE device = OpenDriver();
    const char *what = argc > 2 ? argv[2] : "status";

    if (device == INVALID_HANDLE_VALUE) {
        printf("driver: not running (%lu) - run elevated\n", GetLastError());
        return 1;
    }

    if (_stricmp(what, "policy") == 0) {
        int rc;

        if (argc <= 3) {
            printf("usage: guard policy <file>\n");
            CloseHandle(device);
            return 1;
        }
        rc = CmdGuardPolicy(device, argv[3]);
        CloseHandle(device);
        return rc;
    }

    if (_stricmp(what, "status") == 0) {
        SYSINFO_GUARD_STATUS st;
        DWORD returned = 0;

        memset(&st, 0, sizeof(st));
        if (!DeviceIoControl(device, SYSINFO_IOCTL_GUARD_STATUS, NULL, 0, &st, sizeof(st), &returned, NULL)) {
            printf("guard status failed (%lu)\n", GetLastError());
            CloseHandle(device);
            return 1;
        }
        printf("guard: mode=%s targets=%lu paths=%lu processes=%lu checks=%lu denied=%lu audit=%lu\n",
               st.Mode == SYSINFO_GUARD_ENFORCE ? "enforce" :
               st.Mode == SYSINFO_GUARD_AUDIT ? "audit" : "off",
               (unsigned long)st.Targets, (unsigned long)st.Paths,
               (unsigned long)st.Processes, (unsigned long)st.Checks,
               (unsigned long)st.Denied, (unsigned long)st.Audited);
        CloseHandle(device);
        return 0;
    }

    {
        SYSINFO_GUARD_CONFIG cfg;
        ULONG mode;

        if (_stricmp(what, "off") == 0) mode = SYSINFO_GUARD_OFF;
        else if (_stricmp(what, "audit") == 0) mode = SYSINFO_GUARD_AUDIT;
        else if (_stricmp(what, "enforce") == 0 || _stricmp(what, "on") == 0) mode = SYSINFO_GUARD_ENFORCE;
        else { printf("usage: guard off|audit|enforce|status|policy <file>\n"); CloseHandle(device); return 1; }

        memset(&cfg, 0, sizeof(cfg));
        cfg.Mode = mode;   /* counts 0 = keep built-in targets/paths */
        if (GuardSend(device, &cfg) != 0) {
            CloseHandle(device);
            return 1;
        }
        printf("guard: %s\n", mode == SYSINFO_GUARD_ENFORCE ? "enforce" :
                              mode == SYSINFO_GUARD_AUDIT ? "audit" : "off");
    }

    CloseHandle(device);
    return 0;
}

static BOOL
ContainsNoCase(const char *haystack, const char *needle)
{
    size_t nlen = strlen(needle);
    if (nlen == 0) return TRUE;

    for (; *haystack != 0; haystack++) {
        size_t i = 0;
        while (i < nlen && haystack[i] != 0 &&
               tolower((unsigned char)haystack[i]) == tolower((unsigned char)needle[i])) {
            i++;
        }
        if (i == nlen) return TRUE;
    }
    return FALSE;
}

/*
 * Lossless capture: drain the ring to a file continuously.  The ring can
 * overflow between reads; the file cannot.
 */
static volatile LONG g_CollectStop;

static BOOL WINAPI
CollectCtrlHandler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        InterlockedExchange(&g_CollectStop, 1);
        return TRUE;
    }
    return FALSE;
}

static void
WriteEventTsv(FILE *out, const SYSINFO_MON_EVENT *e)
{
    SYSTEMTIME st;
    FILETIME ft;
    ULARGE_INTEGER u;
    char flags[8];
    unsigned n = 0;

    if (e->Type & SYSINFO_MON_KCALL)  flags[n++] = 'K';   /* entered from kernel */
    if (e->Type & SYSINFO_MON_KSTACK) flags[n++] = 'S';   /* driver frame behind a user call */
    if (e->Type & SYSINFO_MON_KERNEL) flags[n++] = 'D';   /* kernel image */
    flags[n] = 0;

    u.QuadPart = e->Stamp;
    ft.dwLowDateTime = u.LowPart;
    ft.dwHighDateTime = u.HighPart;
    FileTimeToLocalFileTime(&ft, &ft);
    FileTimeToSystemTime(&ft, &st);

    fprintf(out,
            "%04u-%02u-%02u %02u:%02u:%02u.%03u\t%lu\t%lu\t%s\t%s\t%s\t%08lX\t%lu\t%016llX\t%s\t%ls\t%s\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            (unsigned long)e->Pid, (unsigned long)e->Tid,
            e->Image, MonTypeName(e->Type), e->Module,
            (unsigned long)e->Op, (unsigned long)e->Repeat + 1,
            (unsigned long long)e->Caller,
            flags[0] != 0 ? flags : "-",
            e->Path, e->Detail);
}

static int
CmdMonCollect(const char *file, const char *filter, ULONG types)
{
    HANDLE device = OpenDriver();
    const ULONG bufSize = sizeof(SYSINFO_MON_BATCH) + SYSINFO_MON_BATCH_MAX * sizeof(SYSINFO_MON_EVENT);
    BYTE *buffer;
    FILE *out = NULL;
    unsigned long long written = 0, dropped = 0;
    DWORD returned = 0;
    SYSTEMTIME start;
    int rc = 0;

    if (device == INVALID_HANDLE_VALUE) {
        printf("driver: not running (%lu) - run elevated\n", GetLastError());
        return 1;
    }
    if (fopen_s(&out, file, "a") != 0 || out == NULL) {
        printf("cannot open %s\n", file);
        CloseHandle(device);
        return 1;
    }

    /* Collect takes whatever the caller asked for; default is everything. */
    if (CmdMonConfig(1, filter, types, NULL, 16, NULL) != 0) {
        fclose(out);
        CloseHandle(device);
        return 1;
    }

    buffer = (BYTE *)malloc(bufSize);
    if (buffer == NULL) { fclose(out); CloseHandle(device); return 1; }

    GetLocalTime(&start);
    fprintf(out,
            "# sysinfoctl collect  ABI %u  start %04u-%02u-%02u %02u:%02u:%02u  filter %s  types 0x%03lX\n"
            "# time\tpid\ttid\timage\ttype\tmodule\top\trepeat\tcaller\tflags\tpath\tdetail\n",
            SYSINFO_ABI_VERSION, start.wYear, start.wMonth, start.wDay,
            start.wHour, start.wMinute, start.wSecond,
            (filter != NULL && filter[0] != 0) ? filter : "(none)",
            (unsigned long)types);
    fflush(out);

    SetConsoleCtrlHandler(CollectCtrlHandler, TRUE);
    InterlockedExchange(&g_CollectStop, 0);
    printf("collecting to %s (types=all); Ctrl+C to stop\n", file);

    for (;;) {
        PSYSINFO_MON_BATCH batch = (PSYSINFO_MON_BATCH)buffer;
        ULONG i;
        BOOLEAN got = FALSE;

        if (!DeviceIoControl(device, SYSINFO_IOCTL_MON_READ, NULL, 0, buffer, bufSize,
                             &returned, NULL)) {
            printf("collect: read failed (%lu)\n", GetLastError());
            rc = 1;
            break;
        }

        for (i = 0; i < batch->Count; i++) {
            SYSINFO_MON_EVENT *e = (SYSINFO_MON_EVENT *)(buffer + sizeof(SYSINFO_MON_BATCH)) + i;

            WriteEventTsv(out, e);
            written++;
            got = TRUE;
        }
        if (batch->Dropped != 0) dropped = batch->Dropped;

        if (got) {
            fflush(out);
        } else {
            Sleep(25);
        }

        if (InterlockedCompareExchange(&g_CollectStop, 0, 0) != 0) break;
        if (written != 0 && (written % 4096) < batch->Count) {
            /* cheap progress heartbeat */
            fflush(out);
        }
    }

    {
        SYSTEMTIME end;
        GetLocalTime(&end);
        fprintf(out, "# end %04u-%02u-%02u %02u:%02u:%02u  events %llu  ring dropped %llu\n",
                end.wYear, end.wMonth, end.wDay, end.wHour, end.wMinute, end.wSecond,
                written, dropped);
    }
    fclose(out);
    free(buffer);
    CloseHandle(device);

    printf("collected %llu events (%llu dropped by the ring before collection)\n",
           written, dropped);
    return rc;
}

static int
SummaryCmp(const void *a, const void *b)
{
    const SYSINFO_SUMMARY_ENTRY *x = (const SYSINFO_SUMMARY_ENTRY *)a;
    const SYSINFO_SUMMARY_ENTRY *y = (const SYSINFO_SUMMARY_ENTRY *)b;

    if (x->Count != y->Count) return (x->Count < y->Count) ? 1 : -1;
    return _wcsicmp(x->Subject, y->Subject);
}

/*
 * Everything the session did, aggregated.  Unlike `mon dump` this cannot be
 * lost to ring overflow: one row per distinct thing, with a hit count.
 */
static int
CmdMonSummary(const char *filter)
{
    HANDLE device = OpenDriver();
    const ULONG bufSize = sizeof(SYSINFO_SUMMARY_HEAD) +
                          SYSINFO_SUMMARY_BATCH * sizeof(SYSINFO_SUMMARY_ENTRY);
    BYTE *buffer;
    SYSINFO_SUMMARY_ENTRY *rows = NULL;
    ULONG rowsMax = 0, rowsUsed = 0, next = 0, overflow = 0, suppressed = 0, total = 0;
    DWORD returned = 0;
    unsigned long long totalHits = 0;

    if (device == INVALID_HANDLE_VALUE) {
        printf("driver: not running (%lu) - run elevated\n", GetLastError());
        return 1;
    }

    buffer = (BYTE *)malloc(bufSize);
    if (buffer == NULL) { CloseHandle(device); return 1; }

    for (;;) {
        SYSINFO_SUMMARY_REQ req;
        PSYSINFO_SUMMARY_HEAD head;
        PSYSINFO_SUMMARY_ENTRY entries;
        ULONG i;

        req.Start = next;
        req.Max = SYSINFO_SUMMARY_BATCH;
        if (!DeviceIoControl(device, SYSINFO_IOCTL_MON_SUMMARY, &req, sizeof(req),
                             buffer, bufSize, &returned, NULL)) {
            printf("summary read failed (%lu)\n", GetLastError());
            break;
        }

        head = (PSYSINFO_SUMMARY_HEAD)buffer;
        entries = (PSYSINFO_SUMMARY_ENTRY)(head + 1);
        total = head->Total;
        overflow = head->Overflow;
        suppressed = head->Suppressed;

        for (i = 0; i < head->Count; i++) {
            if (rowsUsed == rowsMax) {
                ULONG want = rowsMax ? rowsMax * 2 : 256;
                SYSINFO_SUMMARY_ENTRY *grown = (SYSINFO_SUMMARY_ENTRY *)realloc(rows, want * sizeof(*rows));
                if (grown == NULL) break;
                rows = grown;
                rowsMax = want;
            }
            rows[rowsUsed++] = entries[i];
        }

        next = head->Next;
        if (next == 0 || head->Count == 0) break;
    }

    if (rows != NULL && rowsUsed != 0) {
        qsort(rows, rowsUsed, sizeof(*rows), SummaryCmp);
    }
    printf("summary: %lu distinct, suppressed %lu, overflow %lu\n",
           (unsigned long)total, (unsigned long)suppressed, (unsigned long)overflow);
    for (ULONG i = 0; i < rowsUsed; i++) {
        char subject[SYSINFO_SUMMARY_SUBJECT + 1];
        char image[SYSINFO_MON_IMAGE_CHARS + 1];
        char module[SYSINFO_MON_MODULE_CHARS + 1];

        WideCharToMultiByte(CP_UTF8, 0, rows[i].Subject, -1, subject, sizeof(subject), NULL, NULL);
        memcpy(image, rows[i].Image, sizeof(rows[i].Image));
        image[sizeof(rows[i].Image)] = 0;
        memcpy(module, rows[i].Module, sizeof(rows[i].Module));
        module[sizeof(rows[i].Module)] = 0;

        if (filter != NULL && filter[0] != 0 &&
            !ContainsNoCase(subject, filter) &&
            !ContainsNoCase(image, filter) &&
            !ContainsNoCase(module, filter)) {
            continue;
        }

        totalHits += rows[i].Count;
        printf("%8lu  %s %-16s %-24s %s\n",
               (unsigned long)rows[i].Count, MonTypeName(rows[i].Type),
               image, module[0] ? module : "-", subject);
    }
    printf("(total hits shown: %llu)\n", totalHits);

    free(rows);
    free(buffer);
    CloseHandle(device);
    return 0;
}

static int
CmdMonDump(int watch, const char *filter)
{
    HANDLE device = OpenDriver();
    const ULONG bufferSize = sizeof(SYSINFO_MON_BATCH) + SYSINFO_MON_BATCH_MAX * sizeof(SYSINFO_MON_EVENT);
    BYTE *buffer;
    DWORD returned = 0;
    unsigned long long total = 0;
    unsigned long batches = 0;

    if (device == INVALID_HANDLE_VALUE) {
        printf("driver: not running (%lu) - run elevated\n", GetLastError());
        return 1;
    }

    buffer = (BYTE *)malloc(bufferSize);
    if (buffer == NULL) { CloseHandle(device); return 1; }

    printf("monitor: dumping%s\n", watch ? " (Ctrl+C to stop)" : "");
    for (;;) {
        PSYSINFO_MON_BATCH batch = (PSYSINFO_MON_BATCH)buffer;

        if (!DeviceIoControl(device, SYSINFO_IOCTL_MON_READ, NULL, 0, buffer, bufferSize, &returned, NULL)) {
            printf("monitor read failed (%lu)\n", GetLastError());
            break;
        }

        for (ULONG i = 0; i < batch->Count; i++) {
            SYSINFO_MON_EVENT *e = (SYSINFO_MON_EVENT *)(buffer + sizeof(SYSINFO_MON_BATCH))
                                   + i;
            FILETIME ft;
            SYSTEMTIME st;
            ULARGE_INTEGER u;
            char detail[SYSINFO_MON_MAX_DETAIL + 1];
            char image[SYSINFO_MON_IMAGE_CHARS + 1];
            char module[SYSINFO_MON_MODULE_CHARS + 1];
            char callerText[96];
            char haystack[512];

            u.QuadPart = e->Stamp;
            ft.dwLowDateTime = u.LowPart;
            ft.dwHighDateTime = u.HighPart;
            FileTimeToLocalFileTime(&ft, &ft);
            FileTimeToSystemTime(&ft, &st);

            memcpy(image, e->Image, sizeof(e->Image));
            image[sizeof(e->Image)] = 0;
            memcpy(detail, e->Detail, sizeof(e->Detail));
            detail[sizeof(e->Detail)] = 0;
            memcpy(module, e->Module, sizeof(e->Module));
            module[sizeof(e->Module)] = 0;

            callerText[0] = 0;
            if (e->Caller != 0) {
                ULONG64 off = 0;
                const char *mod = CallerModule(e->Caller, &off);
                if (mod != NULL) {
                    sprintf_s(callerText, sizeof(callerText), "  via %s+0x%llX", mod,
                              (unsigned long long)off);
                } else {
                    sprintf_s(callerText, sizeof(callerText), "  via 0x%llX",
                              (unsigned long long)e->Caller);
                }
            }

            if (filter != NULL && filter[0] != 0) {
                sprintf_s(haystack, sizeof(haystack), "%s %s %ls %s%s%s %s %s",
                          image, detail, e->Path, callerText,
                          (e->Type & SYSINFO_MON_KCALL) ? " kernel" : "",
                          (e->Type & SYSINFO_MON_KSTACK) ? " kstack" : "",
                          (e->Type & SYSINFO_MON_KERNEL) ? " driver" : "",
                          module);
                if (!ContainsNoCase(haystack, filter)) continue;
            }

            printf("%02u:%02u:%02u.%03u  pid %-6lu %-16s %s%s", st.wHour, st.wMinute, st.wSecond,
                   st.wMilliseconds, (unsigned long)e->Pid, image, MonTypeName(e->Type),
                   (e->Type & SYSINFO_MON_KCALL) ? " [kernel]" :
                   ((e->Type & SYSINFO_MON_KSTACK) ? " [kstack]" : ""));

            switch (e->Type & 0x0FFFFFFFu) {
            case SYSINFO_MON_IOCTL:
                printf(" %ls  0x%08lX", e->Path, (unsigned long)e->Op);
                break;
            case SYSINFO_MON_SYSINFO:
                printf(" class %lu", (unsigned long)e->Op);
                break;
            case SYSINFO_MON_REG:
                printf(" %ls  %s  class %lu", e->Path, detail, (unsigned long)e->Op);
                break;
            case SYSINFO_MON_IMAGE:
                printf(" %s%ls  %s", (e->Type & SYSINFO_MON_KERNEL) ? "[driver] " : "",
                       e->Path, detail);
                break;
            case SYSINFO_MON_PROCESS:
                printf(" %s %ls", detail, e->Path);
                break;
            case SYSINFO_MON_HANDLE: {
                static const struct { ULONG bit; const char *name; } rights[] = {
                    { 0x0002, "create_thread" }, { 0x0008, "vm_operation" },
                    { 0x0010, "vm_read" },       { 0x0020, "vm_write" },
                    { 0x0040, "dup_handle" },    { 0x0200, "suspend" },
                    { 0x0400, "query_info" },    { 0x0800, "query_limited" }
                };
                char flags[96];
                int  n = 0;

                flags[0] = 0;
                for (int r = 0; r < 8; r++) {
                    if ((e->Op & rights[r].bit) == 0) continue;
                    n += sprintf_s(flags + n, sizeof(flags) - (size_t)n, "%s%s", n ? "," : "", rights[r].name);
                }
                printf(" target %-14s tid %-6lu access 0x%08lX %s",
                       detail, (unsigned long)e->Tid, (unsigned long)e->Op, flags);
                break;
            }
            case SYSINFO_MON_THREAD:
                printf(" tid %-6lu %s", (unsigned long)e->Tid, detail);
                break;
            default:
                if (e->Path[0] != 0) printf(" %ls", e->Path);
                if (detail[0] != 0)  printf("  %s", detail);
                break;
            }
            printf("%s", callerText);
            if (module[0] != 0) printf("  <- %s", module);
            if (e->Repeat != 0) printf("  (x%lu)", (unsigned long)e->Repeat + 1);
            printf("\n");
            total++;
        }

        if (batch->Dropped != 0 && !watch) {
            printf("(%lu events dropped - ring overflow)\n", (unsigned long)batch->Dropped);
        }
        fflush(stdout);

        if (!watch) {
            if (batch->Count == 0) break;
            if (++batches >= 64) {
                printf("(stopped after %lu events; run 'mon dump' again for the rest)\n",
                       (unsigned long)batches * SYSINFO_MON_BATCH_MAX);
                break;
            }
            continue;
        }
        Sleep(500);
    }

    if (watch) printf("monitor: %llu events\n", total);
    free(buffer);
    CloseHandle(device);
    return 0;
}

/* ------------------------------------------------------------------ main */

static void
Usage(VOID)
{
    printf("sysinfoctl - control tool for SysInfo.sys (needs administrator)\n\n"
           "  sysinfoctl preflight        check this machine (HVCI, test signing, Secure Boot)\n"
           "  sysinfoctl install [path\\to\\SysInfo.sys]\n"
           "  sysinfoctl uninstall\n"
           "  sysinfoctl start | stop\n"
           "  sysinfoctl unload\n"
           "  sysinfoctl status\n"
           "  sysinfoctl hostname [name]          show or set the real computer name\n"
           "  sysinfoctl mac on | off             set/clear a real MAC on every adapter\n"
           "  sysinfoctl mon on [pid|name,...] [types=..] [ignore=..] [ioctl=N] [ioctlmatch=..]\n"
           "                                      watch what a process (or everything) does\n"
           "                                      types: quiet (default) | all | file,key,...\n"
           "                                      ioctl: hex-dump N bytes of matching IOCTL input\n"
           "  sysinfoctl mon summary [filter]     everything so far, aggregated\n"
           "  sysinfoctl mon dump [filter] | watch [filter]\n"
           "                                      print events (filter matches image/path/detail/caller)\n"
           "  sysinfoctl guard off | audit | enforce | status\n"
           "                                      deny the listed targets access to the listed paths\n"
           "  sysinfoctl repair                    fill in missing singleton identifiers\n"
           "  sysinfoctl random [seed] [key=value ...]\n"
           "  sysinfoctl show\n"
           "  sysinfoctl edid [save <file>]      show/save the EDID served for monitor keys\n"
           "  sysinfoctl capture [file]          dump the last captured I/O buffer\n"
           "  sysinfoctl clear\n"
           "  sysinfoctl verify\n\n"
           "overrides: machineguid uuid serial boardserial chassis bios disk volume mac\n");
}

int
main(int argc, char **argv)
{
    const char *command = (argc > 1) ? argv[1] : "status";

    if (_stricmp(command, "preflight") == 0) return CmdPreflight();
    if (_stricmp(command, "hostname") == 0) return CmdHostname(argc > 2 ? argv[2] : NULL);
    if (_stricmp(command, "mac") == 0) {
        const char *what = (argc > 2) ? argv[2] : "on";
        return CmdMac(_stricmp(what, "off") != 0);
    }
    if (_stricmp(command, "mon") == 0) {
        const char *what = (argc > 2) ? argv[2] : "dump";

        if (_stricmp(what, "on") == 0) {
            ULONG types = SYSINFO_MON_BITS_QUIET;
            const char *ignore = NULL;
            const char *ioctlMatch = NULL;
            int ioctlBytes = 16;
            int i;

            for (i = 4; i < argc; i++) {
                if (_strnicmp(argv[i], "types=", 6) == 0) {
                    if (!ParseTypes(argv[i], &types)) return 1;
                } else if (_strnicmp(argv[i], "ignore=", 7) == 0) {
                    ignore = argv[i] + 7;
                } else if (_strnicmp(argv[i], "ioctlmatch=", 11) == 0) {
                    ioctlMatch = argv[i] + 11;
                } else if (_strnicmp(argv[i], "ioctl=", 6) == 0) {
                    ioctlBytes = atoi(argv[i] + 6);
                }
            }
            return CmdMonConfig(1, (argc > 3) ? argv[3] : NULL, types, ignore,
                                ioctlBytes, ioctlMatch);
        }
        if (_stricmp(what, "off") == 0)   return CmdMonConfig(0, NULL, 0, NULL, 0, NULL);
        if (_stricmp(what, "collect") == 0) {
            ULONG types = SYSINFO_MON_BITS_ALL;

            if (argc <= 3) { printf("usage: mon collect <file> [filter] [types=..]\n"); return 1; }
            if (argc > 5 && !ParseTypes(argv[5], &types)) return 1;
            return CmdMonCollect(argv[3], argc > 4 ? argv[4] : NULL, types);
        }
        if (_stricmp(what, "summary") == 0) return CmdMonSummary(argc > 3 ? argv[3] : NULL);
        if (_stricmp(what, "watch") == 0) return CmdMonDump(1, argc > 3 ? argv[3] : NULL);
        return CmdMonDump(0, argc > 3 ? argv[3] : NULL);
    }
    if (_stricmp(command, "guard") == 0) {
        return CmdGuard(argc, argv);
    }
    if (_stricmp(command, "install") == 0)   return CmdInstall(argc > 2 ? argv[2] : NULL);
    if (_stricmp(command, "uninstall") == 0) return CmdUninstall();
    if (_stricmp(command, "start") == 0)     return CmdService(1);
    if (_stricmp(command, "stop") == 0)      return CmdService(0);
    if (_stricmp(command, "unload") == 0)    return CmdUnload(argc > 2 ? argv[2] : NULL);
    if (_stricmp(command, "status") == 0)    return CmdStatus();
    if (_stricmp(command, "read") == 0)      return CmdRead(argc > 2 ? argv[2] : NULL,
                                                            argc > 3 ? argv[3] : NULL,
                                                            argc > 4 ? argv[4] : NULL);
    if (_stricmp(command, "show") == 0)      return CmdShow();
    if (_stricmp(command, "capture") == 0) return CmdCapture(argc > 2 ? argv[2] : NULL);
    if (_stricmp(command, "edid") == 0)      return CmdEdid(argc > 2 ? argv[2] : NULL,
                                                          argc > 3 ? argv[3] : NULL);
    if (_stricmp(command, "clear") == 0)     return CmdClear();
    if (_stricmp(command, "verify") == 0)    return CmdVerify();
    if (_stricmp(command, "remove") == 0) {
        return CmdRemoveReg(argc > 2 ? argv[2] : NULL);
    }
    if (_stricmp(command, "set") == 0) {
        return CmdSetReg(argc > 2 ? argv[2] : NULL, argc > 3 ? argv[3] : NULL);
    }
    if (_stricmp(command, "repair") == 0) {
        return CmdRepair();
    }
    if (_stricmp(command, "random") == 0) {
        ULONGLONG seed = 0;
        int first = 2;

        if (argc > 2 && argv[2][0] >= '0' && argv[2][0] <= '9' && strchr(argv[2], '=') == NULL) {
            seed = _strtoui64(argv[2], NULL, 0);
            first = 3;
        }
        if (seed == 0) {
            LARGE_INTEGER counter;
            QueryPerformanceCounter(&counter);
            seed = (ULONGLONG)counter.QuadPart ^ ((ULONGLONG)GetTickCount64() << 21) ^ GetCurrentProcessId();
        }
        return CmdApply(seed, argc - first, argv + first, TRUE);
    }
    if (_stricmp(command, "apply") == 0) {
        /* apply with an explicit seed, no persistence for a quick look */
        ULONGLONG seed = (argc > 2) ? _strtoui64(argv[2], NULL, 0) : 1;
        return CmdApply(seed, argc - 3, argv + 3, FALSE);
    }

    Usage();
    return 1;
}
