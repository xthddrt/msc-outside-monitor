/*
 * sysinfo.h - shared ABI between SysInfo.sys (kernel) and sysinfoctl.exe (user).
  *
 * Contains no pointers, only fixed-size arrays, so a 32-bit CLI can talk to a
 * 64-bit driver (and vice versa) without packing tricks.
 */
#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#endif

/*
 * An already-loaded driver keeps its .sys file locked, so iterating on the
 * driver means building a *numbered instance* that coexists with the running
 * one: SYSINFO_INSTANCE=3 gives "\Device\SysInfo3", service "SysInfo3" and
 * so on.  Instance 1 (the default) keeps the bare names.
 */
#ifndef SYSINFO_INSTANCE
#define SYSINFO_INSTANCE 1
#endif

#define SYSINFO_STR_(x) #x
#define SYSINFO_STR(x)  SYSINFO_STR_(x)

/* The monitoring driver is a separate image from the identity driver, so its
 * device, service and parameter key carry a suffix.  That keeps both loadable
 * at the same time instead of fighting over \Device\SysInfo. */
#define SYSINFO_SUFFIX_W L"Mon"
#define SYSINFO_SUFFIX_A "Mon"

#define SYSINFO_DEVICE_NAME  L"\\Device\\SysInfo"    SYSINFO_SUFFIX_W
#define SYSINFO_DOS_NAME     L"\\DosDevices\\SysInfo" SYSINFO_SUFFIX_W
#define SYSINFO_WIN32_NAME   L"\\\\.\\SysInfo"       SYSINFO_SUFFIX_W
#define SYSINFO_SERVICE_NAME L"SysInfo"              SYSINFO_SUFFIX_W
#define SYSINFO_SERVICE_NAME_A "SysInfo"             SYSINFO_SUFFIX_A
#define SYSINFO_PARAM_KEY    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\SysInfo" SYSINFO_SUFFIX_W L"\\Parameters"

#define SYSINFO_MAX_STR   32   /* remapped ascii string, includes NUL */
#define SYSINFO_MAX_PATH  160  /* full native registry key path, in WCHARs */
#define SYSINFO_MAX_VALUE 72   /* value name, in WCHARs */
#define SYSINFO_MAX_DATA  512  /* registry value data (an EDID block is 128 or 256) */
#define SYSINFO_MAX_REG   32   /* number of registry overrides */
#define SYSINFO_MAX_EDID  256  /* one monitor's EDID blob */

/* One registry value override. KeyPath is a *native* path, e.g.
 *   \Registry\Machine\Software\Microsoft\Cryptography
 */
typedef struct _SYSINFO_REG_ENTRY {
    WCHAR KeyPath[SYSINFO_MAX_PATH];
    WCHAR ValueName[SYSINFO_MAX_VALUE];
    ULONG Type;                     /* REG_SZ / REG_EXPAND_SZ / REG_DWORD / REG_BINARY */
    ULONG DataLength;
    UCHAR Data[SYSINFO_MAX_DATA];
} SYSINFO_REG_ENTRY;

/* Which groups of identifiers are remapped. */
#define SYSINFO_F_REGISTRY 0x0001
#define SYSINFO_F_SMBIOS   0x0002
#define SYSINFO_F_DISK     0x0004
#define SYSINFO_F_VOLUME   0x0008
#define SYSINFO_F_MAC      0x0010
#define SYSINFO_F_EDID     0x0020
#define SYSINFO_F_ALL      (SYSINFO_F_REGISTRY | SYSINFO_F_SMBIOS | SYSINFO_F_DISK | SYSINFO_F_VOLUME | SYSINFO_F_MAC | SYSINFO_F_EDID)

typedef struct _SYSINFO_CONFIG {
    ULONG Size;                     /* sizeof(SYSINFO_CONFIG), sanity check */
    ULONG Flags;
    ULONG Seed;                     /* informational: seed the CLI generated from */
    ULONG VolumeSerial;             /* 32-bit volume serial for every volume */

    /* ---- SMBIOS remaps (ASCII, NUL terminated) ---- */
    UCHAR SmbiosUuid[16];           /* System Information (Type 1) UUID, raw bytes */
    CHAR  SmbiosSerial[SYSINFO_MAX_STR];    /* Type 1 serial number   */
    CHAR  SmbiosSku[SYSINFO_MAX_STR];       /* Type 1 SKU number      */
    CHAR  SmbiosManufacturer[SYSINFO_MAX_STR]; /* Type 1 manufacturer */
    CHAR  SmbiosProduct[SYSINFO_MAX_STR];      /* Type 1 product name */
    CHAR  BoardManufacturer[SYSINFO_MAX_STR];  /* Type 2 manufacturer */
    CHAR  BoardProduct[SYSINFO_MAX_STR];       /* Type 2 product name */
    CHAR  DimmManufacturer[SYSINFO_MAX_STR];   /* Type 17 manufacturer */
    CHAR  DimmSerial[SYSINFO_MAX_STR];         /* Type 17 serial   */
    CHAR  DimmAsset[SYSINFO_MAX_STR];          /* Type 17 asset tag */
    CHAR  DimmPart[SYSINFO_MAX_STR];           /* Type 17 part number */
    CHAR  BoardSerial[SYSINFO_MAX_STR];     /* Type 2 serial number   */
    CHAR  BoardAsset[SYSINFO_MAX_STR];      /* Type 2 asset tag       */
    CHAR  ChassisSerial[SYSINFO_MAX_STR];   /* Type 3 serial number   */
    CHAR  ChassisAsset[SYSINFO_MAX_STR];    /* Type 3 asset tag       */
    CHAR  BiosVersion[SYSINFO_MAX_STR];     /* Type 0 BIOS version    */
    CHAR  BiosDate[SYSINFO_MAX_STR];        /* Type 0 BIOS date       */
    CHAR  BiosVendor[SYSINFO_MAX_STR];      /* Type 0 BIOS vendor     */
    CHAR  SmbiosVersion[SYSINFO_MAX_STR];   /* Type 1 version         */
    CHAR  SmbiosFamily[SYSINFO_MAX_STR];    /* Type 1 family          */
    CHAR  BoardVersion[SYSINFO_MAX_STR];    /* Type 2 version         */
    CHAR  ChassisManufacturer[SYSINFO_MAX_STR]; /* Type 3 manufacturer */
    CHAR  ChassisVersion[SYSINFO_MAX_STR];  /* Type 3 version         */

    /* ---- storage / network ---- */
    CHAR  DiskSerial[SYSINFO_MAX_STR]; /* STORAGE_DEVICE_DESCRIPTOR serial */
    CHAR  DiskVendor[SYSINFO_MAX_STR]; /* STORAGE_DEVICE_DESCRIPTOR vendor */
    CHAR  DiskModel[SYSINFO_MAX_STR];  /* ... product id (the "model")     */
    CHAR  DiskFirmware[SYSINFO_MAX_STR]; /* ... product revision           */
    UCHAR DiskEui64[8];             /* EUI-64 used for unique ids and NVMe */
    UCHAR DiskNguid[16];            /* NVMe NGUID                          */
    UCHAR Mac[6];                   /* burned-in MAC as seen through NDIS OIDs */
    UCHAR MacPad[2];

    /* ---- monitor identity ---- */
    ULONG EdidLength;               /* 128 or 256, 0 = not configured      */
    UCHAR Edid[SYSINFO_MAX_EDID];   /* template returned by the driver     */

    ULONG RegCount;
    SYSINFO_REG_ENTRY Reg[SYSINFO_MAX_REG];
} SYSINFO_CONFIG, *PSYSINFO_CONFIG;

#define SYSINFO_IOCTL_GET_CONFIG CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define SYSINFO_IOCTL_SET_CONFIG CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define SYSINFO_IOCTL_STATUS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

/* ---------------------------------------------------------------- capture */
/*
 * Diagnostic buffers for an I/O path that needs to be reverse engineered.
 * `sysinfoctl capture <file>` dumps whatever the last interesting call was.
 */
#define SYSINFO_CAPTURE_SLOTS  4
#define SYSINFO_CAPTURE_IN     1024
#define SYSINFO_CAPTURE_OUT    8192
#define SYSINFO_CAPTURE_PATH   64
#define SYSINFO_CAPTURE_IOCTL  1u
#define SYSINFO_CAPTURE_WMI    2u

typedef struct _SYSINFO_CAPTURE_ENTRY {
    ULONG Kind;             /* SYSINFO_CAPTURE_*                     */
    ULONG Code;             /* IOCTL code / WMI minor function       */
    ULONG InLength;
    ULONG OutLength;
    ULONG Aux;              /* provider id / last status             */
    ULONG Pad;
    UCHAR In[SYSINFO_CAPTURE_IN];
    UCHAR Out[SYSINFO_CAPTURE_OUT];
    WCHAR Path[SYSINFO_CAPTURE_PATH];
} SYSINFO_CAPTURE_ENTRY, *PSYSINFO_CAPTURE_ENTRY;

typedef struct _SYSINFO_CAPTURE {
    ULONG Count;
    ULONG Pad;
    SYSINFO_CAPTURE_ENTRY Entry[SYSINFO_CAPTURE_SLOTS];
} SYSINFO_CAPTURE, *PSYSINFO_CAPTURE;

#define SYSINFO_IOCTL_CAPTURE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

/* --------------------------------------------------------------- monitor */

/*
 * A ring of "what did that program just do" events, filled from documented
 * kernel notifications (image load, process create/exit) and from the existing
 * Nt* detours (registry value reads, device IOCTLs, system-information
 * classes).  Inactive until `sysinfoctl mon on`.
 */
#define SYSINFO_MON_MAX_PATH    128
#define SYSINFO_MON_MAX_DETAIL  96
#define SYSINFO_MON_IMAGE_CHARS 16
#define SYSINFO_MON_MODULE_CHARS 24
#define SYSINFO_MON_IGNORE_CHARS 160
#define SYSINFO_MON_BATCH_MAX   64

#define SYSINFO_MON_IMAGE   1u   /* image loaded (dll/exe/driver)     */
#define SYSINFO_MON_PROCESS 2u   /* process created / exited          */
#define SYSINFO_MON_REG     3u   /* registry value queried            */
#define SYSINFO_MON_IOCTL   4u   /* device I/O control                */
#define SYSINFO_MON_SYSINFO 5u   /* NtQuerySystemInformation class    */
#define SYSINFO_MON_HANDLE  6u   /* handle opened to a process/thread */
#define SYSINFO_MON_THREAD  7u   /* thread created / exited           */
#define SYSINFO_MON_FILE    8u   /* file opened / created / read      */
#define SYSINFO_MON_KEY     9u   /* registry key opened / written     */
#define SYSINFO_MON_MEM     10u  /* process memory read / written     */
#define SYSINFO_MON_KCB     11u  /* kernel callback registered        */
#define SYSINFO_MON_DEV     12u  /* device object created             */
#define SYSINFO_MON_KCALL   0x40000000u  /* flag: call came from kernel mode */
#define SYSINFO_MON_KERNEL  0x80000000u  /* flags: kernel image     */
#define SYSINFO_MON_KSTACK  0x20000000u  /* flag: a driver frame is on the
                                          * stack behind a user-mode syscall  */

typedef struct _SYSINFO_MON_EVENT {
    ULONG64 Stamp;          /* KeQuerySystemTime (100 ns since 1601)      */
    ULONG   Type;           /* SYSINFO_MON_*                              */
    ULONG   Pid;
    ULONG   Tid;
    ULONG   Op;             /* IOCTL code / sysinfo class / flags         */
    ULONG64 Caller;         /* kernel caller address, 0 = user-mode call  */
    CHAR    Image[SYSINFO_MON_IMAGE_CHARS];
    CHAR    Detail[SYSINFO_MON_MAX_DETAIL];
    WCHAR   Path[SYSINFO_MON_MAX_PATH];
    ULONG64 UserCaller;     /* user-mode syscall return address, 0 if none  */
    CHAR    Module[SYSINFO_MON_MODULE_CHARS]; /* module owning the caller  */
    ULONG   Repeat;         /* extra identical hits folded into this entry  */
    ULONG   Pad;
} SYSINFO_MON_EVENT;

typedef struct _SYSINFO_MON_CONFIG {
    ULONG Enable;
    ULONG PidFilter;        /* 0 = every process                          */
    ULONG KernelImages;     /* also record kernel image loads             */
    ULONG ImageCount;       /* image-name filters (used when PidFilter=0) */
    ULONG SsnRead;          /* ntdll!NtReadVirtualMemory syscall number    */
    ULONG SsnWrite;         /* ntdll!NtWriteVirtualMemory syscall number   */
    CHAR  Images[4][SYSINFO_MON_IMAGE_CHARS];
    ULONG Types;            /* SYSINFO_MON_BIT_*, 0 = store every type     */
    ULONG IgnoreCount;      /* SummaryIgnore[] entries in use              */
    ULONG IgnoreRelative;   /* also fold unrooted (relative) subjects      */
    ULONG IoctlDump;        /* bytes of IOCTL input to hex, 0 = off        */
    ULONG IoctlMatchChars;
    WCHAR SummaryIgnore[4][SYSINFO_MON_IGNORE_CHARS];
    WCHAR IoctlMatch[32];   /* only dump for devices whose name matches    */
    ULONG UnsafeHooksEnabled; /* second opt-in, always zero in normal builds */
} SYSINFO_MON_CONFIG, *PSYSINFO_MON_CONFIG;

/* One bit per SYSINFO_MON_*.  The ring only stores selected types; the
 * summary table below always sees everything. */
#define SYSINFO_MON_BIT_IMAGE   0x0001u
#define SYSINFO_MON_BIT_PROCESS 0x0002u
#define SYSINFO_MON_BIT_REG     0x0004u
#define SYSINFO_MON_BIT_IOCTL   0x0008u
#define SYSINFO_MON_BIT_SYSINFO 0x0010u
#define SYSINFO_MON_BIT_HANDLE  0x0020u
#define SYSINFO_MON_BIT_THREAD  0x0040u
#define SYSINFO_MON_BIT_FILE    0x0080u
#define SYSINFO_MON_BIT_KEY     0x0100u
#define SYSINFO_MON_BIT_MEM     0x0200u
#define SYSINFO_MON_BIT_KCB     0x0400u
#define SYSINFO_MON_BIT_DEV     0x0800u
#define SYSINFO_MON_BITS_ALL    0x0FFFu
/* Ring default: everything except the three that arrive hundreds of times a
 * second.  The summary always records all of them. */
#define SYSINFO_MON_BITS_QUIET  (SYSINFO_MON_BITS_ALL & \
                                 ~(SYSINFO_MON_BIT_MEM | SYSINFO_MON_BIT_THREAD | \
                                   SYSINFO_MON_BIT_HANDLE))

/* ------------------------------------------------------------- summary */
/*
 * A fixed table of distinct (type, process image, subject) observations with
 * a hit count.  It never wraps: one entry per distinct thing the target did,
 * so it survives a session that produces millions of events.  The subject is
 * the path, or "target <image>"/"pid <n>" for handles and memory.
 */
#define SYSINFO_SUMMARY_SLOTS     8192
#define SYSINFO_SUMMARY_SUBJECT   160

typedef struct _SYSINFO_SUMMARY_ENTRY {
    ULONG64 First;
    ULONG64 Last;
    ULONG   Count;
    ULONG   Pid;
    ULONG   Type;           /* SYSINFO_MON_*                       */
    ULONG   Access;         /* last access mask seen               */
    CHAR    Image[SYSINFO_MON_IMAGE_CHARS];
    CHAR    Module[SYSINFO_MON_MODULE_CHARS];
    WCHAR   Subject[SYSINFO_SUMMARY_SUBJECT];
} SYSINFO_SUMMARY_ENTRY, *PSYSINFO_SUMMARY_ENTRY;

#define SYSINFO_SUMMARY_BATCH 24

typedef struct _SYSINFO_SUMMARY_REQ {
    ULONG Start;            /* first slot to read                  */
    ULONG Max;              /* entries wanted (<= BATCH)           */
} SYSINFO_SUMMARY_REQ, *PSYSINFO_SUMMARY_REQ;

typedef struct _SYSINFO_SUMMARY_HEAD {
    ULONG AbiVersion;
    ULONG Total;            /* slots in use                        */
    ULONG Next;             /* pass back as Start; 0 = no more     */
    ULONG Overflow;         /* subjects dropped, table was full    */
    ULONG Suppressed;       /* hits folded away by SummaryIgnore   */
    ULONG Count;            /* entries that follow                 */
    /* SYSINFO_SUMMARY_ENTRY Entries[Count]; */
} SYSINFO_SUMMARY_HEAD, *PSYSINFO_SUMMARY_HEAD;

typedef struct _SYSINFO_MON_BATCH {
    ULONG Count;
    ULONG Dropped;
    ULONG Enabled;
    ULONG PidFilter;
    /* SYSINFO_MON_EVENT Events[Count]; */
} SYSINFO_MON_BATCH, *PSYSINFO_MON_BATCH;

#define SYSINFO_IOCTL_MON_CONFIG CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define SYSINFO_IOCTL_MON_READ   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define SYSINFO_IOCTL_MON_SUMMARY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

/* --------------------------------------------------------------- guard */
/*
 * Policy-driven access guard.  The driver watches the target process images
 * and denies access to configured path/registry substrings or browser
 * process handles.  Defaults are built in; the CLI only flips the mode.
 */
#define SYSINFO_GUARD_OFF      0u
#define SYSINFO_GUARD_AUDIT    1u
#define SYSINFO_GUARD_ENFORCE  2u

#define SYSINFO_GUARD_MAX_TARGETS  8
#define SYSINFO_GUARD_MAX_PATHS   16
#define SYSINFO_GUARD_MAX_PROCS    8
#define SYSINFO_GUARD_TARGET_CHARS 16
#define SYSINFO_GUARD_PATH_CHARS   260

typedef struct _SYSINFO_GUARD_CONFIG {
    ULONG Mode;                 /* SYSINFO_GUARD_* */
    ULONG TargetCount;
    CHAR  Targets[SYSINFO_GUARD_MAX_TARGETS][SYSINFO_GUARD_TARGET_CHARS];
    ULONG PathCount;            /* matching is case-insensitive substring */
    WCHAR Paths[SYSINFO_GUARD_MAX_PATHS][SYSINFO_GUARD_PATH_CHARS];
    ULONG ProcessCount;
    CHAR  Processes[SYSINFO_GUARD_MAX_PROCS][SYSINFO_GUARD_TARGET_CHARS];
} SYSINFO_GUARD_CONFIG, *PSYSINFO_GUARD_CONFIG;

typedef struct _SYSINFO_GUARD_STATUS {
    ULONG AbiVersion;
    ULONG Mode;
    ULONG Targets;
    ULONG Paths;
    ULONG Processes;
    ULONG Checks;
    ULONG Denied;
    ULONG Audited;
} SYSINFO_GUARD_STATUS, *PSYSINFO_GUARD_STATUS;

#define SYSINFO_IOCTL_GUARD_CONFIG CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define SYSINFO_IOCTL_GUARD_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x831, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

/* SYSINFO_IOCTL_READ_MEM: input SYSINFO_READ_REQ, output is the raw bytes (<= 64 KiB). */
#define SYSINFO_IOCTL_READ_MEM   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define SYSINFO_READ_MAX         0x10000

typedef struct _SYSINFO_READ_REQ {
    ULONG64 Address;
    ULONG   Length;
    ULONG   Pad;
} SYSINFO_READ_REQ, *PSYSINFO_READ_REQ;

/* Returned by SYSINFO_IOCTL_STATUS: lets the CLI detect a stale .sys. */
#define SYSINFO_ABI_VERSION   18
#define SYSINFO_HOOKS_TOTAL   4

/* SYSINFO_STATUS.Reserved carries a stage code. */
#define SYSINFO_STAGE_NONE        0u   /* not attempted yet            */
#define SYSINFO_STAGE_OK          1u   /* syscall table found          */
#define SYSINFO_STAGE_NO_ANCHOR   2u   /* an anchor export is missing   */
#define SYSINFO_STAGE_NO_SSN      3u   /* could not read a Zw* syscall number */
#define SYSINFO_STAGE_NO_IMAGE    4u   /* ntoskrnl base not found       */
#define SYSINFO_STAGE_NO_TEXT     5u   /* ntoskrnl .text not found      */
#define SYSINFO_STAGE_IRQL        6u   /* calibration ran above PASSIVE */
#define SYSINFO_STAGE_NO_TABLE    7u   /* scan finished, no layout matched */
#define SYSINFO_STAGE_HVCI        8u   /* Memory Integrity blocks kernel text writes */
#define SYSINFO_STAGE_WRITE       9u   /* could not write read-only kernel text     */
#define SYSINFO_STAGE_HYPERVISOR  10u  /* VBS/HyperGuard is running                 */

/* How the driver got write access to read-only kernel text. */
#define SYSINFO_WRITE_NONE        0u
#define SYSINFO_WRITE_MDL         1u   /* writable second mapping via an MDL */
#define SYSINFO_WRITE_CR0         2u   /* CR0.WP window (only when CET is off) */

/* Diag layout:
 *   0..6   driver object facts      7..17  syscall calibration + anchors
 *   18..29 window around the table  30..33 detour counters
 *   34..49 last unmatched key path  50..57 last unmatched value name
 *   58..59 their byte lengths        60..61 last key-name failure
 *   62 resolved query-key routine    63 1 = came from the service table
 *   64 mssmbios device   65 its IRP_MJ_SYSTEM_CONTROL
 *   66 WMI queries seen   67 last buffer kind   68 last buffer length
 *   69 signature offset   70 last status        71 rewrites applied
 *   72 WmiInit status     73 1 = dispatch is inside the mssmbios image
 *   74 IOCTLs seen on the WMI data device
 */
#define SYSINFO_DIAG_COUNT 80
#define SYSINFO_DIAG_STATS  30
#define SYSINFO_DIAG_PATH   34
#define SYSINFO_DIAG_NAME   50
#define SYSINFO_DIAG_PATHLEN 58
#define SYSINFO_DIAG_NAMELEN 59
#define SYSINFO_DIAG_KEYSTATUS 60
#define SYSINFO_DIAG_KEYRET    61
#define SYSINFO_DIAG_QKADDR    62
#define SYSINFO_DIAG_QKVIA     63
#define SYSINFO_DIAG_WMI_DEV      64
#define SYSINFO_DIAG_WMI_MJ       65
#define SYSINFO_DIAG_WMI_CALLS    66
#define SYSINFO_DIAG_WMI_BUFKIND  67   /* 1=SystemBuffer 2=MdlAddress 3=UserBuffer */
#define SYSINFO_DIAG_WMI_BUFLEN   68
#define SYSINFO_DIAG_WMI_HIT      69   /* offset of the real table, -1 = not found */
#define SYSINFO_DIAG_WMI_STATUS   70
#define SYSINFO_DIAG_WMI_APPLIED  71
#define SYSINFO_DIAG_WMI_INIT     72
#define SYSINFO_DIAG_WMI_INIMAGE  73
#define SYSINFO_DIAG_WMI_IOCTL    74
#define SYSINFO_DIAG_MON_ENABLED  75
#define SYSINFO_DIAG_MON_EVENTS   76
#define SYSINFO_DIAG_MON_DROPPED  77
#define SYSINFO_DIAG_MON_HOOKS    78
#define SYSINFO_DIAG_MON_OPEN     35   /* NtOpenProcess/NtOpenThread calls seen */
#define SYSINFO_DIAG_MON_OPEN_EV  36   /* ...that produced a handle event */
#define SYSINFO_DIAG_TRACE_HOOKS  37   /* file/key/mem/callback hooks live */
#define SYSINFO_DIAG_OB_STATUS    38   /* ObRegisterCallbacks result */

typedef struct _SYSINFO_STATUS {
    ULONG AbiVersion;
    ULONG HooksInstalled;
    ULONG HasConfig;
    ULONG Reserved;                 /* SYSINFO_STAGE_* */
    ULONG CiOptions;                /* raw SystemCodeIntegrityInformation options */
    ULONG HvciEnforced;             /* Memory Integrity blocks kernel text writes  */
    ULONG CetEnabled;               /* CR4.CET (kernel shadow stacks) is on        */
    ULONG PatchMethod;              /* SYSINFO_WRITE_*                             */
    ULONG UnsafeHooksImplemented;   /* inline-hook code is present, not a safety claim */
    ULONG UnsafeHooksEnabled;       /* second runtime opt-in, zero by default */
    ULONG64 Diag[SYSINFO_DIAG_COUNT];  /* driver-object + calibration diagnostics */
} SYSINFO_STATUS, *PSYSINFO_STATUS;
