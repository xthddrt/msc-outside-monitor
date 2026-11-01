/* subject.h - fixed-width subject equality and folding for the monitor summary.
 *
 * Kept free of WDK headers so the same code the driver uses can be compiled and
 * exercised by a host-side test (compat/tests).
 */
#pragma once
#include <wchar.h>

/*
 * Does this summary entry describe the same observation?
 *
 * Both subject arrays are zero-filled to their full fixed width by the caller
 * (SumSubject zeroes the event's subject buffer, SummaryAdd zeroes the entry),
 * so equality over the whole width is the subject comparison the table needs.
 * Comparing a pointer-sized prefix instead folds every subject that shares its
 * first characters - which for device paths is "\Dev" - into the wrong row.
 */
static __inline int MonSummaryEntryMatches(unsigned entryType, unsigned entryPid,
                                           const wchar_t* entrySubject,
                                           unsigned eventType, unsigned eventPid,
                                           const wchar_t* subject, unsigned chars)
{
    unsigned index;

    if (entryType != eventType || entryPid != eventPid) return 0;
    for (index = 0; index < chars; index++) {
        if (entrySubject[index] != subject[index]) return 0;
    }
    return 1;
}

/* ASCII upcase for the fold's fixed characters, so this header stays OS-free. */
static __inline wchar_t MonFoldUpcase(wchar_t value)
{
    return (value >= L'a' && value <= L'z') ? (wchar_t)(value - (L'a' - L'A')) : value;
}

/* Terminate the folded subject at From and clear the rest of the fixed width. */
static __inline void MonZeroSubjectTail(wchar_t* subject, unsigned chars, unsigned from)
{
    while (from < chars) subject[from++] = 0;
}

/*
 * A name relative to the program's directory is the program's own file.  Keep
 * the information but collapse the tail: "Data\Packs\Skill_00001.ms" becomes
 * "Data\...", and a debug-symbol probe "ntdll.pdb" becomes "*.pdb". Names with
 * neither a separator nor a .pdb suffix are short and unique enough to keep.
 *
 * The characters after the new terminator are cleared: SummaryAdd compares the
 * subject over its whole fixed width, so a stale tail would make two identical
 * observations land in different rows.
 */
static __inline void MonFoldRelative(wchar_t* subject, unsigned chars)
{
    unsigned i, n;

    if (subject == 0 || chars == 0) return;
    if (subject[0] == L'\\') return;
    if (subject[0] != 0 && subject[1] == L':') return;

    for (i = 0; i < chars && subject[i] != 0; i++) {
        if (subject[i] == L'\\') {
            if (i + 4 < chars) {
                subject[i]     = L'\\';
                subject[i + 1] = L'.';
                subject[i + 2] = L'.';
                subject[i + 3] = L'.';
                MonZeroSubjectTail(subject, chars, i + 4);
            } else {
                MonZeroSubjectTail(subject, chars, i);
            }
            return;
        }
    }

    if (i >= chars || i < 4) return;
    if (MonFoldUpcase(subject[i - 4]) != L'.') return;
    if (MonFoldUpcase(subject[i - 3]) != L'P') return;
    if (MonFoldUpcase(subject[i - 2]) != L'D') return;
    if (MonFoldUpcase(subject[i - 1]) != L'B') return;

    for (n = 0; n < 5 && n + 1 < chars; n++) subject[n] = L"*.pdb"[n];
    MonZeroSubjectTail(subject, chars, n);
}
