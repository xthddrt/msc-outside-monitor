/* subject.h - fixed-width subject equality for the monitor summary.
 *
 * Kept free of WDK headers so the same comparison the driver uses can be
 * compiled and exercised by a host-side test (compat/tests).
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
