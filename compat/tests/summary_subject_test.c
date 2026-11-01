/* summary_subject_test.c - SummaryAdd must compare the whole summary subject.
 *
 * Two device paths from the same process share their first four characters
 * ("\Dev"). Comparing only a pointer-sized prefix folded the second observation
 * into the first row. This drives the same helper the driver uses.
 */
#include "../driver/subject.h"
#include <stdio.h>

#define SUBJECT_CHARS 160
#define SYSINFO_MON_FILE 8u
#define SYSINFO_MON_KEY 9u

static int failures;

static void check(int condition, const char* name)
{
    if (!condition) {
        printf("FAIL: %s\n", name);
        failures++;
    }
}

int main(void)
{
    wchar_t first[SUBJECT_CHARS] = L"\\Device\\HarddiskVolume3\\Users\\alice\\AppData\\Local\\Google\\Chrome\\User Data\\A";
    wchar_t second[SUBJECT_CHARS] = L"\\Device\\HarddiskVolume3\\Users\\alice\\AppData\\Local\\Google\\Chrome\\User Data\\B499";
    wchar_t blank[SUBJECT_CHARS] = L"";

    /* Same type and PID, same first four characters, different observations. */
    check(!MonSummaryEntryMatches(SYSINFO_MON_FILE, 1, first, SYSINFO_MON_FILE, 1, second,
                                  SUBJECT_CHARS),
          "subjects that differ after the first four characters do not match");
    check(!MonSummaryEntryMatches(SYSINFO_MON_FILE, 1, second, SYSINFO_MON_FILE, 1, first,
                                  SUBJECT_CHARS),
          "the comparison is symmetric");
    check(MonSummaryEntryMatches(SYSINFO_MON_FILE, 1, first, SYSINFO_MON_FILE, 1, first,
                                 SUBJECT_CHARS),
          "an identical subject matches");
    check(MonSummaryEntryMatches(SYSINFO_MON_FILE, 1, blank, SYSINFO_MON_FILE, 1, blank,
                                 SUBJECT_CHARS),
          "two empty subjects match");
    check(!MonSummaryEntryMatches(SYSINFO_MON_FILE, 1, first, SYSINFO_MON_KEY, 1, first,
                                  SUBJECT_CHARS),
          "a different event type does not match");
    check(!MonSummaryEntryMatches(SYSINFO_MON_FILE, 1, first, SYSINFO_MON_FILE, 2, first,
                                  SUBJECT_CHARS),
          "a different process does not match");

    if (failures != 0) return 1;
    printf("summary subject regression passed\n");
    return 0;
}
