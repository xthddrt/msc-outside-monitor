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

    /*
     * The driver fills the subject, folds it, and SummaryAdd stores only up to
     * the terminator with the rest zeroed.  Every fold must therefore leave the
     * whole width defined, or the same observation never matches its own row.
     */
    {
        wchar_t subject[SUBJECT_CHARS] = L"Data\\Packs\\Skill_00001.ms";
        wchar_t other[SUBJECT_CHARS] = L"Data\\Packs\\Skill_00002.ms";
        wchar_t stored[SUBJECT_CHARS];
        wchar_t different[SUBJECT_CHARS] = L"Logs\\Client.log";
        unsigned index;
        unsigned length;

        MonFoldRelative(subject, SUBJECT_CHARS);
        check(wcscmp(subject, L"Data\\...") == 0,
              "a relative path folds at its first separator");
        for (index = 0; index < SUBJECT_CHARS; index++) stored[index] = 0;
        for (length = 0; length + 1 < SUBJECT_CHARS && subject[length] != 0; length++) {
            stored[length] = subject[length];
        }
        check(MonSummaryEntryMatches(SYSINFO_MON_FILE, 1, stored, SYSINFO_MON_FILE, 1, subject,
                                     SUBJECT_CHARS),
              "a folded relative path matches the row it created");

        MonFoldRelative(other, SUBJECT_CHARS);
        check(wcscmp(other, L"Data\\...") == 0,
              "files under the same directory fold to the same text");
        check(MonSummaryEntryMatches(SYSINFO_MON_FILE, 1, stored, SYSINFO_MON_FILE, 1, other,
                                     SUBJECT_CHARS),
              "two relative paths under one directory share a row");

        MonFoldRelative(different, SUBJECT_CHARS);
        check(wcscmp(different, L"Logs\\...") == 0,
              "a different directory keeps its own text");
        check(!MonSummaryEntryMatches(SYSINFO_MON_FILE, 1, stored, SYSINFO_MON_FILE, 1, different,
                                      SUBJECT_CHARS),
              "subjects that fold to different text do not match");
    }
    {
        wchar_t probe[SUBJECT_CHARS] = L"ntdll.pdb";
        wchar_t otherProbe[SUBJECT_CHARS] = L"client12.pdb";
        wchar_t stored[SUBJECT_CHARS];
        unsigned index;

        MonFoldRelative(probe, SUBJECT_CHARS);
        MonFoldRelative(otherProbe, SUBJECT_CHARS);
        check(wcscmp(probe, L"*.pdb") == 0 && wcscmp(otherProbe, L"*.pdb") == 0,
              "debug-symbol probes fold to *.pdb");
        for (index = 0; index < SUBJECT_CHARS; index++) {
            stored[index] = index < 5 ? L"*.pdb"[index] : 0;
        }
        check(MonSummaryEntryMatches(SYSINFO_MON_FILE, 1, stored, SYSINFO_MON_FILE, 1, otherProbe,
                                     SUBJECT_CHARS),
              "two symbol probes for different names share a row");
    }
    {
        wchar_t absolute[SUBJECT_CHARS] = L"\\Device\\HarddiskVolume3\\Data\\a.ms";
        wchar_t drive[SUBJECT_CHARS] = L"C:\\logs\\a.ms";

        MonFoldRelative(absolute, SUBJECT_CHARS);
        MonFoldRelative(drive, SUBJECT_CHARS);
        check(wcscmp(absolute, L"\\Device\\HarddiskVolume3\\Data\\a.ms") == 0 &&
              wcscmp(drive, L"C:\\logs\\a.ms") == 0,
              "rooted subjects are not folded");
    }

    if (failures != 0) return 1;
    printf("summary subject regression passed\n");
    return 0;
}
