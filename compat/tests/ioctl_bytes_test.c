/* ioctl_bytes_test.c - the MON_READ / MON_SUMMARY response size must follow the
 * records produced, not the caller's buffer.
 *
 * Both IOCTLs are METHOD_BUFFERED, so the I/O manager copies exactly
 * IoStatus.Information bytes back. Reporting the output buffer length handed the
 * caller untouched pool bytes past the last record; these helpers are what the
 * driver now uses for Information.
 */
#include "../shared/sysinfo.h"
#include <stdio.h>

static int failures;

static void check(int condition, const char *name)
{
    if (!condition) {
        printf("FAIL: %s\n", name);
        failures++;
    }
}

int main(void)
{
    const ULONG readOne = sizeof(SYSINFO_MON_BATCH) + sizeof(SYSINFO_MON_EVENT);
    const ULONG readThree = sizeof(SYSINFO_MON_BATCH) + 3 * sizeof(SYSINFO_MON_EVENT);
    const ULONG readFull = sizeof(SYSINFO_MON_BATCH) +
                           SYSINFO_MON_BATCH_MAX * sizeof(SYSINFO_MON_EVENT);
    const ULONG summaryOne = sizeof(SYSINFO_SUMMARY_HEAD) + sizeof(SYSINFO_SUMMARY_ENTRY);
    const ULONG summaryThree = sizeof(SYSINFO_SUMMARY_HEAD) + 3 * sizeof(SYSINFO_SUMMARY_ENTRY);
    const ULONG summaryFull = sizeof(SYSINFO_SUMMARY_HEAD) +
                              SYSINFO_SUMMARY_BATCH * sizeof(SYSINFO_SUMMARY_ENTRY);

    check(SysinfoMonReadBytes(0) == sizeof(SYSINFO_MON_BATCH), "empty MON_READ is the batch header");
    check(SysinfoMonReadBytes(1) == readOne, "one MON_READ record");
    check(SysinfoMonReadBytes(3) == readThree, "three MON_READ records");
    check(SysinfoMonReadBytes(1) < readFull, "a short MON_READ does not report the whole buffer");
    check(SysinfoMonReadBytes(SYSINFO_MON_BATCH_MAX) == readFull, "a full MON_READ is the whole buffer");

    check(SysinfoSummaryBytes(0) == sizeof(SYSINFO_SUMMARY_HEAD), "empty MON_SUMMARY is the head");
    check(SysinfoSummaryBytes(1) == summaryOne, "one MON_SUMMARY row");
    check(SysinfoSummaryBytes(3) == summaryThree, "three MON_SUMMARY rows");
    check(SysinfoSummaryBytes(1) < summaryFull, "a short MON_SUMMARY does not report the whole buffer");
    check(SysinfoSummaryBytes(SYSINFO_SUMMARY_BATCH) == summaryFull, "a full MON_SUMMARY is the whole buffer");

    if (failures != 0) return 1;
    printf("ioctl byte-count regression passed\n");
    return 0;
}
