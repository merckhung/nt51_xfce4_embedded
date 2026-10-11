/* SPDX-License-Identifier: GPL-2.0-only */
/* Translate the NT memory/process counters available to Linux sysinfo callers.
 * Linux load averages, cache categories and swap accounting are not provided.
 */
#include <stdlib.h>
#include "../tests/nt_syscall_defs.h"

long nt_sysinfo(unsigned long *info) {
    if (!info) return -14;
    ULONG basic[11], performance[128], length;
    if (!NT_SUCCESS(Nt_QuerySystemInformation(0, basic, sizeof(basic), NULL)) ||
        !NT_SUCCESS(Nt_QuerySystemInformation(2, performance, sizeof(performance), &length)) || length < 48)
        return -5;
    ULONG capacity = 65536;
    unsigned char *snapshot = NULL;
    NTSTATUS status;
    do {
        unsigned char *grown = realloc(snapshot, capacity);
        if (!grown) { free(snapshot); return -12; }
        snapshot = grown;
        status = Nt_QuerySystemInformation(5, snapshot, capacity, &length);
        if (status != STATUS_INFO_LENGTH_MISMATCH) break;
        capacity = length > capacity ? length + 4096 : capacity * 2;
    } while (capacity <= 4194304);
    if (!NT_SUCCESS(status) || length > capacity) { free(snapshot); return -5; }
    unsigned processes = 0, offset = 0;
    while (offset + 184 <= length) {
        processes++;
        ULONG next = *(ULONG *)(snapshot + offset);
        if (!next) break;
        if (next < 184 || next > length - offset) { free(snapshot); return -5; }
        offset += next;
    }
    free(snapshot);
    volatile ULONG *interrupt_time = (volatile ULONG *)0x7ffe0008;
    ULONG low, high;
    do { high = interrupt_time[1]; low = interrupt_time[0]; } while (high != interrupt_time[2]);
    for (unsigned i = 0; i < 16; i++) info[i] = 0;
    info[0] = (((uint64_t)high << 32) | low) / 10000000;
    info[4] = basic[3];
    info[5] = performance[11];
    info[10] = processes > 65535 ? 65535 : processes;
    info[13] = basic[2];
    return 0;
}
