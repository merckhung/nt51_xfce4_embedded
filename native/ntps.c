/* SPDX-License-Identifier: GPL-2.0-only */
/* BusyBox ps backend for this NT 5.1 port. All rows come from a live NT snapshot.
 * Linux /proc is absent. Unknown ownership/TTY/state is displayed as '?' rather
 * than inventing Linux metadata. CPU is lifetime CPU / elapsed wall time.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../tests/nt_syscall_defs.h"

typedef struct {
    ULONG next, threads;
    LARGE_INTEGER spare[3], created, user, kernel;
    UNICODE_STRING image;
    LONG priority;
    HANDLE pid, parent;
    ULONG handles, session, directory_base;
    ULONG peak_virtual, virtual_size, faults, peak_working_set, working_set;
    ULONG pool[4], pagefile, peak_pagefile, private_pages;
    LARGE_INTEGER io[6];
} NT_PROCESS;
_Static_assert(sizeof(NT_PROCESS) == 184, "NT 5.1 x86 process layout");
_Static_assert(offsetof(NT_PROCESS, pid) == 68, "NT process ID layout");

typedef struct {
    ULONG magic;
    int applet, argc, envc;
    char elf[260], cwd[260];
    int arg_offset[64], env_offset[128];
    char strings[8192];
} SPAWN_ARGUMENTS;

static NTSTATUS open_process(ULONG pid, HANDLE *handle) {
    OBJECT_ATTRIBUTES attributes = { .Length = sizeof(attributes) };
    CLIENT_ID id = { (HANDLE)pid, NULL };
    ULONG args[4] = { (ULONG)handle, 0x410, (ULONG)&attributes, (ULONG)&id };
    NTSTATUS status = DoNtSyscall(122, args, 4);
    if (!NT_SUCCESS(status)) { args[1] = 0x400; status = DoNtSyscall(122, args, 4); }
    return status;
}

static int remote_read(HANDLE handle, const void *address, void *buffer, ULONG length) {
    ULONG got = 0;
    ULONG args[5] = { (ULONG)handle, (ULONG)address, (ULONG)buffer, length, (ULONG)&got };
    return NT_SUCCESS(DoNtSyscall(186, args, 5)) && got == length;
}

static void unicode_text(const UNICODE_STRING *text, char *output, unsigned size) {
    unsigned length = text->Length / 2;
    if (length >= size) length = size - 1;
    for (unsigned i = 0; i < length; i++)
        output[i] = text->Buffer[i] >= 32 && text->Buffer[i] < 127 ? text->Buffer[i] : '?';
    output[length] = 0;
}

static int command_line(HANDLE handle, char *output, unsigned size) {
    SPAWN_ARGUMENTS arguments;
    if (remote_read(handle, (void *)0x014f0000, &arguments, sizeof(arguments)) &&
        arguments.magic == 0x5350574e && arguments.argc > 0 && arguments.argc <= 64) {
        unsigned used = 0;
        for (int i = 0; i < arguments.argc; i++) {
            int offset = arguments.arg_offset[i];
            if (offset < 0 || offset >= sizeof(arguments.strings)) return 0;
            if (used && used + 1 < size) output[used++] = ' ';
            while (offset < sizeof(arguments.strings) && arguments.strings[offset] && used + 1 < size)
                output[used++] = arguments.strings[offset++];
        }
        output[used] = 0;
        return used != 0;
    }
    /* Native init/loader processes carry their arguments in the NT PEB. */
    ULONG basic[6], parameters = 0, flags = 0;
    UNICODE_STRING command;
    unsigned short wide[1024];
    if (!NT_SUCCESS(Nt_QueryInformationProcess(handle, 0, basic, sizeof(basic), NULL)) ||
        !remote_read(handle, (void *)(basic[1] + 0x10), &parameters, sizeof(parameters)) || !parameters ||
        !remote_read(handle, (void *)(parameters + 8), &flags, sizeof(flags)) ||
        !remote_read(handle, (void *)(parameters + 0x40), &command, sizeof(command)) || !command.Length)
        return 0;
    if (!(flags & 1)) command.Buffer = (unsigned short *)(parameters + (ULONG)command.Buffer);
    if (command.Length > sizeof(wide) - 2) command.Length = sizeof(wide) - 2;
    if (!remote_read(handle, command.Buffer, wide, command.Length)) return 0;
    command.Buffer = wide;
    unicode_text(&command, output, size);
    return output[0] != 0;
}

static void owner(HANDLE process, char *output, unsigned size) {
    HANDLE token;
    unsigned char buffer[256];
    ULONG length;
    strcpy(output, "?");
    if (!NT_SUCCESS(Nt_OpenProcessToken(process, 8, &token))) return;
    if (NT_SUCCESS(Nt_QueryInformationToken(token, 1, buffer, sizeof(buffer), &length))) {
        unsigned char *sid = *(unsigned char **)buffer;
        if (sid >= buffer && sid + 12 <= buffer + sizeof(buffer) && sid[0] == 1 && sid[1] &&
            sid + 8 + sid[1] * 4 <= buffer + sizeof(buffer)) {
            unsigned authority = 0;
            for (unsigned i = 2; i < 8; i++) authority = (authority << 8) | sid[i];
            ULONG sub = *(ULONG *)(sid + 8);
            if (authority == 5 && sid[1] == 1 && sub == 18) strcpy(output, "SYSTEM");
            else snprintf(output, size, "SID:%lu", *(ULONG *)(sid + 8 + (sid[1] - 1) * 4));
        }
    }
    Nt_Close(token);
}

int ntps_main(int argc, char **argv) {
    int full = 0;
    for (int i = 1; i < argc; i++) {
        const char *option = argv[i];
        if (*option == '-') option++;
        if (!*option) goto usage;
        while (*option) {
            if (*option == 'u' || *option == 'f' || *option == 'l') full = 1;
            else if (*option != 'a' && *option != 'x' && *option != 'A' && *option != 'e' && *option != 'w') goto usage;
            option++;
        }
    }
    ULONG capacity = 65536, used = 0;
    unsigned char *snapshot = NULL;
    NTSTATUS status;
    do {
        unsigned char *grown = realloc(snapshot, capacity);
        if (!grown) { free(snapshot); fprintf(stderr, "ps: out of memory\n"); return 1; }
        snapshot = grown;
        status = Nt_QuerySystemInformation(5, snapshot, capacity, &used);
        if (status != STATUS_INFO_LENGTH_MISMATCH) break;
        capacity = used > capacity ? used + 4096 : capacity * 2;
    } while (capacity <= 4194304);
    if (!NT_SUCCESS(status) || used > capacity || used < sizeof(NT_PROCESS)) {
        fprintf(stderr, "ps: NT process query failed: 0x%08lx\n", (ULONG)status);
        free(snapshot); return 1;
    }
    ULONG basic[11] = {0};
    LARGE_INTEGER now;
    int have_time = NT_SUCCESS(Nt_QuerySystemTime(&now));
    uint64_t memory = NT_SUCCESS(Nt_QuerySystemInformation(0, basic, sizeof(basic), NULL))
        ? (uint64_t)basic[2] * basic[3] : 0;
    puts(full ? "USER        PID %CPU %MEM      VSZ    RSS TTY STAT START TIME COMMAND" : "  PID USER       COMMAND");
    unsigned offset = 0;
    while (offset + sizeof(NT_PROCESS) <= used) {
        NT_PROCESS *process = (NT_PROCESS *)(snapshot + offset);
        unsigned record_size = process->next ? process->next : used - offset;
        if (record_size < sizeof(*process) || record_size > used - offset) { free(snapshot); return 1; }
        char command[1024] = "", user[24] = "?", start[16] = "?", cpu[24] = "?", mem[24] = "?";
        HANDLE handle;
        if (NT_SUCCESS(open_process((ULONG)process->pid, &handle))) {
            command_line(handle, command, sizeof(command)); owner(handle, user, sizeof(user)); Nt_Close(handle);
        }
        if (!command[0]) {
            if (process->image.Buffer && (unsigned char *)process->image.Buffer >= snapshot &&
                (unsigned char *)process->image.Buffer + process->image.Length <= snapshot + used)
                unicode_text(&process->image, command, sizeof(command));
            else strcpy(command, process->pid ? "[unknown]" : "[Idle]");
        }
        uint64_t cpu_time = process->user.QuadPart + process->kernel.QuadPart;
        if (have_time && process->created.QuadPart > 0 && now.QuadPart > process->created.QuadPart) {
            unsigned tenths = cpu_time * 1000 / (now.QuadPart - process->created.QuadPart);
            snprintf(cpu, sizeof(cpu), "%u.%u", tenths / 10, tenths % 10);
        }
        if (memory) {
            unsigned tenths = (uint64_t)process->working_set * 1000 / memory;
            snprintf(mem, sizeof(mem), "%u.%u", tenths / 10, tenths % 10);
        }
        if (process->created.QuadPart >= 116444736000000000LL) {
            time_t seconds = (process->created.QuadPart - 116444736000000000LL) / 10000000;
            struct tm stamp;
            if (gmtime_r(&seconds, &stamp)) strftime(start, sizeof(start), "%H:%M", &stamp);
        }
        char state = '?';
        if (process->threads && record_size >= sizeof(*process) + process->threads * 64) {
            state = 'W';
            for (unsigned i = 0; i < process->threads; i++) {
                ULONG thread_state = *(ULONG *)((unsigned char *)process + sizeof(*process) + i * 64 + 52);
                if (thread_state == 1 || thread_state == 2 || thread_state == 3) state = 'R';
            }
        }
        unsigned seconds = cpu_time / 10000000;
        if (full) printf("%-10s %5lu %4s %4s %8lu %6lu   ?   %c  %5s %u:%02u %s\n", user,
                         (ULONG)process->pid, cpu, mem, process->virtual_size / 1024,
                         process->working_set / 1024, state, start, seconds / 60, seconds % 60, command);
        else printf("%5lu %-10s %s\n", (ULONG)process->pid, user, command);
        if (!process->next) break;
        offset += process->next;
    }
    free(snapshot); return 0;
usage:
    fprintf(stderr, "usage: ps [aux | -ef | -A] [-w]\n");
    return 1;
}
