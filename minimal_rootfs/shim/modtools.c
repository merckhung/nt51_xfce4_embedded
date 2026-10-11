/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * minimal_rootfs/shim/modtools.c
 * XDDK module tools for the embedded2 BusyBox shell:
 *   insmod <file.sys> [name]   load a kernel module   (NtLoadDriver)
 *   rmmod <name>               unload a kernel module (NtUnloadDriver)
 *   lsmod [-a]                 list loaded kernel modules
 *   modinfo <file.sys>         print .xinfo metadata from a module file
 *   xddkctl <dev> <cmd> [arg]  send IOCTLs to an XDDK device
 * Dispatched in-process from sys_execve (nt_linux_shim.c). Uses NT system
 * services directly through DoNtSyscall; output through MUSL stdio.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../native/include/xddk_ioctl.h"

extern long DoNtSyscall(unsigned long id, void *args, unsigned int num_args);
extern void shim_translate_path(const char *posix_path, unsigned short *nt_buf, unsigned int max_chars);

/* NT 5.1 system service numbers (see native/ntdll/syscalls.asm) */
#define NTSYS_AdjustPrivilegesToken   11
#define NTSYS_Close                   25
#define NTSYS_CreateFile              37
#define NTSYS_CreateKey               41
#define NTSYS_DeleteKey               63
#define NTSYS_DeviceIoControlFile     66
#define NTSYS_LoadDriver              97
#define NTSYS_OpenProcessToken       123
#define NTSYS_QuerySystemInformation 173
#define NTSYS_SetValueKey            247
#define NTSYS_UnloadDriver           262

typedef long NTSTATUS;
typedef void *HANDLE;
#define NT_OK(s) (((long)(s)) >= 0)

typedef struct { unsigned short Length, MaximumLength; unsigned short *Buffer; } NTUSTR;
typedef struct {
    unsigned long Length; HANDLE RootDirectory; NTUSTR *ObjectName;
    unsigned long Attributes; void *SecurityDescriptor; void *SecurityQos;
} NTOA;
typedef struct { union { NTSTATUS Status; void *Pointer; } u; unsigned long Information; } NTIOSB;

#define OBJ_CASE_INSENSITIVE      0x40
#define KEY_ALL_ACCESS            0xF003F
#define REG_OPTION_VOLATILE       1
#define REG_EXPAND_SZ             2
#define REG_DWORD                 4
#define SE_LOAD_DRIVER_PRIVILEGE  10
#define SE_PRIVILEGE_ENABLED      2
#define TOKEN_ADJUST_PRIVILEGES   0x20
#define TOKEN_QUERY               0x08
#define SYSTEM_MODULE_INFORMATION 11

#define SERVICES_ROOT "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\"

static unsigned int wlen(const unsigned short *w)
{
    unsigned int n = 0;
    while (w[n]) n++;
    return n;
}

static void a2w(unsigned short *dst, unsigned int max, const char *src)
{
    unsigned int i = 0;
    while (src[i] && i + 1 < max) { dst[i] = (unsigned char)src[i]; i++; }
    dst[i] = 0;
}

static void mk_ustr(NTUSTR *u, unsigned short *w)
{
    u->Length = (unsigned short)(wlen(w) * 2);
    u->MaximumLength = (unsigned short)(u->Length + 2);
    u->Buffer = w;
}

static void mk_oa(NTOA *oa, NTUSTR *name)
{
    oa->Length = sizeof(NTOA);
    oa->RootDirectory = 0;
    oa->ObjectName = name;
    oa->Attributes = OBJ_CASE_INSENSITIVE;
    oa->SecurityDescriptor = 0;
    oa->SecurityQos = 0;
}

static NTSTATUS nt_close(HANDLE h)
{
    unsigned long a[1] = { (unsigned long)h };
    return DoNtSyscall(NTSYS_Close, a, 1);
}

static const char *status_text(NTSTATUS st)
{
    switch ((unsigned long)st) {
    case 0x00000000: return "success";
    case 0xC0000022: return "access denied";
    case 0xC0000034: return "object name not found";
    case 0xC000003A: return "path not found";
    case 0xC0000035: return "object name collision";
    case 0xC000010E: return "image already loaded";
    case 0xC0000061: return "privilege not held";
    case 0xC000007B: return "invalid image format";
    case 0xC0000010: return "invalid device request";
    case 0xC000000D: return "invalid parameter";
    case 0xC0000023: return "buffer too small";
    case 0xC0000001: return "unsuccessful";
    case 0xC00002B6: return "device removed";
    case 0xC0000428: return "invalid image hash";
    default:         return "error";
    }
}

/* Linux-style module name: basename without directory and .sys suffix */
static void module_name_from_path(const char *path, char *out, unsigned int max)
{
    const char *b = path, *p;
    unsigned int i = 0;
    for (p = path; *p; p++) if (*p == '/' || *p == '\\') b = p + 1;
    while (b[i] && b[i] != '.' && i + 1 < max) { out[i] = b[i]; i++; }
    out[i] = 0;
}

static int valid_name(const char *n)
{
    unsigned int i;
    if (!n[0] || strlen(n) > 31) return 0;
    for (i = 0; n[i]; i++) {
        char c = n[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

/* ===================================================================== */
/* NtLoadDriver requires SeLoadDriverPrivilege to be enabled in the       */
/* caller's token (the shell runs as SYSTEM, which holds it).             */
/* ===================================================================== */
static NTSTATUS enable_load_driver_privilege(void)
{
    HANDLE tok = 0;
    struct { unsigned long Count; unsigned long LuidLow; long LuidHigh; unsigned long Attr; } tp;
    unsigned long a3[3], a6[6];
    NTSTATUS st;

    a3[0] = (unsigned long)-1;                       /* current process */
    a3[1] = TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY;
    a3[2] = (unsigned long)&tok;
    st = DoNtSyscall(NTSYS_OpenProcessToken, a3, 3);
    if (!NT_OK(st)) return st;

    tp.Count = 1;
    tp.LuidLow = SE_LOAD_DRIVER_PRIVILEGE;
    tp.LuidHigh = 0;
    tp.Attr = SE_PRIVILEGE_ENABLED;
    a6[0] = (unsigned long)tok;
    a6[1] = 0;
    a6[2] = (unsigned long)&tp;
    a6[3] = sizeof(tp);
    a6[4] = 0;
    a6[5] = 0;
    st = DoNtSyscall(NTSYS_AdjustPrivilegesToken, a6, 6);
    nt_close(tok);
    return st;
}

/* ===================================================================== */
/* Service key: \Registry\Machine\System\<ControlSet>\Services\<name>     */
/* ===================================================================== */
static const char *g_roots[] = {
    "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\",
    "\\Registry\\Machine\\System\\ControlSet001\\Services\\",
};

static NTSTATUS reg_open_or_create(const char *path, HANDLE *key)
{
    unsigned short w[200];
    NTUSTR u;
    NTOA oa;
    unsigned long disp = 0;
    unsigned long a[7];

    a2w(w, 200, path);
    mk_ustr(&u, w);
    mk_oa(&oa, &u);
    a[0] = (unsigned long)key;
    a[1] = KEY_ALL_ACCESS;
    a[2] = (unsigned long)&oa;
    a[3] = 0;
    a[4] = 0;
    a[5] = REG_OPTION_VOLATILE;
    a[6] = (unsigned long)&disp;
    return DoNtSyscall(NTSYS_CreateKey, a, 7);
}

static NTSTATUS reg_set(HANDLE key, const char *valname, unsigned long type,
                        const void *data, unsigned long size)
{
    unsigned short wname[64];
    NTUSTR u;
    unsigned long a[6];

    a2w(wname, 64, valname);
    mk_ustr(&u, wname);
    a[0] = (unsigned long)key;
    a[1] = (unsigned long)&u;
    a[2] = 0;
    a[3] = type;
    a[4] = (unsigned long)data;
    a[5] = size;
    return DoNtSyscall(NTSYS_SetValueKey, a, 6);
}

static NTSTATUS reg_set_dword(HANDLE key, const char *valname, unsigned long v)
{
    return reg_set(key, valname, REG_DWORD, &v, sizeof(v));
}

static void reg_delete(const char *path)
{
    HANDLE key = 0;
    unsigned long a[1];
    if (NT_OK(reg_open_or_create(path, &key))) {
        a[0] = (unsigned long)key;
        DoNtSyscall(NTSYS_DeleteKey, a, 1);
        nt_close(key);
    }
}

static NTSTATUS nt_driver_call(unsigned long sysno, const char *keypath)
{
    unsigned short w[200];
    NTUSTR u;
    unsigned long a[1];
    a2w(w, 200, keypath);
    mk_ustr(&u, w);
    a[0] = (unsigned long)&u;
    return DoNtSyscall(sysno, a, 1);
}

/* ===================================================================== */
/* insmod                                                                 */
/* ===================================================================== */
int insmod_main(int argc, char **argv)
{
    char name[40], keypath[200];
    unsigned short ntimg[260];
    HANDLE key = 0;
    NTSTATUS st = 0;
    FILE *f;
    unsigned int r;

    if (argc < 2) {
        printf("usage: insmod <module.sys> [name]\n");
        fflush(stdout);
        return 1;
    }
    if (argc >= 3) snprintf(name, sizeof(name), "%s", argv[2]);
    else module_name_from_path(argv[1], name, sizeof(name));
    if (!valid_name(name)) {
        printf("insmod: invalid module name '%s'\n", name);
        fflush(stdout);
        return 1;
    }
    f = fopen(argv[1], "rb");
    if (!f) {
        printf("insmod: can't open '%s'\n", argv[1]);
        fflush(stdout);
        return 1;
    }
    fclose(f);

    shim_translate_path(argv[1], ntimg, 260);
    enable_load_driver_privilege();

    for (r = 0; r < 2; r++) {
        snprintf(keypath, sizeof(keypath), "%s%s", g_roots[r], name);
        st = reg_open_or_create(keypath, &key);
        if (NT_OK(st)) break;
    }
    if (!NT_OK(st)) {
        printf("insmod: can't create service key for '%s': 0x%08lX (%s)\n",
               name, (unsigned long)st, status_text(st));
        fflush(stdout);
        return 1;
    }
    reg_set_dword(key, "Type", 1);            /* SERVICE_KERNEL_DRIVER */
    reg_set_dword(key, "Start", 3);           /* SERVICE_DEMAND_START  */
    reg_set_dword(key, "ErrorControl", 1);
    reg_set(key, "ImagePath", REG_EXPAND_SZ, ntimg, (wlen(ntimg) + 1) * 2);
    nt_close(key);

    st = nt_driver_call(NTSYS_LoadDriver, keypath);
    if (!NT_OK(st)) {
        printf("insmod: can't insert '%s': 0x%08lX (%s)\n", argv[1], (unsigned long)st, status_text(st));
        if ((unsigned long)st != 0xC000010E) reg_delete(keypath);
        fflush(stdout);
        return 1;
    }
    printf("insmod: loaded '%s' from %s\n", name, argv[1]);
    fflush(stdout);
    return 0;
}

/* ===================================================================== */
/* rmmod                                                                  */
/* ===================================================================== */
int rmmod_main(int argc, char **argv)
{
    char name[40], keypath[200];
    NTSTATUS st = 0;
    unsigned int r;
    int i, rc = 0;

    enable_load_driver_privilege();
    if (argc < 2) {
        printf("usage: rmmod <name> [name...]\n");
        fflush(stdout);
        return 1;
    }
    for (i = 1; i < argc; i++) {
        module_name_from_path(argv[i], name, sizeof(name));
        if (!valid_name(name)) {
            printf("rmmod: invalid module name '%s'\n", argv[i]);
            rc = 1;
            continue;
        }
        for (r = 0; r < 2; r++) {
            snprintf(keypath, sizeof(keypath), "%s%s", g_roots[r], name);
            st = nt_driver_call(NTSYS_UnloadDriver, keypath);
            if (NT_OK(st)) break;
        }
        if (!NT_OK(st)) {
            if ((unsigned long)st == 0xC0000034)
                printf("rmmod: module '%s' is not loaded\n", name);
            else
                printf("rmmod: can't unload '%s': 0x%08lX (%s)\n", name, (unsigned long)st, status_text(st));
            rc = 1;
            continue;
        }
        reg_delete(keypath);
        printf("rmmod: unloaded '%s'\n", name);
    }
    fflush(stdout);
    return rc;
}

/* ===================================================================== */
/* lsmod                                                                  */
/* ===================================================================== */
typedef struct {
    HANDLE         Section;
    void          *MappedBase;
    void          *ImageBase;
    unsigned long  ImageSize;
    unsigned long  Flags;
    unsigned short LoadOrderIndex;
    unsigned short InitOrderIndex;
    unsigned short LoadCount;
    unsigned short OffsetToFileName;
    unsigned char  FullPathName[256];
} NT_MODULE_INFO;

static int path_is_xddk(const unsigned char *p)
{
    const char *pat = "lib\\modules\\";
    unsigned int i, j;
    for (i = 0; p[i]; i++) {
        for (j = 0; pat[j]; j++) {
            unsigned char c = p[i + j];
            if (c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');
            if (c != (unsigned char)pat[j]) break;
        }
        if (!pat[j]) return 1;
    }
    return 0;
}

int lsmod_main(int argc, char **argv)
{
    unsigned long size = 64 * 1024, ret = 0, n, i, shown = 0, hidden = 0;
    unsigned long a[4];
    unsigned char *buf;
    NT_MODULE_INFO *mods;
    NTSTATUS st;
    int all = (argc >= 2 && strcmp(argv[1], "-a") == 0);

    buf = (unsigned char *)malloc(size);
    if (!buf) { printf("lsmod: out of memory\n"); fflush(stdout); return 1; }
    a[0] = SYSTEM_MODULE_INFORMATION;
    a[1] = (unsigned long)buf;
    a[2] = size;
    a[3] = (unsigned long)&ret;
    st = DoNtSyscall(NTSYS_QuerySystemInformation, a, 4);
    if (!NT_OK(st)) {
        printf("lsmod: NtQuerySystemInformation failed: 0x%08lX\n", (unsigned long)st);
        free(buf);
        fflush(stdout);
        return 1;
    }
    n = *(unsigned long *)buf;
    mods = (NT_MODULE_INFO *)(buf + 4);

    printf("%-16s %8s  %-8s  %s\n", "Module", "Size", "Base", "Path");
    for (i = 0; i < n; i++) {
        const unsigned char *full = mods[i].FullPathName;
        const char *file = (const char *)full + mods[i].OffsetToFileName;
        char name[40];
        int xddk = path_is_xddk(full);
        if (!all && !xddk) { hidden++; continue; }
        module_name_from_path(file, name, sizeof(name));
        printf("%-16s %8lu  %08lX  %s%s\n", name, mods[i].ImageSize,
               (unsigned long)mods[i].ImageBase, (const char *)full, xddk ? "  [xddk]" : "");
        shown++;
    }
    if (!all) {
        if (shown == 0) printf("(no XDDK modules loaded)\n");
        printf("(%lu kernel/boot modules hidden; use 'lsmod -a' to list all %lu)\n", hidden, n);
    }
    free(buf);
    fflush(stdout);
    return 0;
}

/* ===================================================================== */
/* modinfo: print the .xinfo section ("key=value" strings) of a .sys file */
/* ===================================================================== */
static unsigned long rd32(const unsigned char *p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((unsigned long)p[3] << 24); }
static unsigned int  rd16(const unsigned char *p) { return p[0] | (p[1] << 8); }

int modinfo_main(int argc, char **argv)
{
    FILE *f;
    unsigned char *img;
    long len;
    unsigned long pe, nsec, sect, i;
    int found = 0;

    if (argc < 2) { printf("usage: modinfo <module.sys>\n"); fflush(stdout); return 1; }
    f = fopen(argv[1], "rb");
    if (!f) { printf("modinfo: can't open '%s'\n", argv[1]); fflush(stdout); return 1; }
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len <= 0x40 || len > 4 * 1024 * 1024) { fclose(f); printf("modinfo: bad file\n"); fflush(stdout); return 1; }
    img = (unsigned char *)malloc((size_t)len);
    if (!img || fread(img, 1, (size_t)len, f) != (size_t)len) {
        fclose(f); free(img); printf("modinfo: read error\n"); fflush(stdout); return 1;
    }
    fclose(f);

    pe = rd32(img + 0x3C);
    if (img[0] != 'M' || img[1] != 'Z' || pe + 24 > (unsigned long)len || memcmp(img + pe, "PE\0\0", 4) != 0) {
        printf("modinfo: '%s' is not a PE driver image\n", argv[1]);
        free(img); fflush(stdout); return 1;
    }
    nsec = rd16(img + pe + 6);
    sect = pe + 24 + rd16(img + pe + 20);
    printf("filename:       %s\n", argv[1]);
    for (i = 0; i < nsec && sect + 40 * (i + 1) <= (unsigned long)len; i++) {
        const unsigned char *s = img + sect + 40 * i;
        if (memcmp(s, ".xinfo", 6) == 0 && (s[6] == 0)) {
            unsigned long raw = rd32(s + 20), rsz = rd32(s + 16), vsz = rd32(s + 8), p, end;
            if (vsz && vsz < rsz) rsz = vsz;
            end = raw + rsz;
            if (end > (unsigned long)len) end = (unsigned long)len;
            p = raw;
            while (p < end) {
                const char *str = (const char *)img + p;
                size_t sl = strnlen(str, end - p);
                const char *eq = memchr(str, '=', sl);
                if (sl && eq) {
                    char key[32];
                    size_t kl = (size_t)(eq - str);
                    if (kl >= sizeof(key)) kl = sizeof(key) - 1;
                    memcpy(key, str, kl);
                    key[kl] = 0;
                    printf("%s:%*s%.*s\n", key, (int)(15 - kl), "", (int)(sl - (eq - str) - 1), eq + 1);
                    found = 1;
                }
                p += sl ? sl : 1;
            }
        }
    }
    if (!found) printf("modinfo: no XDDK metadata (.xinfo) in '%s'\n", argv[1]);
    free(img);
    fflush(stdout);
    return found ? 0 : 1;
}

/* ===================================================================== */
/* xddkctl <device> <command> [arg]                                       */
/* ===================================================================== */
static NTSTATUS dev_open(const char *dev, HANDLE *h)
{
    char path[80];
    unsigned short w[80];
    NTUSTR u;
    NTOA oa;
    NTIOSB iosb;
    unsigned long a[11];

    if (strncmp(dev, "/dev/", 5) == 0) dev += 5;
    snprintf(path, sizeof(path), "\\??\\%s", dev);
    a2w(w, 80, path);
    mk_ustr(&u, w);
    mk_oa(&oa, &u);
    a[0] = (unsigned long)h;
    a[1] = 0xC0100000UL;          /* GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE */
    a[2] = (unsigned long)&oa;
    a[3] = (unsigned long)&iosb;
    a[4] = 0;
    a[5] = 0;
    a[6] = 3;                     /* FILE_SHARE_READ | FILE_SHARE_WRITE */
    a[7] = 1;                     /* FILE_OPEN */
    a[8] = 0x20;                  /* FILE_SYNCHRONOUS_IO_NONALERT */
    a[9] = 0;
    a[10] = 0;
    return DoNtSyscall(NTSYS_CreateFile, a, 11);
}

static NTSTATUS dev_ioctl(HANDLE h, unsigned long code, void *in, unsigned long inLen,
                          void *out, unsigned long outLen, unsigned long *got)
{
    NTIOSB iosb;
    unsigned long a[10];
    NTSTATUS st;
    iosb.u.Status = 0;
    iosb.Information = 0;
    a[0] = (unsigned long)h; a[1] = 0; a[2] = 0; a[3] = 0;
    a[4] = (unsigned long)&iosb;
    a[5] = code;
    a[6] = (unsigned long)in;  a[7] = inLen;
    a[8] = (unsigned long)out; a[9] = outLen;
    st = DoNtSyscall(NTSYS_DeviceIoControlFile, a, 10);
    if (got) *got = iosb.Information;
    return st;
}

int xddkctl_main(int argc, char **argv)
{
    HANDLE h = 0;
    NTSTATUS st;
    unsigned long got = 0;
    const char *cmd;

    if (argc < 3) {
        printf("usage: xddkctl <device> info\n"
               "       xddkctl xchar   stats | clear\n"
               "       xddkctl xticker get | period <ms>\n");
        fflush(stdout);
        return 1;
    }
    cmd = argv[2];
    st = dev_open(argv[1], &h);
    if (!NT_OK(st)) {
        printf("xddkctl: can't open device '%s': 0x%08lX (%s) - is the module loaded?\n",
               argv[1], (unsigned long)st, status_text(st));
        fflush(stdout);
        return 1;
    }

    if (strcmp(cmd, "info") == 0) {
        XDDK_INFO info;
        memset(&info, 0, sizeof(info));
        st = dev_ioctl(h, IOCTL_XDDK_GET_INFO, 0, 0, &info, sizeof(info), &got);
        if (NT_OK(st)) {
            printf("device:        /dev/%s\n", info.device);
            printf("module:        %s %s\n", info.module, info.version);
            printf("loaded for:    %llu ms\n", (unsigned long long)info.loaded_ms);
            printf("open handles:  %lu (total opens %lu)\n", info.open_count, info.total_opens);
            printf("bytes:         read %llu, written %llu\n",
                   (unsigned long long)info.bytes_read, (unsigned long long)info.bytes_written);
            printf("ioctls:        %lu\n", info.ioctls);
            printf("live allocs:   %lu\n", info.live_allocs);
        }
    } else if (strcmp(cmd, "stats") == 0) {
        XCHAR_STATS s;
        memset(&s, 0, sizeof(s));
        st = dev_ioctl(h, IOCTL_XCHAR_STATS, 0, 0, &s, sizeof(s), &got);
        if (NT_OK(st))
            printf("xchar: %lu/%lu bytes buffered, total in %llu, total out %llu\n",
                   s.used, s.capacity, (unsigned long long)s.total_in, (unsigned long long)s.total_out);
    } else if (strcmp(cmd, "clear") == 0) {
        st = dev_ioctl(h, IOCTL_XCHAR_CLEAR, 0, 0, 0, 0, &got);
        if (NT_OK(st)) printf("xchar: buffer cleared\n");
    } else if (strcmp(cmd, "get") == 0) {
        XTICKER_STATE s;
        memset(&s, 0, sizeof(s));
        st = dev_ioctl(h, IOCTL_XTICKER_GET, 0, 0, &s, sizeof(s), &got);
        if (NT_OK(st))
            printf("xticker: ticks=%llu period=%lums objects=%lu\n",
                   (unsigned long long)s.ticks, s.period_ms, s.objects_alive);
    } else if (strcmp(cmd, "period") == 0 && argc >= 4) {
        xddk_u32 ms = (xddk_u32)strtoul(argv[3], 0, 0);
        st = dev_ioctl(h, IOCTL_XTICKER_SET_PERIOD, &ms, sizeof(ms), 0, 0, &got);
        if (NT_OK(st)) printf("xticker: period set to %lu ms\n", (unsigned long)ms);
    } else {
        printf("xddkctl: unknown command '%s'\n", cmd);
        nt_close(h);
        fflush(stdout);
        return 1;
    }
    if (!NT_OK(st))
        printf("xddkctl: %s failed: 0x%08lX (%s)\n", cmd, (unsigned long)st, status_text(st));
    nt_close(h);
    fflush(stdout);
    return NT_OK(st) ? 0 : 1;
}
