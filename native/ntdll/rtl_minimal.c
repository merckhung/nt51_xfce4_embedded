/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * native/ntdll/rtl_minimal.c
 * Core Native Runtime Library (RTL) implementation for custom ntdll.dll
 */

#include "../include/ntnative.h"

/* Compiler intrinsic / freestanding memory primitives */
#pragma function(memset, memcpy, memcmp, strlen)

void * __cdecl memset(void *dst, int val, unsigned int count) {
    unsigned char *p = (unsigned char *)dst;
    while (count--) {
        *p++ = (unsigned char)val;
    }
    return dst;
}

void * __cdecl memcpy(void *dst, const void *src, unsigned int count) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (count--) {
        *d++ = *s++;
    }
    return dst;
}

void * __cdecl memmove(void *dst, const void *src, unsigned int count) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    if (d < s) {
        while (count--) {
            *d++ = *s++;
        }
    } else if (d > s) {
        d += count;
        s += count;
        while (count--) {
            *--d = *--s;
        }
    }
    return dst;
}

int __cdecl memcmp(const void *buf1, const void *buf2, unsigned int count) {
    const unsigned char *p1 = (const unsigned char *)buf1;
    const unsigned char *p2 = (const unsigned char *)buf2;
    while (count--) {
        if (*p1 != *p2) {
            return (int)*p1 - (int)*p2;
        }
        p1++;
        p2++;
    }
    return 0;
}

unsigned int __cdecl strlen(const char *str) {
    const char *s = str;
    if (!s) return 0;
    while (*s) s++;
    return (unsigned int)(s - str);
}

unsigned int __cdecl wcslen(const WCHAR *str) {
    const WCHAR *s = str;
    if (!s) return 0;
    while (*s) s++;
    return (unsigned int)(s - str);
}

/* Atomic operations */
static __inline LONG AtomicIncrement(volatile LONG *target_val) {
    LONG res;
    __asm {
        mov ecx, target_val
        mov eax, 1
        lock xadd [ecx], eax
        inc eax
        mov res, eax
    }
    return res;
}

static __inline LONG AtomicDecrement(volatile LONG *target_val) {
    LONG res;
    __asm {
        mov ecx, target_val
        mov eax, -1
        lock xadd [ecx], eax
        dec eax
        mov res, eax
    }
    return res;
}

static __inline LONG AtomicCompareExchange(volatile LONG *dest, LONG exch, LONG comp) {
    LONG prev;
    __asm {
        mov ecx, dest
        mov edx, exch
        mov eax, comp
        lock cmpxchg [ecx], edx
        mov prev, eax
    }
    return prev;
}

/*----------------------------------------------------------------------------
 * Heap Manager (Backed by NtAllocateVirtualMemory / NtFreeVirtualMemory)
 *----------------------------------------------------------------------------*/
#define HEAP_BLOCK_MAGIC_FREE 0x4642544EUL /* 'NTBF' */
#define HEAP_BLOCK_MAGIC_USED 0x5542544EUL /* 'NTBU' */
#define HEAP_BLOCK_MAGIC_BIG  0x4742544EUL /* 'NTBG' */
#define HEAP_SEGMENT_SIZE     (256 * 1024)
#define HEAP_BIG_THRESHOLD    (64 * 1024)
#define HEAP_ZERO_MEMORY      0x00000008

typedef struct _NTDLL_HEAP_BLOCK {
    ULONG Magic;
    SIZE_T Size; /* Usable payload size */
    struct _NTDLL_HEAP_BLOCK *NextInSegment;
    ULONG Reserved;
} NTDLL_HEAP_BLOCK;

typedef struct _NTDLL_HEAP_SEGMENT {
    struct _NTDLL_HEAP_SEGMENT *NextSegment;
    PVOID BaseAddress;
    SIZE_T TotalSize;
    NTDLL_HEAP_BLOCK *FirstBlock;
} NTDLL_HEAP_SEGMENT;

typedef struct _NTDLL_HEAP {
    ULONG Magic;
    RTL_CRITICAL_SECTION Lock;
    BOOLEAN LockInitialized;
    NTDLL_HEAP_SEGMENT *Segments;
} NTDLL_HEAP;

static NTDLL_HEAP g_DefaultProcessHeap;
static BOOLEAN g_DefaultHeapReady = FALSE;

static NTDLL_HEAP_SEGMENT *HeapAllocateSegment(SIZE_T min_size) {
    PVOID base = NULL;
    SIZE_T region_size = (min_size + sizeof(NTDLL_HEAP_SEGMENT) + sizeof(NTDLL_HEAP_BLOCK) + 0xFFFF) & ~((SIZE_T)0xFFFF);
    NTSTATUS st;
    NTDLL_HEAP_SEGMENT *seg;
    NTDLL_HEAP_BLOCK *blk;

    if (region_size < HEAP_SEGMENT_SIZE) {
        region_size = HEAP_SEGMENT_SIZE;
    }

    st = NtAllocateVirtualMemory(
        NtCurrentProcess(),
        &base,
        0,
        &region_size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );
    if (!NT_SUCCESS(st) || !base) {
        return NULL;
    }

    seg = (NTDLL_HEAP_SEGMENT *)base;
    seg->NextSegment = NULL;
    seg->BaseAddress = base;
    seg->TotalSize = region_size;

    blk = (NTDLL_HEAP_BLOCK *)((PUCHAR)base + ((sizeof(NTDLL_HEAP_SEGMENT) + 15) & ~15));
    blk->Magic = HEAP_BLOCK_MAGIC_FREE;
    blk->Size = region_size - ((PUCHAR)blk - (PUCHAR)base) - sizeof(NTDLL_HEAP_BLOCK);
    blk->NextInSegment = NULL;
    blk->Reserved = 0;

    seg->FirstBlock = blk;
    return seg;
}

PVOID NTAPI RtlCreateHeap(
    IN ULONG Flags,
    IN PVOID HeapBase OPTIONAL,
    IN SIZE_T ReserveSize OPTIONAL,
    IN SIZE_T CommitSize OPTIONAL,
    IN PVOID Lock OPTIONAL,
    IN PVOID Parameters OPTIONAL
) {
    if (!g_DefaultHeapReady) {
        memset(&g_DefaultProcessHeap, 0, sizeof(g_DefaultProcessHeap));
        g_DefaultProcessHeap.Magic = 0x50414548UL;
        RtlInitializeCriticalSection(&g_DefaultProcessHeap.Lock);
        g_DefaultProcessHeap.LockInitialized = TRUE;
        g_DefaultProcessHeap.Segments = HeapAllocateSegment(HEAP_SEGMENT_SIZE);
        g_DefaultHeapReady = TRUE;
        if (NtCurrentPeb() && !NtCurrentPeb()->ProcessHeap) {
            NtCurrentPeb()->ProcessHeap = &g_DefaultProcessHeap;
        }
        return &g_DefaultProcessHeap;
    } else {
        NTDLL_HEAP *h = (NTDLL_HEAP *)RtlAllocateHeap(&g_DefaultProcessHeap, HEAP_ZERO_MEMORY, sizeof(NTDLL_HEAP));
        if (!h) return &g_DefaultProcessHeap;
        h->Magic = 0x50414548UL;
        RtlInitializeCriticalSection(&h->Lock);
        h->LockInitialized = TRUE;
        h->Segments = HeapAllocateSegment(ReserveSize ? ReserveSize : HEAP_SEGMENT_SIZE);
        return h;
    }
}

PVOID NTAPI RtlDestroyHeap(IN PVOID HeapHandle) {
    NTDLL_HEAP *h = (NTDLL_HEAP *)HeapHandle;
    NTDLL_HEAP_SEGMENT *seg;
    if (!h || h == &g_DefaultProcessHeap) {
        return NULL;
    }
    seg = h->Segments;
    while (seg) {
        NTDLL_HEAP_SEGMENT *next = seg->NextSegment;
        PVOID base = seg->BaseAddress;
        SIZE_T sz = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &base, &sz, MEM_RELEASE);
        seg = next;
    }
    if (h->LockInitialized) {
        RtlDeleteCriticalSection(&h->Lock);
    }
    RtlFreeHeap(&g_DefaultProcessHeap, 0, h);
    return NULL;
}

PVOID NTAPI RtlGetProcessHeap(VOID) {
    PPEB peb = NtCurrentPeb();
    if (!g_DefaultHeapReady) {
        RtlCreateHeap(0, NULL, 0, 0, NULL, NULL);
    }
    if (peb && !peb->ProcessHeap) {
        peb->ProcessHeap = &g_DefaultProcessHeap;
    }
    return &g_DefaultProcessHeap;
}

PVOID NTAPI RtlAllocateHeap(
    IN PVOID HeapHandle,
    IN ULONG Flags,
    IN SIZE_T Size
) {
    NTDLL_HEAP *h = (NTDLL_HEAP *)(HeapHandle ? HeapHandle : RtlGetProcessHeap());
    SIZE_T aligned_size;
    NTDLL_HEAP_SEGMENT *seg;

    if (!g_DefaultHeapReady) {
        RtlCreateHeap(0, NULL, 0, 0, NULL, NULL);
        h = &g_DefaultProcessHeap;
    }
    if (Size == 0) {
        Size = 16;
    }
    aligned_size = (Size + 15) & ~((SIZE_T)15);

    /* Large allocation directly via NtAllocateVirtualMemory */
    if (aligned_size >= HEAP_BIG_THRESHOLD) {
        PVOID base = NULL;
        SIZE_T region_size = (aligned_size + sizeof(NTDLL_HEAP_BLOCK) + 0xFFF) & ~((SIZE_T)0xFFF);
        NTSTATUS st = NtAllocateVirtualMemory(
            NtCurrentProcess(),
            &base,
            0,
            &region_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
        );
        if (!NT_SUCCESS(st) || !base) {
            return NULL;
        }
        {
            NTDLL_HEAP_BLOCK *blk = (NTDLL_HEAP_BLOCK *)base;
            blk->Magic = HEAP_BLOCK_MAGIC_BIG;
            blk->Size = region_size - sizeof(NTDLL_HEAP_BLOCK);
            blk->NextInSegment = NULL;
            blk->Reserved = (ULONG)region_size;
            return (PVOID)(blk + 1);
        }
    }

    if (h->LockInitialized) {
        RtlEnterCriticalSection(&h->Lock);
    }

    for (seg = h->Segments; seg != NULL; seg = seg->NextSegment) {
        NTDLL_HEAP_BLOCK *blk = seg->FirstBlock;
        while (blk) {
            /* Coalesce adjacent free blocks */
            while (blk->Magic == HEAP_BLOCK_MAGIC_FREE &&
                   blk->NextInSegment &&
                   blk->NextInSegment->Magic == HEAP_BLOCK_MAGIC_FREE) {
                blk->Size += sizeof(NTDLL_HEAP_BLOCK) + blk->NextInSegment->Size;
                blk->NextInSegment = blk->NextInSegment->NextInSegment;
            }
            if (blk->Magic == HEAP_BLOCK_MAGIC_FREE && blk->Size >= aligned_size) {
                if (blk->Size >= aligned_size + sizeof(NTDLL_HEAP_BLOCK) + 32) {
                    NTDLL_HEAP_BLOCK *split = (NTDLL_HEAP_BLOCK *)((PUCHAR)(blk + 1) + aligned_size);
                    split->Magic = HEAP_BLOCK_MAGIC_FREE;
                    split->Size = blk->Size - aligned_size - sizeof(NTDLL_HEAP_BLOCK);
                    split->NextInSegment = blk->NextInSegment;
                    split->Reserved = 0;

                    blk->Size = aligned_size;
                    blk->NextInSegment = split;
                }
                blk->Magic = HEAP_BLOCK_MAGIC_USED;
                if (h->LockInitialized) {
                    RtlLeaveCriticalSection(&h->Lock);
                }
                if (Flags & HEAP_ZERO_MEMORY) {
                    memset((PVOID)(blk + 1), 0, blk->Size);
                }
                return (PVOID)(blk + 1);
            }
            blk = blk->NextInSegment;
        }
    }

    /* Allocate a new segment */
    {
        NTDLL_HEAP_SEGMENT *new_seg = HeapAllocateSegment(aligned_size + 4096);
        if (!new_seg) {
            if (h->LockInitialized) {
                RtlLeaveCriticalSection(&h->Lock);
            }
            return NULL;
        }
        new_seg->NextSegment = h->Segments;
        h->Segments = new_seg;

        {
            NTDLL_HEAP_BLOCK *blk = new_seg->FirstBlock;
            if (blk->Size >= aligned_size + sizeof(NTDLL_HEAP_BLOCK) + 32) {
                NTDLL_HEAP_BLOCK *split = (NTDLL_HEAP_BLOCK *)((PUCHAR)(blk + 1) + aligned_size);
                split->Magic = HEAP_BLOCK_MAGIC_FREE;
                split->Size = blk->Size - aligned_size - sizeof(NTDLL_HEAP_BLOCK);
                split->NextInSegment = NULL;
                split->Reserved = 0;

                blk->Size = aligned_size;
                blk->NextInSegment = split;
            }
            blk->Magic = HEAP_BLOCK_MAGIC_USED;
            if (h->LockInitialized) {
                RtlLeaveCriticalSection(&h->Lock);
            }
            if (Flags & HEAP_ZERO_MEMORY) {
                memset((PVOID)(blk + 1), 0, blk->Size);
            }
            return (PVOID)(blk + 1);
        }
    }
}

BOOLEAN NTAPI RtlFreeHeap(
    IN PVOID HeapHandle,
    IN ULONG Flags,
    IN PVOID BaseAddress
) {
    NTDLL_HEAP *h = (NTDLL_HEAP *)(HeapHandle ? HeapHandle : RtlGetProcessHeap());
    NTDLL_HEAP_BLOCK *blk;

    if (!BaseAddress) {
        return TRUE;
    }
    blk = ((NTDLL_HEAP_BLOCK *)BaseAddress) - 1;
    if (blk->Magic == HEAP_BLOCK_MAGIC_BIG) {
        PVOID base = (PVOID)blk;
        SIZE_T sz = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &base, &sz, MEM_RELEASE);
        return TRUE;
    }
    if (blk->Magic != HEAP_BLOCK_MAGIC_USED) {
        return FALSE;
    }
    if (h && h->LockInitialized) {
        RtlEnterCriticalSection(&h->Lock);
    }
    blk->Magic = HEAP_BLOCK_MAGIC_FREE;
    if (h && h->LockInitialized) {
        RtlLeaveCriticalSection(&h->Lock);
    }
    return TRUE;
}

SIZE_T NTAPI RtlSizeHeap(
    IN PVOID HeapHandle,
    IN ULONG Flags,
    IN PVOID BaseAddress
) {
    NTDLL_HEAP_BLOCK *blk;
    if (!BaseAddress) return 0;
    blk = ((NTDLL_HEAP_BLOCK *)BaseAddress) - 1;
    if (blk->Magic == HEAP_BLOCK_MAGIC_USED || blk->Magic == HEAP_BLOCK_MAGIC_BIG) {
        return blk->Size;
    }
    return 0;
}

PVOID NTAPI RtlReAllocateHeap(
    IN PVOID HeapHandle,
    IN ULONG Flags,
    IN PVOID BaseAddress,
    IN SIZE_T Size
) {
    SIZE_T old_size;
    PVOID new_ptr;

    if (!BaseAddress) {
        return RtlAllocateHeap(HeapHandle, Flags, Size);
    }
    if (Size == 0) {
        RtlFreeHeap(HeapHandle, Flags, BaseAddress);
        return NULL;
    }
    old_size = RtlSizeHeap(HeapHandle, Flags, BaseAddress);
    if (old_size >= Size) {
        return BaseAddress;
    }
    new_ptr = RtlAllocateHeap(HeapHandle, Flags, Size);
    if (!new_ptr) {
        return NULL;
    }
    memcpy(new_ptr, BaseAddress, (unsigned int)old_size);
    RtlFreeHeap(HeapHandle, Flags, BaseAddress);
    return new_ptr;
}

/*----------------------------------------------------------------------------
 * Critical Section Routines
 *----------------------------------------------------------------------------*/
NTSTATUS NTAPI RtlInitializeCriticalSection(IN PRTL_CRITICAL_SECTION CriticalSection) {
    if (!CriticalSection) return STATUS_INVALID_PARAMETER;
    CriticalSection->DebugInfo = NULL;
    CriticalSection->LockCount = -1;
    CriticalSection->RecursionCount = 0;
    CriticalSection->OwningThread = NULL;
    CriticalSection->LockSemaphore = NULL;
    CriticalSection->SpinCount = 0;
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI RtlDeleteCriticalSection(IN PRTL_CRITICAL_SECTION CriticalSection) {
    if (!CriticalSection) return STATUS_INVALID_PARAMETER;
    if (CriticalSection->LockSemaphore) {
        NtClose(CriticalSection->LockSemaphore);
        CriticalSection->LockSemaphore = NULL;
    }
    CriticalSection->LockCount = -1;
    CriticalSection->RecursionCount = 0;
    CriticalSection->OwningThread = NULL;
    return STATUS_SUCCESS;
}

static HANDLE GetOrCreateCritSecEvent(PRTL_CRITICAL_SECTION cs) {
    if (!cs->LockSemaphore) {
        HANDLE ev = NULL;
        NTSTATUS st = NtCreateEvent(&ev, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
        if (NT_SUCCESS(st) && ev) {
            if (AtomicCompareExchange((volatile LONG *)&cs->LockSemaphore, (LONG)(ULONG_PTR)ev, 0) != 0) {
                NtClose(ev);
            }
        }
    }
    return cs->LockSemaphore;
}

BOOLEAN NTAPI RtlTryEnterCriticalSection(IN PRTL_CRITICAL_SECTION CriticalSection) {
    HANDLE tid = NtCurrentTeb()->ClientId.UniqueThread;
    if (AtomicCompareExchange(&CriticalSection->LockCount, 0, -1) == -1) {
        CriticalSection->OwningThread = tid;
        CriticalSection->RecursionCount = 1;
        return TRUE;
    }
    if (CriticalSection->OwningThread == tid) {
        AtomicIncrement(&CriticalSection->LockCount);
        CriticalSection->RecursionCount++;
        return TRUE;
    }
    return FALSE;
}

NTSTATUS NTAPI RtlEnterCriticalSection(IN PRTL_CRITICAL_SECTION CriticalSection) {
    HANDLE tid = NtCurrentTeb()->ClientId.UniqueThread;
    if (AtomicIncrement(&CriticalSection->LockCount) == 0) {
        CriticalSection->OwningThread = tid;
        CriticalSection->RecursionCount = 1;
        return STATUS_SUCCESS;
    }
    if (CriticalSection->OwningThread == tid) {
        CriticalSection->RecursionCount++;
        return STATUS_SUCCESS;
    }
    {
        HANDLE ev = GetOrCreateCritSecEvent(CriticalSection);
        if (ev) {
            NtWaitForSingleObject(ev, FALSE, NULL);
        }
    }
    CriticalSection->OwningThread = tid;
    CriticalSection->RecursionCount = 1;
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI RtlLeaveCriticalSection(IN PRTL_CRITICAL_SECTION CriticalSection) {
    if (--CriticalSection->RecursionCount > 0) {
        AtomicDecrement(&CriticalSection->LockCount);
        return STATUS_SUCCESS;
    }
    CriticalSection->OwningThread = NULL;
    if (AtomicDecrement(&CriticalSection->LockCount) >= 0) {
        HANDLE ev = GetOrCreateCritSecEvent(CriticalSection);
        if (ev) {
            NtSetEvent(ev, NULL);
        }
    }
    return STATUS_SUCCESS;
}

/*----------------------------------------------------------------------------
 * String & Character Routines
 *----------------------------------------------------------------------------*/
WCHAR NTAPI RtlUpcaseUnicodeChar(IN WCHAR ch) {
    if (ch >= L'a' && ch <= L'z') {
        return (WCHAR)(ch - (L'a' - L'A'));
    }
    return ch;
}

VOID NTAPI RtlInitAnsiString(
    OUT PANSI_STRING DestinationString,
    IN PCSZ SourceString OPTIONAL
) {
    if (!DestinationString) return;
    if (SourceString) {
        USHORT len = (USHORT)strlen(SourceString);
        DestinationString->Length = len;
        DestinationString->MaximumLength = (USHORT)(len + 1);
        DestinationString->Buffer = (PCHAR)SourceString;
    } else {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
        DestinationString->Buffer = NULL;
    }
}

VOID NTAPI RtlInitUnicodeString(
    OUT PUNICODE_STRING DestinationString,
    IN PCWSTR SourceString OPTIONAL
) {
    if (!DestinationString) return;
    if (SourceString) {
        USHORT len = (USHORT)(wcslen(SourceString) * sizeof(WCHAR));
        DestinationString->Length = len;
        DestinationString->MaximumLength = (USHORT)(len + sizeof(WCHAR));
        DestinationString->Buffer = (PWSTR)SourceString;
    } else {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
        DestinationString->Buffer = NULL;
    }
}

BOOLEAN NTAPI RtlEqualUnicodeString(
    IN PCUNICODE_STRING String1,
    IN PCUNICODE_STRING String2,
    IN BOOLEAN CaseInSensitive
) {
    USHORT i, count;
    if (!String1 || !String2) return FALSE;
    if (String1->Length != String2->Length) return FALSE;
    count = String1->Length / sizeof(WCHAR);
    for (i = 0; i < count; i++) {
        WCHAR c1 = String1->Buffer[i];
        WCHAR c2 = String2->Buffer[i];
        if (c1 != c2) {
            if (!CaseInSensitive) return FALSE;
            if (RtlUpcaseUnicodeChar(c1) != RtlUpcaseUnicodeChar(c2)) return FALSE;
        }
    }
    return TRUE;
}

NTSTATUS NTAPI RtlAnsiStringToUnicodeString(
    IN OUT PUNICODE_STRING DestinationString,
    IN PCANSI_STRING SourceString,
    IN BOOLEAN AllocateDestinationString
) {
    USHORT i, chars, byte_len, max_len;
    if (!DestinationString || !SourceString) return STATUS_INVALID_PARAMETER;

    chars = SourceString->Length;
    byte_len = (USHORT)(chars * sizeof(WCHAR));
    max_len = (USHORT)(byte_len + sizeof(WCHAR));

    if (AllocateDestinationString) {
        PWSTR buf = (PWSTR)RtlAllocateHeap(RtlGetProcessHeap(), 0, max_len);
        if (!buf) return STATUS_NO_MEMORY;
        DestinationString->Buffer = buf;
        DestinationString->MaximumLength = max_len;
    } else {
        if (DestinationString->MaximumLength < max_len) {
            return STATUS_BUFFER_OVERFLOW;
        }
    }

    DestinationString->Length = byte_len;
    for (i = 0; i < chars; i++) {
        DestinationString->Buffer[i] = (WCHAR)(UCHAR)SourceString->Buffer[i];
    }
    DestinationString->Buffer[chars] = L'\0';
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI RtlUnicodeStringToAnsiString(
    IN OUT PANSI_STRING DestinationString,
    IN PCUNICODE_STRING SourceString,
    IN BOOLEAN AllocateDestinationString
) {
    USHORT i, chars, max_len;
    if (!DestinationString || !SourceString) return STATUS_INVALID_PARAMETER;

    chars = SourceString->Length / sizeof(WCHAR);
    max_len = (USHORT)(chars + 1);

    if (AllocateDestinationString) {
        PCHAR buf = (PCHAR)RtlAllocateHeap(RtlGetProcessHeap(), 0, max_len);
        if (!buf) return STATUS_NO_MEMORY;
        DestinationString->Buffer = buf;
        DestinationString->MaximumLength = max_len;
    } else {
        if (DestinationString->MaximumLength < max_len) {
            return STATUS_BUFFER_OVERFLOW;
        }
    }

    DestinationString->Length = chars;
    for (i = 0; i < chars; i++) {
        WCHAR wc = SourceString->Buffer[i];
        DestinationString->Buffer[i] = (wc < 0x100) ? (CHAR)wc : '?';
    }
    DestinationString->Buffer[chars] = '\0';
    return STATUS_SUCCESS;
}

VOID NTAPI RtlFreeUnicodeString(IN PUNICODE_STRING UnicodeString) {
    if (UnicodeString && UnicodeString->Buffer) {
        RtlFreeHeap(RtlGetProcessHeap(), 0, UnicodeString->Buffer);
        UnicodeString->Buffer = NULL;
        UnicodeString->Length = 0;
        UnicodeString->MaximumLength = 0;
    }
}

VOID NTAPI RtlFreeAnsiString(IN PANSI_STRING AnsiString) {
    if (AnsiString && AnsiString->Buffer) {
        RtlFreeHeap(RtlGetProcessHeap(), 0, AnsiString->Buffer);
        AnsiString->Buffer = NULL;
        AnsiString->Length = 0;
        AnsiString->MaximumLength = 0;
    }
}

/*----------------------------------------------------------------------------
 * Process Parameter Normalization & Creation
 *----------------------------------------------------------------------------*/
#define NORMALIZE_USTR(params, ustr) \
    do { \
        if ((ustr).Buffer) { \
            (ustr).Buffer = (PWSTR)((ULONG_PTR)(ustr).Buffer + (ULONG_PTR)(params)); \
        } \
    } while (0)

#define DENORMALIZE_USTR(params, ustr) \
    do { \
        if ((ustr).Buffer) { \
            (ustr).Buffer = (PWSTR)((ULONG_PTR)(ustr).Buffer - (ULONG_PTR)(params)); \
        } \
    } while (0)

PRTL_USER_PROCESS_PARAMETERS NTAPI RtlNormalizeProcessParams(
    IN OUT PRTL_USER_PROCESS_PARAMETERS ProcessParameters
) {
    if (!ProcessParameters) return NULL;
    if (ProcessParameters->Flags & RTL_USER_PROC_PARAMS_NORMALIZED) {
        return ProcessParameters;
    }
    NORMALIZE_USTR(ProcessParameters, ProcessParameters->CurrentDirectory.DosPath);
    NORMALIZE_USTR(ProcessParameters, ProcessParameters->DllPath);
    NORMALIZE_USTR(ProcessParameters, ProcessParameters->ImagePathName);
    NORMALIZE_USTR(ProcessParameters, ProcessParameters->CommandLine);
    NORMALIZE_USTR(ProcessParameters, ProcessParameters->WindowTitle);
    NORMALIZE_USTR(ProcessParameters, ProcessParameters->DesktopInfo);
    NORMALIZE_USTR(ProcessParameters, ProcessParameters->ShellInfo);
    NORMALIZE_USTR(ProcessParameters, ProcessParameters->RuntimeData);
    ProcessParameters->Flags |= RTL_USER_PROC_PARAMS_NORMALIZED;
    return ProcessParameters;
}

PRTL_USER_PROCESS_PARAMETERS NTAPI RtlDeNormalizeProcessParams(
    IN OUT PRTL_USER_PROCESS_PARAMETERS ProcessParameters
) {
    if (!ProcessParameters) return NULL;
    if (!(ProcessParameters->Flags & RTL_USER_PROC_PARAMS_NORMALIZED)) {
        return ProcessParameters;
    }
    DENORMALIZE_USTR(ProcessParameters, ProcessParameters->CurrentDirectory.DosPath);
    DENORMALIZE_USTR(ProcessParameters, ProcessParameters->DllPath);
    DENORMALIZE_USTR(ProcessParameters, ProcessParameters->ImagePathName);
    DENORMALIZE_USTR(ProcessParameters, ProcessParameters->CommandLine);
    DENORMALIZE_USTR(ProcessParameters, ProcessParameters->WindowTitle);
    DENORMALIZE_USTR(ProcessParameters, ProcessParameters->DesktopInfo);
    DENORMALIZE_USTR(ProcessParameters, ProcessParameters->ShellInfo);
    DENORMALIZE_USTR(ProcessParameters, ProcessParameters->RuntimeData);
    ProcessParameters->Flags &= ~RTL_USER_PROC_PARAMS_NORMALIZED;
    return ProcessParameters;
}

static VOID CopyParamUnicodeString(
    PUCHAR *cursor,
    PUNICODE_STRING dst,
    PUNICODE_STRING src
) {
    if (!src || !src->Buffer || src->Length == 0) {
        dst->Length = 0;
        dst->MaximumLength = 0;
        dst->Buffer = NULL;
        return;
    }
    dst->Length = src->Length;
    dst->MaximumLength = (USHORT)(src->Length + sizeof(WCHAR));
    dst->Buffer = (PWSTR)(*cursor);
    memcpy(*cursor, src->Buffer, src->Length);
    *(PWSTR)(*cursor + src->Length) = L'\0';
    *cursor += (dst->MaximumLength + 3) & ~3;
}

NTSTATUS NTAPI RtlCreateProcessParameters(
    OUT PRTL_USER_PROCESS_PARAMETERS *ProcessParameters,
    IN PUNICODE_STRING ImagePathName,
    IN PUNICODE_STRING DllPath OPTIONAL,
    IN PUNICODE_STRING CurrentDirectory OPTIONAL,
    IN PUNICODE_STRING CommandLine OPTIONAL,
    IN PVOID Environment OPTIONAL,
    IN PUNICODE_STRING WindowTitle OPTIONAL,
    IN PUNICODE_STRING DesktopInfo OPTIONAL,
    IN PUNICODE_STRING ShellInfo OPTIONAL,
    IN PUNICODE_STRING RuntimeData OPTIONAL
) {
    SIZE_T total_bytes = sizeof(RTL_USER_PROCESS_PARAMETERS) + 512;
    PVOID base = NULL;
    SIZE_T region_size;
    NTSTATUS st;
    PRTL_USER_PROCESS_PARAMETERS params;
    PUCHAR cursor;

    if (!ProcessParameters || !ImagePathName) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ImagePathName) total_bytes += ImagePathName->Length + 8;
    if (DllPath) total_bytes += DllPath->Length + 8;
    if (CurrentDirectory) total_bytes += CurrentDirectory->Length + 8;
    if (CommandLine) total_bytes += CommandLine->Length + 8;
    if (WindowTitle) total_bytes += WindowTitle->Length + 8;
    if (DesktopInfo) total_bytes += DesktopInfo->Length + 8;
    if (ShellInfo) total_bytes += ShellInfo->Length + 8;
    if (RuntimeData) total_bytes += RuntimeData->Length + 8;

    region_size = (total_bytes + 0xFFF) & ~((SIZE_T)0xFFF);
    st = NtAllocateVirtualMemory(
        NtCurrentProcess(),
        &base,
        0,
        &region_size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );
    if (!NT_SUCCESS(st) || !base) {
        return st;
    }

    memset(base, 0, region_size);
    params = (PRTL_USER_PROCESS_PARAMETERS)base;
    params->MaximumLength = (ULONG)region_size;
    params->Length = (ULONG)total_bytes;
    params->Flags = RTL_USER_PROC_PARAMS_NORMALIZED;
    params->Environment = Environment;

    cursor = (PUCHAR)base + ((sizeof(RTL_USER_PROCESS_PARAMETERS) + 7) & ~7);
    CopyParamUnicodeString(&cursor, &params->ImagePathName, ImagePathName);
    CopyParamUnicodeString(&cursor, &params->DllPath, DllPath);
    CopyParamUnicodeString(&cursor, &params->CurrentDirectory.DosPath, CurrentDirectory);
    CopyParamUnicodeString(&cursor, &params->CommandLine, CommandLine ? CommandLine : ImagePathName);
    CopyParamUnicodeString(&cursor, &params->WindowTitle, WindowTitle);
    CopyParamUnicodeString(&cursor, &params->DesktopInfo, DesktopInfo);
    CopyParamUnicodeString(&cursor, &params->ShellInfo, ShellInfo);
    CopyParamUnicodeString(&cursor, &params->RuntimeData, RuntimeData);

    params->Length = (ULONG)(cursor - (PUCHAR)base);
    RtlDeNormalizeProcessParams(params);
    *ProcessParameters = params;
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI RtlDestroyProcessParameters(
    IN PRTL_USER_PROCESS_PARAMETERS ProcessParameters
) {
    PVOID base = ProcessParameters;
    SIZE_T sz = 0;
    if (!ProcessParameters) return STATUS_SUCCESS;
    return NtFreeVirtualMemory(NtCurrentProcess(), &base, &sz, MEM_RELEASE);
}

/*----------------------------------------------------------------------------
 * Exception, Error & Debug Helpers
 *----------------------------------------------------------------------------*/
ULONG NTAPI RtlNtStatusToDosError(IN NTSTATUS Status) {
    if (NT_SUCCESS(Status)) return 0;
    switch (Status) {
        case STATUS_OBJECT_NAME_NOT_FOUND:
        case STATUS_NO_SUCH_FILE:          return 2;  /* ERROR_FILE_NOT_FOUND */
        case STATUS_OBJECT_PATH_NOT_FOUND: return 3;  /* ERROR_PATH_NOT_FOUND */
        case STATUS_ACCESS_DENIED:         return 5;  /* ERROR_ACCESS_DENIED */
        case STATUS_INVALID_HANDLE:        return 6;  /* ERROR_INVALID_HANDLE */
        case STATUS_NO_MEMORY:
        case STATUS_INSUFFICIENT_RESOURCES:return 8;  /* ERROR_NOT_ENOUGH_MEMORY */
        case STATUS_INVALID_PARAMETER:     return 87; /* ERROR_INVALID_PARAMETER */
        case STATUS_BUFFER_TOO_SMALL:
        case STATUS_BUFFER_OVERFLOW:       return 122;/* ERROR_INSUFFICIENT_BUFFER */
        case STATUS_OBJECT_NAME_COLLISION: return 183;/* ERROR_ALREADY_EXISTS */
        case STATUS_DIRECTORY_NOT_EMPTY:   return 145;/* ERROR_DIR_NOT_EMPTY */
        case STATUS_NOT_A_DIRECTORY:       return 267;/* ERROR_DIRECTORY */
        case STATUS_FILE_IS_A_DIRECTORY:   return 5;  /* ERROR_ACCESS_DENIED */
        case STATUS_END_OF_FILE:           return 38; /* ERROR_HANDLE_EOF */
        case STATUS_PIPE_BROKEN:
        case STATUS_PIPE_CLOSING:
        case STATUS_PIPE_DISCONNECTED:     return 109;/* ERROR_BROKEN_PIPE */
        default:                           return (ULONG)(Status & 0xFFFF);
    }
}

BOOLEAN NTAPI RtlDispatchException(
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN PCONTEXT ContextRecord
) {
    return FALSE;
}

VOID NTAPI RtlRaiseException(IN PEXCEPTION_RECORD ExceptionRecord) {
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
    NtRaiseException(ExceptionRecord, &ctx, TRUE);
}

VOID NTAPI RtlRaiseStatus(IN NTSTATUS Status) {
    EXCEPTION_RECORD er;
    memset(&er, 0, sizeof(er));
    er.ExceptionCode = Status;
    er.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
    RtlRaiseException(&er);
}

ULONG CDECL DbgPrint(IN PCSTR Format, ...) {
    return 0;
}
