/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * native/ntdll/ldr_pe.c
 * User-mode PE/COFF Dynamic Linker and Process Loader for custom ntdll.dll
 */

#include "../include/ntnative.h"

extern BOOLEAN NTAPI LdrpCallInitRoutine(
    IN PDLL_INIT_ROUTINE InitRoutine,
    IN PVOID DllHandle,
    IN ULONG Reason,
    IN PVOID Context OPTIONAL
);

static PEB_LDR_DATA g_PebLdrData;
static RTL_CRITICAL_SECTION g_LoaderLock;
static BOOLEAN g_LoaderInitialized = FALSE;
static PVOID g_NtDllBase = NULL;

static int AsciiStrCmpI(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        char c1 = *s1++;
        char c2 = *s2++;
        if (c1 >= 'a' && c1 <= 'z') c1 -= ('a' - 'A');
        if (c2 >= 'a' && c2 <= 'z') c2 -= ('a' - 'A');
        if (c1 != c2) return (int)(unsigned char)c1 - (int)(unsigned char)c2;
    }
    return (int)(unsigned char)*s1 - (int)(unsigned char)*s2;
}

static int AsciiStrCmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return (int)(unsigned char)*s1 - (int)(unsigned char)*s2;
}

static PWSTR ExtractBaseNameW(PCWSTR path, USHORT byte_len, USHORT *out_byte_len) {
    USHORT chars = byte_len / sizeof(WCHAR);
    USHORT i;
    USHORT last_sep = 0;
    BOOLEAN found_sep = FALSE;
    for (i = 0; i < chars; i++) {
        if (path[i] == L'\\' || path[i] == L'/') {
            last_sep = (USHORT)(i + 1);
            found_sep = TRUE;
        }
    }
    if (found_sep) {
        *out_byte_len = (USHORT)((chars - last_sep) * sizeof(WCHAR));
        return (PWSTR)(path + last_sep);
    }
    *out_byte_len = byte_len;
    return (PWSTR)path;
}

PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(IN PVOID Base) {
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    if (!Base || Base == (PVOID)(LONG_PTR)-1) {
        return NULL;
    }
    dos = (PIMAGE_DOS_HEADER)Base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x10000000) {
        return NULL;
    }
    nt = (PIMAGE_NT_HEADERS)((PUCHAR)Base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }
    return nt;
}

PVOID NTAPI RtlImageDirectoryEntryToData(
    IN PVOID Base,
    IN BOOLEAN MappedAsImage,
    IN USHORT DirectoryEntry,
    OUT PULONG Size
) {
    PIMAGE_NT_HEADERS nt;
    ULONG rva;

    if (Size) *Size = 0;
    if ((ULONG_PTR)Base & 1) {
        Base = (PVOID)((ULONG_PTR)Base & ~((ULONG_PTR)1));
        MappedAsImage = FALSE;
    }
    nt = RtlImageNtHeader(Base);
    if (!nt) return NULL;
    if (DirectoryEntry >= nt->OptionalHeader.NumberOfRvaAndSizes) {
        return NULL;
    }
    rva = nt->OptionalHeader.DataDirectory[DirectoryEntry].VirtualAddress;
    if (!rva) return NULL;
    if (Size) {
        *Size = nt->OptionalHeader.DataDirectory[DirectoryEntry].Size;
    }
    if (MappedAsImage || rva < nt->OptionalHeader.SizeOfHeaders) {
        return (PVOID)((PUCHAR)Base + rva);
    }
    {
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        USHORT i;
        for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
            if (rva >= sec->VirtualAddress &&
                rva < sec->VirtualAddress + sec->SizeOfRawData) {
                return (PVOID)((PUCHAR)Base + (rva - sec->VirtualAddress) + sec->PointerToRawData);
            }
        }
    }
    return NULL;
}

static NTSTATUS LdrpRelocateImage(PVOID Base) {
    PIMAGE_NT_HEADERS nt = RtlImageNtHeader(Base);
    LONG_PTR delta;
    ULONG reloc_size = 0;
    PIMAGE_BASE_RELOCATION reloc;
    ULONG bytes_left;

    if (!nt) return STATUS_INVALID_IMAGE_FORMAT;
    delta = (LONG_PTR)((ULONG_PTR)Base - (ULONG_PTR)nt->OptionalHeader.ImageBase);
    if (delta == 0) {
        return STATUS_SUCCESS;
    }

    reloc = (PIMAGE_BASE_RELOCATION)RtlImageDirectoryEntryToData(
        Base, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &reloc_size
    );
    if (!reloc || reloc_size == 0) {
        return STATUS_CONFLICTING_ADDRESSES;
    }

    /* Make image writable during relocation */
    {
        PVOID prot_base = Base;
        SIZE_T prot_size = nt->OptionalHeader.SizeOfImage;
        ULONG old_prot = 0;
        NtProtectVirtualMemory(NtCurrentProcess(), &prot_base, &prot_size, PAGE_EXECUTE_READWRITE, &old_prot);
    }

    bytes_left = reloc_size;
    while (bytes_left >= sizeof(IMAGE_BASE_RELOCATION) && reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
        ULONG count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
        PUSHORT entries = (PUSHORT)(reloc + 1);
        PUCHAR page_va = (PUCHAR)Base + reloc->VirtualAddress;
        ULONG i;

        for (i = 0; i < count; i++) {
            USHORT type = entries[i] >> 12;
            USHORT offset = entries[i] & 0x0FFF;
            switch (type) {
                case IMAGE_REL_BASED_ABSOLUTE:
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    *(PULONG)(page_va + offset) += (ULONG)delta;
                    break;
                case IMAGE_REL_BASED_HIGH:
                    *(PUSHORT)(page_va + offset) += (USHORT)((delta >> 16) & 0xFFFF);
                    break;
                case IMAGE_REL_BASED_LOW:
                    *(PUSHORT)(page_va + offset) += (USHORT)(delta & 0xFFFF);
                    break;
                default:
                    break;
            }
        }

        if (bytes_left < reloc->SizeOfBlock) break;
        bytes_left -= reloc->SizeOfBlock;
        reloc = (PIMAGE_BASE_RELOCATION)((PUCHAR)reloc + reloc->SizeOfBlock);
    }

    return STATUS_SUCCESS;
}

static PLDR_DATA_TABLE_ENTRY LdrpAllocateEntry(
    PVOID DllBase,
    PCWSTR FullPathW,
    USHORT FullPathByteLen
) {
    PLDR_DATA_TABLE_ENTRY entry;
    PIMAGE_NT_HEADERS nt = RtlImageNtHeader(DllBase);
    PWSTR full_copy;
    USHORT base_len = 0;
    PWSTR base_ptr;

    entry = (PLDR_DATA_TABLE_ENTRY)RtlAllocateHeap(RtlGetProcessHeap(), 8, sizeof(LDR_DATA_TABLE_ENTRY));
    if (!entry) return NULL;

    full_copy = (PWSTR)RtlAllocateHeap(RtlGetProcessHeap(), 8, FullPathByteLen + sizeof(WCHAR));
    if (!full_copy) {
        RtlFreeHeap(RtlGetProcessHeap(), 0, entry);
        return NULL;
    }
    if (FullPathW && FullPathByteLen > 0) {
        memcpy(full_copy, FullPathW, FullPathByteLen);
    }
    full_copy[FullPathByteLen / sizeof(WCHAR)] = L'\0';

    entry->DllBase = DllBase;
    if (nt) {
        entry->SizeOfImage = nt->OptionalHeader.SizeOfImage;
        entry->EntryPoint = nt->OptionalHeader.AddressOfEntryPoint
            ? (PVOID)((PUCHAR)DllBase + nt->OptionalHeader.AddressOfEntryPoint)
            : NULL;
        entry->TimeDateStamp = nt->FileHeader.TimeDateStamp;
    }
    entry->FullDllName.Buffer = full_copy;
    entry->FullDllName.Length = FullPathByteLen;
    entry->FullDllName.MaximumLength = (USHORT)(FullPathByteLen + sizeof(WCHAR));

    base_ptr = ExtractBaseNameW(full_copy, FullPathByteLen, &base_len);
    entry->BaseDllName.Buffer = base_ptr;
    entry->BaseDllName.Length = base_len;
    entry->BaseDllName.MaximumLength = (USHORT)(base_len + sizeof(WCHAR));
    entry->LoadCount = 1;
    entry->Flags = 0;

    InsertTailList(&g_PebLdrData.InLoadOrderModuleList, &entry->InLoadOrderLinks);
    InsertTailList(&g_PebLdrData.InMemoryOrderModuleList, &entry->InMemoryOrderLinks);
    InsertTailList(&g_PebLdrData.InInitializationOrderModuleList, &entry->InInitializationOrderLinks);
    return entry;
}

static NTSTATUS LdrpSnapImports(PVOID ImageBase);

NTSTATUS NTAPI LdrFindEntryForAddress(
    IN PVOID Address,
    OUT PLDR_DATA_TABLE_ENTRY *TableEntry
) {
    PLIST_ENTRY head, curr;
    ULONG_PTR addr = (ULONG_PTR)Address;

    if (!TableEntry) return STATUS_INVALID_PARAMETER;
    *TableEntry = NULL;
    if (!g_LoaderInitialized) return STATUS_DLL_NOT_FOUND;

    head = &g_PebLdrData.InLoadOrderModuleList;
    for (curr = head->Flink; curr != head; curr = curr->Flink) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        ULONG_PTR base = (ULONG_PTR)entry->DllBase;
        if (addr >= base && addr < base + entry->SizeOfImage) {
            *TableEntry = entry;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_DLL_NOT_FOUND;
}

NTSTATUS NTAPI LdrGetDllHandle(
    IN PWSTR DllPath OPTIONAL,
    IN PULONG DllCharacteristics OPTIONAL,
    IN PUNICODE_STRING DllName,
    OUT PVOID *DllHandle
) {
    PLIST_ENTRY head, curr;
    USHORT target_base_len = 0;
    PWSTR target_base_ptr;
    UNICODE_STRING target_base;

    if (!DllName || !DllHandle) return STATUS_INVALID_PARAMETER;
    *DllHandle = NULL;
    if (!g_LoaderInitialized) return STATUS_DLL_NOT_FOUND;

    target_base_ptr = ExtractBaseNameW(DllName->Buffer, DllName->Length, &target_base_len);
    target_base.Buffer = target_base_ptr;
    target_base.Length = target_base_len;
    target_base.MaximumLength = target_base_len;

    head = &g_PebLdrData.InLoadOrderModuleList;
    for (curr = head->Flink; curr != head; curr = curr->Flink) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (RtlEqualUnicodeString(&entry->BaseDllName, &target_base, TRUE) ||
            RtlEqualUnicodeString(&entry->FullDllName, DllName, TRUE)) {
            *DllHandle = entry->DllBase;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_DLL_NOT_FOUND;
}

NTSTATUS NTAPI LdrGetProcedureAddress(
    IN PVOID DllHandle,
    IN PANSI_STRING ProcedureName OPTIONAL,
    IN ULONG ProcedureNumber OPTIONAL,
    OUT PVOID *ProcedureAddress
) {
    ULONG exp_size = 0;
    PIMAGE_EXPORT_DIRECTORY exp;
    PULONG functions;
    PULONG names;
    PUSHORT ordinals;
    ULONG func_idx = 0xFFFFFFFF;
    ULONG rva;

    if (!DllHandle || !ProcedureAddress) return STATUS_INVALID_PARAMETER;
    *ProcedureAddress = NULL;

    exp = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(
        DllHandle, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &exp_size
    );
    if (!exp || exp_size == 0) {
        return STATUS_ENTRYPOINT_NOT_FOUND;
    }

    functions = (PULONG)((PUCHAR)DllHandle + exp->AddressOfFunctions);
    names = (PULONG)((PUCHAR)DllHandle + exp->AddressOfNames);
    ordinals = (PUSHORT)((PUCHAR)DllHandle + exp->AddressOfNameOrdinals);

    if (ProcedureName && ProcedureName->Buffer) {
        /* Binary search export name table, with linear fallback */
        LONG low = 0;
        LONG high = (LONG)exp->NumberOfNames - 1;
        while (low <= high) {
            LONG mid = (low + high) >> 1;
            const char *exp_name = (const char *)((PUCHAR)DllHandle + names[mid]);
            int cmp = AsciiStrCmp(ProcedureName->Buffer, exp_name);
            if (cmp == 0) {
                func_idx = ordinals[mid];
                break;
            } else if (cmp < 0) {
                high = mid - 1;
            } else {
                low = mid + 1;
            }
        }
        if (func_idx == 0xFFFFFFFF) {
            ULONG i;
            for (i = 0; i < exp->NumberOfNames; i++) {
                const char *exp_name = (const char *)((PUCHAR)DllHandle + names[i]);
                if (AsciiStrCmp(ProcedureName->Buffer, exp_name) == 0) {
                    func_idx = ordinals[i];
                    break;
                }
            }
        }
        if (func_idx == 0xFFFFFFFF) {
            return STATUS_ENTRYPOINT_NOT_FOUND;
        }
    } else {
        if (ProcedureNumber < exp->Base) {
            return STATUS_ORDINAL_NOT_FOUND;
        }
        func_idx = ProcedureNumber - exp->Base;
    }

    if (func_idx >= exp->NumberOfFunctions) {
        return STATUS_ENTRYPOINT_NOT_FOUND;
    }

    rva = functions[func_idx];
    if (rva == 0) {
        return STATUS_ENTRYPOINT_NOT_FOUND;
    }

    /* Check for export forwarding (RVA points inside export directory) */
    {
        ULONG exp_rva = (ULONG)((PUCHAR)exp - (PUCHAR)DllHandle);
        if (rva >= exp_rva && rva < exp_rva + exp_size) {
            const char *fwd = (const char *)((PUCHAR)DllHandle + rva);
            char dll_buf[64];
            char sym_buf[128];
            int i = 0, j = 0;
            ANSI_STRING dll_astr, sym_astr;
            UNICODE_STRING dll_ustr;
            WCHAR dll_wbuf[68];
            PVOID fwd_dll = NULL;
            NTSTATUS st;

            while (fwd[i] && fwd[i] != '.' && i < 58) {
                dll_buf[i] = fwd[i];
                i++;
            }
            dll_buf[i++] = '.';
            dll_buf[i++] = 'd';
            dll_buf[i++] = 'l';
            dll_buf[i++] = 'l';
            dll_buf[i] = '\0';

            if (fwd[i - 4] == '.') {
                const char *p = fwd + (i - 3);
                while (*p && j < 127) {
                    sym_buf[j++] = *p++;
                }
            }
            sym_buf[j] = '\0';

            RtlInitAnsiString(&dll_astr, dll_buf);
            dll_ustr.Buffer = dll_wbuf;
            dll_ustr.Length = 0;
            dll_ustr.MaximumLength = sizeof(dll_wbuf);
            RtlAnsiStringToUnicodeString(&dll_ustr, &dll_astr, FALSE);

            st = LdrLoadDll(NULL, NULL, &dll_ustr, &fwd_dll);
            if (!NT_SUCCESS(st)) return st;

            RtlInitAnsiString(&sym_astr, sym_buf);
            return LdrGetProcedureAddress(fwd_dll, &sym_astr, 0, ProcedureAddress);
        }
    }

    *ProcedureAddress = (PVOID)((PUCHAR)DllHandle + rva);
    return STATUS_SUCCESS;
}

static NTSTATUS LdrpOpenDllFile(PUNICODE_STRING DllName, PHANDLE OutFile, PWSTR OutPathBuf, USHORT OutPathMaxBytes, PUSHORT OutPathLen) {
    static const PCWSTR prefixes[] = {
        L"",
        L"\\SystemRoot\\system32\\",
        L"\\SystemRoot\\",
        L"\\??\\C:\\WINDOWS\\system32\\",
        L"\\??\\C:\\bin\\",
        L"\\??\\C:\\"
    };
    ULONG i;

    for (i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        PCWSTR pfx = prefixes[i];
        USHORT pfx_chars = (USHORT)wcslen(pfx);
        USHORT name_chars = DllName->Length / sizeof(WCHAR);
        USHORT total_chars = (USHORT)(pfx_chars + name_chars);
        UNICODE_STRING u_path;
        OBJECT_ATTRIBUTES oa;
        IO_STATUS_BLOCK iosb;
        HANDLE hFile = NULL;
        NTSTATUS st;

        if (i == 0 && (name_chars == 0 || DllName->Buffer[0] != L'\\')) {
            continue;
        }
        if ((total_chars + 1) * sizeof(WCHAR) > OutPathMaxBytes) {
            continue;
        }
        if (pfx_chars > 0) {
            memcpy(OutPathBuf, pfx, pfx_chars * sizeof(WCHAR));
        }
        memcpy(OutPathBuf + pfx_chars, DllName->Buffer, name_chars * sizeof(WCHAR));
        OutPathBuf[total_chars] = L'\0';

        u_path.Buffer = OutPathBuf;
        u_path.Length = (USHORT)(total_chars * sizeof(WCHAR));
        u_path.MaximumLength = (USHORT)((total_chars + 1) * sizeof(WCHAR));

        InitializeObjectAttributes(&oa, &u_path, OBJ_CASE_INSENSITIVE, NULL, NULL);
        st = NtOpenFile(
            &hFile,
            SYNCHRONIZE | FILE_EXECUTE | FILE_READ_DATA,
            &oa,
            &iosb,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
        );
        if (NT_SUCCESS(st) && hFile) {
            *OutFile = hFile;
            *OutPathLen = u_path.Length;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_DLL_NOT_FOUND;
}

NTSTATUS NTAPI LdrLoadDll(
    IN PWSTR DllPath OPTIONAL,
    IN PULONG DllCharacteristics OPTIONAL,
    IN PUNICODE_STRING DllName,
    OUT PVOID *DllHandle
) {
    PVOID existing = NULL;
    HANDLE hFile = NULL;
    HANDLE hSection = NULL;
    PVOID viewBase = NULL;
    SIZE_T viewSize = 0;
    WCHAR fullPathBuf[260];
    USHORT fullPathLen = 0;
    NTSTATUS st;
    PLDR_DATA_TABLE_ENTRY entry;

    if (!DllName || !DllHandle) return STATUS_INVALID_PARAMETER;
    *DllHandle = NULL;

    if (NT_SUCCESS(LdrGetDllHandle(DllPath, DllCharacteristics, DllName, &existing)) && existing) {
        PLDR_DATA_TABLE_ENTRY found = NULL;
        if (NT_SUCCESS(LdrFindEntryForAddress(existing, &found)) && found) {
            if (found->LoadCount != 0xFFFF) {
                found->LoadCount++;
            }
        }
        *DllHandle = existing;
        return STATUS_SUCCESS;
    }

    st = LdrpOpenDllFile(DllName, &hFile, fullPathBuf, sizeof(fullPathBuf), &fullPathLen);
    if (!NT_SUCCESS(st)) {
        return st;
    }

    st = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_EXECUTE,
        SEC_IMAGE,
        hFile
    );
    NtClose(hFile);
    if (!NT_SUCCESS(st)) {
        return st;
    }

    st = NtMapViewOfSection(
        hSection,
        NtCurrentProcess(),
        &viewBase,
        0,
        0,
        NULL,
        &viewSize,
        ViewShare,
        0,
        PAGE_EXECUTE_WRITECOPY
    );
    NtClose(hSection);
    if (!NT_SUCCESS(st) && st != STATUS_IMAGE_NOT_AT_BASE) {
        return st;
    }

    /* Perform base relocations if mapped at non-preferred base */
    {
        PIMAGE_NT_HEADERS nt = RtlImageNtHeader(viewBase);
        if (st == STATUS_IMAGE_NOT_AT_BASE ||
            (nt && (ULONG_PTR)viewBase != (ULONG_PTR)nt->OptionalHeader.ImageBase)) {
            NTSTATUS rel_st = LdrpRelocateImage(viewBase);
            if (!NT_SUCCESS(rel_st)) {
                NtUnmapViewOfSection(NtCurrentProcess(), viewBase);
                return rel_st;
            }
        }
    }

    entry = LdrpAllocateEntry(viewBase, fullPathBuf, fullPathLen);
    if (!entry) {
        NtUnmapViewOfSection(NtCurrentProcess(), viewBase);
        return STATUS_NO_MEMORY;
    }

    st = LdrpSnapImports(viewBase);
    if (!NT_SUCCESS(st)) {
        RemoveEntryList(&entry->InLoadOrderLinks);
        RemoveEntryList(&entry->InMemoryOrderLinks);
        RemoveEntryList(&entry->InInitializationOrderLinks);
        NtUnmapViewOfSection(NtCurrentProcess(), viewBase);
        return st;
    }

    if (entry->EntryPoint) {
        BOOLEAN ok = LdrpCallInitRoutine(
            (PDLL_INIT_ROUTINE)entry->EntryPoint,
            viewBase,
            DLL_PROCESS_ATTACH,
            NULL
        );
        if (!ok) {
            RemoveEntryList(&entry->InLoadOrderLinks);
            RemoveEntryList(&entry->InMemoryOrderLinks);
            RemoveEntryList(&entry->InInitializationOrderLinks);
            NtUnmapViewOfSection(NtCurrentProcess(), viewBase);
            return STATUS_UNSUCCESSFUL;
        }
    }

    *DllHandle = viewBase;
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI LdrUnloadDll(IN PVOID DllHandle) {
    PLDR_DATA_TABLE_ENTRY entry = NULL;
    NTSTATUS st;

    if (!DllHandle || DllHandle == g_NtDllBase) {
        return STATUS_SUCCESS;
    }
    st = LdrFindEntryForAddress(DllHandle, &entry);
    if (!NT_SUCCESS(st) || !entry) {
        return STATUS_DLL_NOT_FOUND;
    }
    if (entry->LoadCount == 0xFFFF) {
        return STATUS_SUCCESS;
    }
    if (--entry->LoadCount > 0) {
        return STATUS_SUCCESS;
    }

    if (entry->EntryPoint) {
        LdrpCallInitRoutine(
            (PDLL_INIT_ROUTINE)entry->EntryPoint,
            entry->DllBase,
            DLL_PROCESS_DETACH,
            NULL
        );
    }

    RemoveEntryList(&entry->InLoadOrderLinks);
    RemoveEntryList(&entry->InMemoryOrderLinks);
    RemoveEntryList(&entry->InInitializationOrderLinks);
    if (entry->FullDllName.Buffer) {
        RtlFreeHeap(RtlGetProcessHeap(), 0, entry->FullDllName.Buffer);
    }
    RtlFreeHeap(RtlGetProcessHeap(), 0, entry);
    NtUnmapViewOfSection(NtCurrentProcess(), DllHandle);
    return STATUS_SUCCESS;
}

static NTSTATUS LdrpSnapImports(PVOID ImageBase) {
    ULONG imp_size = 0;
    PIMAGE_IMPORT_DESCRIPTOR imp;
    PIMAGE_NT_HEADERS nt = RtlImageNtHeader(ImageBase);

    if (!nt) return STATUS_INVALID_IMAGE_FORMAT;
    imp = (PIMAGE_IMPORT_DESCRIPTOR)RtlImageDirectoryEntryToData(
        ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &imp_size
    );
    if (!imp || imp_size == 0) {
        return STATUS_SUCCESS;
    }

    /* Ensure IAT pages are writable */
    {
        PVOID prot_base = ImageBase;
        SIZE_T prot_size = nt->OptionalHeader.SizeOfImage;
        ULONG old_prot = 0;
        NtProtectVirtualMemory(
            NtCurrentProcess(),
            &prot_base,
            &prot_size,
            PAGE_EXECUTE_READWRITE,
            &old_prot
        );
    }

    for (; imp->Name != 0 && imp->FirstThunk != 0; imp++) {
        const char *dll_name_a = (const char *)((PUCHAR)ImageBase + imp->Name);
        PVOID dep_base = NULL;
        PIMAGE_THUNK_DATA orig_thunk;
        PIMAGE_THUNK_DATA iat_thunk;

        if (AsciiStrCmpI(dll_name_a, "ntdll.dll") == 0) {
            dep_base = g_NtDllBase;
        } else {
            ANSI_STRING a_str;
            UNICODE_STRING u_str;
            WCHAR wbuf[128];
            NTSTATUS st;

            RtlInitAnsiString(&a_str, dll_name_a);
            u_str.Buffer = wbuf;
            u_str.Length = 0;
            u_str.MaximumLength = sizeof(wbuf);
            RtlAnsiStringToUnicodeString(&u_str, &a_str, FALSE);

            st = LdrLoadDll(NULL, NULL, &u_str, &dep_base);
            if (!NT_SUCCESS(st) || !dep_base) {
                return st;
            }
        }

        orig_thunk = (PIMAGE_THUNK_DATA)((PUCHAR)ImageBase +
            (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
        iat_thunk = (PIMAGE_THUNK_DATA)((PUCHAR)ImageBase + imp->FirstThunk);

        for (; orig_thunk->u1.AddressOfData != 0; orig_thunk++, iat_thunk++) {
            PVOID proc_addr = NULL;
            NTSTATUS st;

            if (orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                ULONG ord = orig_thunk->u1.Ordinal & 0xFFFF;
                st = LdrGetProcedureAddress(dep_base, NULL, ord, &proc_addr);
            } else {
                PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)((PUCHAR)ImageBase + orig_thunk->u1.AddressOfData);
                ANSI_STRING proc_name;
                RtlInitAnsiString(&proc_name, (PCSZ)ibn->Name);
                st = LdrGetProcedureAddress(dep_base, &proc_name, 0, &proc_addr);
            }
            if (!NT_SUCCESS(st) || !proc_addr) {
                return st;
            }
            iat_thunk->u1.Function = (ULONG)(ULONG_PTR)proc_addr;
        }
    }

    return STATUS_SUCCESS;
}

VOID NTAPI LdrpInitialize(
    IN PCONTEXT Context,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2
) {
    PPEB peb = NtCurrentPeb();

    if (SystemArgument1) {
        g_NtDllBase = SystemArgument1;
    }

    if (!g_LoaderInitialized) {
        RtlInitializeCriticalSection(&g_LoaderLock);
        RtlGetProcessHeap();

        memset(&g_PebLdrData, 0, sizeof(g_PebLdrData));
        g_PebLdrData.Length = sizeof(g_PebLdrData);
        g_PebLdrData.Initialized = TRUE;
        InitializeListHead(&g_PebLdrData.InLoadOrderModuleList);
        InitializeListHead(&g_PebLdrData.InMemoryOrderModuleList);
        InitializeListHead(&g_PebLdrData.InInitializationOrderModuleList);

        if (peb) {
            peb->Ldr = &g_PebLdrData;
            peb->LoaderLock = &g_LoaderLock;
            if (peb->ProcessParameters) {
                RtlNormalizeProcessParams(peb->ProcessParameters);
            }
        }

        if (g_NtDllBase) {
            static const WCHAR ntdll_path[] = L"\\SystemRoot\\system32\\ntdll.dll";
            PLDR_DATA_TABLE_ENTRY ntdll_entry = LdrpAllocateEntry(
                g_NtDllBase, ntdll_path, sizeof(ntdll_path) - sizeof(WCHAR)
            );
            if (ntdll_entry) {
                ntdll_entry->LoadCount = 0xFFFF;
            }
        }

        if (peb && peb->ImageBaseAddress) {
            PCWSTR exe_path = L"\\SystemRoot\\system32\\smss.exe";
            USHORT exe_len = 29 * sizeof(WCHAR);
            if (peb->ProcessParameters && peb->ProcessParameters->ImagePathName.Buffer) {
                exe_path = peb->ProcessParameters->ImagePathName.Buffer;
                exe_len = peb->ProcessParameters->ImagePathName.Length;
            }
            {
                PLDR_DATA_TABLE_ENTRY exe_entry = LdrpAllocateEntry(
                    peb->ImageBaseAddress, exe_path, exe_len
                );
                if (exe_entry) {
                    exe_entry->LoadCount = 0xFFFF;
                }
            }
            LdrpRelocateImage(peb->ImageBaseAddress);
            LdrpSnapImports(peb->ImageBaseAddress);
        }

        g_LoaderInitialized = TRUE;
    }
}

BOOLEAN NTAPI _DllMainCRTStartup(
    IN PVOID DllHandle,
    IN ULONG Reason,
    IN PVOID Context OPTIONAL
) {
    if (Reason == DLL_PROCESS_ATTACH && !g_NtDllBase) {
        g_NtDllBase = DllHandle;
    }
    return TRUE;
}
