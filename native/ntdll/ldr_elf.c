/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * native/ntdll/ldr_elf.c
 * User-mode ELF32 (EM_386, ET_EXEC & ET_DYN) Loader and Dynamic Linker for NT 5.1
 */

#include "../include/ntnative.h"

static NTSTATUS OpenElfPath(PCWSTR Path, PHANDLE OutHandle) {
    WCHAR nt_path[260];
    UNICODE_STRING u_path;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    USHORT len = (USHORT)wcslen(Path);

    if (!Path || !OutHandle) return STATUS_INVALID_PARAMETER;

    if (len >= 2 && Path[1] == L':') {
        nt_path[0] = L'\\';
        nt_path[1] = L'?';
        nt_path[2] = L'?';
        nt_path[3] = L'\\';
        memcpy(nt_path + 4, Path, (len + 1) * sizeof(WCHAR));
    } else if (Path[0] != L'\\') {
        static const WCHAR pfx[] = L"\\??\\C:\\";
        memcpy(nt_path, pfx, 7 * sizeof(WCHAR));
        memcpy(nt_path + 7, Path, (len + 1) * sizeof(WCHAR));
    } else {
        memcpy(nt_path, Path, (len + 1) * sizeof(WCHAR));
    }

    RtlInitUnicodeString(&u_path, nt_path);
    InitializeObjectAttributes(&oa, &u_path, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return NtOpenFile(
        OutHandle,
        SYNCHRONIZE | FILE_READ_DATA | FILE_EXECUTE,
        &oa,
        &iosb,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
    );
}

static PVOID ResolveElfSymbol(const char *sym_name) {
    UNICODE_STRING ntdll_u;
    PVOID ntdll_base = NULL;
    ANSI_STRING a_sym;
    PVOID addr = NULL;

    if (!sym_name || !sym_name[0]) return NULL;
    RtlInitUnicodeString(&ntdll_u, L"ntdll.dll");
    if (NT_SUCCESS(LdrGetDllHandle(NULL, NULL, &ntdll_u, &ntdll_base)) && ntdll_base) {
        RtlInitAnsiString(&a_sym, sym_name);
        if (NT_SUCCESS(LdrGetProcedureAddress(ntdll_base, &a_sym, 0, &addr)) && addr) {
            return addr;
        }
    }
    return NULL;
}

static VOID ApplyElfRelTable(
    Elf32_Rel *rel_tab,
    ULONG rel_bytes,
    Elf32_Sym *sym_tab,
    const char *str_tab,
    LONG_PTR load_bias
) {
    ULONG count = rel_bytes / sizeof(Elf32_Rel);
    ULONG i;

    for (i = 0; i < count; i++) {
        ULONG r_off = rel_tab[i].r_offset;
        ULONG r_info = rel_tab[i].r_info;
        ULONG sym_idx = ELF32_R_SYM(r_info);
        UCHAR r_type = ELF32_R_TYPE(r_info);
        PULONG target = (PULONG)((ULONG_PTR)r_off + (ULONG_PTR)load_bias);
        ULONG sym_val = 0;

        if (sym_idx != 0 && sym_tab) {
            Elf32_Sym *sym = &sym_tab[sym_idx];
            if (sym->st_shndx != 0) {
                sym_val = (ULONG)((ULONG_PTR)sym->st_value + (ULONG_PTR)load_bias);
            } else if (str_tab) {
                const char *sname = str_tab + sym->st_name;
                sym_val = (ULONG)(ULONG_PTR)ResolveElfSymbol(sname);
            }
        }

        switch (r_type) {
            case R_386_NONE:
                break;
            case R_386_RELATIVE:
                *target += (ULONG)load_bias;
                break;
            case R_386_32:
                *target += sym_val;
                break;
            case R_386_PC32:
                *target += sym_val - (ULONG)(ULONG_PTR)target;
                break;
            case R_386_GLOB_DAT:
            case R_386_JMP_SLOT:
                *target = sym_val;
                break;
            default:
                break;
        }
    }
}

static ULONG ElfFlagsToNtProtect(ULONG p_flags) {
    if (p_flags & PF_X) {
        return (p_flags & PF_W) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    }
    if (p_flags & PF_W) {
        return PAGE_READWRITE;
    }
    if (p_flags & PF_R) {
        return PAGE_READONLY;
    }
    return PAGE_NOACCESS;
}

NTSTATUS NTAPI LdrLoadElfImage(
    IN PCWSTR DosOrNtPath,
    OUT PELF_IMAGE_HANDLE OutImage
) {
    HANDLE hFile = NULL;
    IO_STATUS_BLOCK iosb;
    FILE_STANDARD_INFORMATION fsi;
    ULONG file_size;
    PUCHAR file_buf = NULL;
    Elf32_Ehdr *ehdr;
    Elf32_Phdr *phdrs;
    ULONG min_vaddr = 0xFFFFFFFF;
    ULONG max_vaddr = 0;
    BOOLEAN has_load = FALSE;
    USHORT i;
    PVOID map_base = NULL;
    SIZE_T map_size = 0;
    LONG_PTR load_bias = 0;
    NTSTATUS st;

    if (!DosOrNtPath || !OutImage) return STATUS_INVALID_PARAMETER;
    memset(OutImage, 0, sizeof(*OutImage));

    st = OpenElfPath(DosOrNtPath, &hFile);
    if (!NT_SUCCESS(st)) return st;

    st = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
    if (!NT_SUCCESS(st) || fsi.EndOfFile.LowPart < sizeof(Elf32_Ehdr)) {
        NtClose(hFile);
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    file_size = fsi.EndOfFile.LowPart;

    file_buf = (PUCHAR)RtlAllocateHeap(RtlGetProcessHeap(), 0, file_size);
    if (!file_buf) {
        NtClose(hFile);
        return STATUS_NO_MEMORY;
    }

    st = NtReadFile(hFile, NULL, NULL, NULL, &iosb, file_buf, file_size, NULL, NULL);
    NtClose(hFile);
    if (!NT_SUCCESS(st) || iosb.Information < sizeof(Elf32_Ehdr)) {
        RtlFreeHeap(RtlGetProcessHeap(), 0, file_buf);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    ehdr = (Elf32_Ehdr *)file_buf;
    if (ehdr->e_ident[0] != ELFMAG0 ||
        ehdr->e_ident[1] != ELFMAG1 ||
        ehdr->e_ident[2] != ELFMAG2 ||
        ehdr->e_ident[3] != ELFMAG3 ||
        ehdr->e_ident[4] != ELFCLASS32 ||
        ehdr->e_ident[5] != ELFDATA2LSB ||
        (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) ||
        ehdr->e_machine != EM_386 ||
        ehdr->e_phoff == 0 ||
        ehdr->e_phnum == 0) {
        RtlFreeHeap(RtlGetProcessHeap(), 0, file_buf);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    phdrs = (Elf32_Phdr *)(file_buf + ehdr->e_phoff);
    for (i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD && phdrs[i].p_memsz > 0) {
            ULONG seg_start = phdrs[i].p_vaddr & ~0xFFFUL;
            ULONG seg_end = (phdrs[i].p_vaddr + phdrs[i].p_memsz + 0xFFFUL) & ~0xFFFUL;
            if (seg_start < min_vaddr) min_vaddr = seg_start;
            if (seg_end > max_vaddr) max_vaddr = seg_end;
            has_load = TRUE;
        }
    }

    if (!has_load || max_vaddr <= min_vaddr) {
        RtlFreeHeap(RtlGetProcessHeap(), 0, file_buf);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    map_size = max_vaddr - min_vaddr;
    if (ehdr->e_type == ET_EXEC && min_vaddr >= 0x00010000) {
        map_base = (PVOID)(ULONG_PTR)min_vaddr;
        st = NtAllocateVirtualMemory(
            NtCurrentProcess(),
            &map_base,
            0,
            &map_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        );
        if (!NT_SUCCESS(st)) {
            map_base = NULL;
            map_size = max_vaddr - min_vaddr;
            st = NtAllocateVirtualMemory(
                NtCurrentProcess(),
                &map_base,
                0,
                &map_size,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_EXECUTE_READWRITE
            );
        }
    } else {
        map_base = NULL;
        st = NtAllocateVirtualMemory(
            NtCurrentProcess(),
            &map_base,
            0,
            &map_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        );
    }

    if (!NT_SUCCESS(st) || !map_base) {
        RtlFreeHeap(RtlGetProcessHeap(), 0, file_buf);
        return st;
    }

    load_bias = (LONG_PTR)((ULONG_PTR)map_base - (ULONG_PTR)min_vaddr);

    /* Copy PT_LOAD segments */
    for (i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD && phdrs[i].p_memsz > 0) {
            PUCHAR dst = (PUCHAR)((ULONG_PTR)phdrs[i].p_vaddr + (ULONG_PTR)load_bias);
            if (phdrs[i].p_filesz > 0) {
                if (phdrs[i].p_offset + phdrs[i].p_filesz > file_size) {
                    SIZE_T free_sz = 0;
                    NtFreeVirtualMemory(NtCurrentProcess(), &map_base, &free_sz, MEM_RELEASE);
                    RtlFreeHeap(RtlGetProcessHeap(), 0, file_buf);
                    return STATUS_INVALID_IMAGE_FORMAT;
                }
                memcpy(dst, file_buf + phdrs[i].p_offset, phdrs[i].p_filesz);
            }
            if (phdrs[i].p_memsz > phdrs[i].p_filesz) {
                memset(dst + phdrs[i].p_filesz, 0, phdrs[i].p_memsz - phdrs[i].p_filesz);
            }
        }
    }

    /* Process PT_DYNAMIC relocations if present */
    for (i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC && phdrs[i].p_memsz > 0) {
            Elf32_Dyn *dyn = (Elf32_Dyn *)((ULONG_PTR)phdrs[i].p_vaddr + (ULONG_PTR)load_bias);
            const char *str_tab = NULL;
            Elf32_Sym *sym_tab = NULL;
            Elf32_Rel *rel_tab = NULL;
            ULONG rel_sz = 0;
            Elf32_Rel *jmprel_tab = NULL;
            ULONG jmprel_sz = 0;

            for (; dyn->d_tag != DT_NULL; dyn++) {
                ULONG ptr_val = (dyn->d_val < min_vaddr)
                    ? (ULONG)((ULONG_PTR)dyn->d_val + (ULONG_PTR)map_base)
                    : (ULONG)((ULONG_PTR)dyn->d_val + (ULONG_PTR)load_bias);
                switch (dyn->d_tag) {
                    case DT_STRTAB:   str_tab = (const char *)(ULONG_PTR)ptr_val; break;
                    case DT_SYMTAB:   sym_tab = (Elf32_Sym *)(ULONG_PTR)ptr_val; break;
                    case DT_REL:      rel_tab = (Elf32_Rel *)(ULONG_PTR)ptr_val; break;
                    case DT_RELSZ:    rel_sz = dyn->d_val; break;
                    case DT_JMPREL:   jmprel_tab = (Elf32_Rel *)(ULONG_PTR)ptr_val; break;
                    case DT_PLTRELSZ: jmprel_sz = dyn->d_val; break;
                    default: break;
                }
            }

            if (rel_tab && rel_sz > 0) {
                ApplyElfRelTable(rel_tab, rel_sz, sym_tab, str_tab, load_bias);
            }
            if (jmprel_tab && jmprel_sz > 0) {
                ApplyElfRelTable(jmprel_tab, jmprel_sz, sym_tab, str_tab, load_bias);
            }
        }
    }

    /* Apply segment permissions */
    for (i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD && phdrs[i].p_memsz > 0) {
            PVOID seg_base = (PVOID)(((ULONG_PTR)phdrs[i].p_vaddr + (ULONG_PTR)load_bias) & ~0xFFFUL);
            SIZE_T seg_size = (phdrs[i].p_memsz + 0xFFFUL) & ~0xFFFUL;
            ULONG old_prot = 0;
            ULONG new_prot = ElfFlagsToNtProtect(phdrs[i].p_flags);
            NtProtectVirtualMemory(NtCurrentProcess(), &seg_base, &seg_size, new_prot, &old_prot);
        }
    }

    OutImage->BaseAddress = map_base;
    OutImage->MappedSize = map_size;
    OutImage->LoadBias = load_bias;
    OutImage->EntryPoint = (PVOID)((ULONG_PTR)ehdr->e_entry + (ULONG_PTR)load_bias);
    OutImage->ElfType = ehdr->e_type;
    OutImage->Phnum = ehdr->e_phnum;

    RtlFreeHeap(RtlGetProcessHeap(), 0, file_buf);
    return STATUS_SUCCESS;
}

typedef int (__cdecl *PFN_ELF_ENTRY)(int argc, char **argv, char **envp);

NTSTATUS NTAPI LdrExecuteElfImage(
    IN PELF_IMAGE_HANDLE Image,
    IN int argc,
    IN char **argv,
    IN char **envp
) {
    PFN_ELF_ENTRY entry;
    int rc;

    if (!Image || !Image->EntryPoint) {
        return STATUS_INVALID_PARAMETER;
    }
    entry = (PFN_ELF_ENTRY)Image->EntryPoint;
    rc = entry(argc, argv, envp);
    return (NTSTATUS)rc;
}

NTSTATUS NTAPI LdrUnloadElfImage(IN PELF_IMAGE_HANDLE Image) {
    PVOID base;
    SIZE_T sz = 0;
    if (!Image || !Image->BaseAddress) {
        return STATUS_INVALID_PARAMETER;
    }
    base = Image->BaseAddress;
    Image->BaseAddress = NULL;
    Image->EntryPoint = NULL;
    return NtFreeVirtualMemory(NtCurrentProcess(), &base, &sz, MEM_RELEASE);
}
