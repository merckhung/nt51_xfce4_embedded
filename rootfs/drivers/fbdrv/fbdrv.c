/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * rootfs/drivers/fbdrv/fbdrv.c
 * Bochs/QEMU VBE Linear Framebuffer Kernel Driver for Windows XP (NT 5.1 x86)
 * Creates \Device\fb0 and \DosDevices\fb0 (accessible in POSIX userspace as /dev/fb0)
 */

#include <ntddk.h>
#include "fbdrv_ioctl.h"

/* Bochs / QEMU VBE DISPI I/O Ports and Registers */
#define VBE_DISPI_IOPORT_INDEX       0x01CE
#define VBE_DISPI_IOPORT_DATA        0x01CF

#define VBE_DISPI_INDEX_ID           0x0
#define VBE_DISPI_INDEX_XRES         0x1
#define VBE_DISPI_INDEX_YRES         0x2
#define VBE_DISPI_INDEX_BPP          0x3
#define VBE_DISPI_INDEX_ENABLE       0x4
#define VBE_DISPI_INDEX_BANK         0x5
#define VBE_DISPI_INDEX_VIRT_WIDTH   0x6
#define VBE_DISPI_INDEX_VIRT_HEIGHT  0x7
#define VBE_DISPI_INDEX_X_OFFSET     0x8
#define VBE_DISPI_INDEX_Y_OFFSET     0x9

#define VBE_DISPI_DISABLED           0x00
#define VBE_DISPI_ENABLED            0x01
#define VBE_DISPI_LFB_ENABLED        0x40
#define VBE_DISPI_NOCLEARMEM         0x80

#define DEFAULT_LFB_PHYS_ADDR        0xE0000000UL
#define LFB_MAP_SIZE                 0x00400000UL  /* 4 MB */

typedef struct _FBDRV_EXT {
    PDEVICE_OBJECT DeviceObject;
    ULONG          PhysAddr;
    PVOID          LfbKernel;
    ULONG          LfbMapSize;
    PMDL           LfbMdl;
    ULONG          Width;
    ULONG          Height;
    ULONG          Bpp;
    ULONG          Pitch;
    ULONG          SizeBytes;
    ULONG          VbeVersion;
    BOOLEAN        GraphicsActive;
} FBDRV_EXT, *PFBDRV_EXT;

static void SerDbgPutc(char c) {
    int timeout = 50000;
    while (!(READ_PORT_UCHAR((PUCHAR)0x3FD) & 0x20) && --timeout > 0);
    WRITE_PORT_UCHAR((PUCHAR)0x3F8, (UCHAR)c);
}

static void SerDbgPrint(const char *s) {
    while (*s) {
        if (*s == '\n') SerDbgPutc('\r');
        SerDbgPutc(*s++);
    }
}

static void SerDbgHex32(ULONG val) {
    static const char hex[] = "0123456789ABCDEF";
    int i;
    for (i = 28; i >= 0; i -= 4) {
        SerDbgPutc(hex[(val >> i) & 0xF]);
    }
}

/* =========================================================================
 * Linux i386 Ring-0 %gs TLS GDT[12] (0x63) + IDT[0x80] User Vsyscall Gate
 * ========================================================================= */
static ULONG   g_UserVsyscallAddr = 0;
static BOOLEAN g_LinuxKernelHooksInstalled = FALSE;

__declspec(naked) static void FbInt80TrapHandler(void) {
    __asm {
        push eax
        push edx
        push ecx
        mov  cx, fs
        mov  ax, 030h
        mov  fs, ax
        mov  eax, dword ptr [esp + 12]   /* user EIP after int 0x80 */
        mov  edx, dword ptr [esp + 24]   /* user ESP */
        sub  edx, 4
        mov  dword ptr [esp + 24], edx   /* update user ESP in iret frame */
        mov  dword ptr [edx], eax        /* push return EIP onto user stack */
        mov  eax, g_UserVsyscallAddr
        mov  dword ptr [esp + 12], eax   /* iret directly to __kernel_vsyscall */
        mov  fs, cx
        pop  ecx
        pop  edx
        pop  eax
        iretd
    }
}

/* Context switching restores TLS in the Bazel kernel source patch. */
static void InstallLinuxKernelHooks(void) {
    PUCHAR idt = NULL;
    ULONG handlerAddr = (ULONG)&FbInt80TrapHandler;
    ULONG savedCr0 = 0;
    if (g_LinuxKernelHooksInstalled) return;
    __asm {
        mov eax, fs:[0x38]
        mov idt, eax
        pushfd
        cli
        mov eax, cr0
        mov savedCr0, eax
        and eax, 0FFFEFFFFh
        mov cr0, eax
    }
    if (idt) {
        PUCHAR gate = idt + (0x80 * 8);
        *(USHORT *)(gate + 0) = (USHORT)handlerAddr;
        *(USHORT *)(gate + 2) = 0x0008;
        *(USHORT *)(gate + 4) = 0xEE00;
        *(USHORT *)(gate + 6) = (USHORT)(handlerAddr >> 16);
        g_LinuxKernelHooksInstalled = TRUE;
    }
    __asm {
        mov eax, savedCr0
        mov cr0, eax
        popfd
    }
    SerDbgPrint(g_LinuxKernelHooksInstalled ?
        "[fbdrv] Installed Linux int80 gate; TLS restored by kernel source patch.\n" :
        "[fbdrv] Failed to install Linux int80 gate.\n");
}

static void FbSetThreadTlsGdt(ULONG baseAddr, ULONG vsyscallAddr) {
    PUCHAR gdt = NULL;
    PUCHAR curThread = NULL;

    if (vsyscallAddr != 0) {
        g_UserVsyscallAddr = vsyscallAddr;
    }
    if (!g_LinuxKernelHooksInstalled) {
        InstallLinuxKernelHooks();
    }

    __asm {
        push eax
        mov  eax, fs:[0x3C]    /* KPCR.GDT */
        mov  gdt, eax
        mov  eax, fs:[0x124]   /* KPCR.PrcbData.CurrentThread */
        mov  curThread, eax
        pop  eax
    }

    if (curThread) {
        /* Store Linux tp in KTHREAD->TlsArray (offset 0x24) in NonPagedPool */
        *(ULONG *)(curThread + 0x24) = baseAddr;
    }

    if (gdt) {
        PUCHAR desc = gdt + (12 * 8); /* GDT[12] -> selector 0x63 */
        *(USHORT *)(desc + 0) = 0xFFFF;
        *(USHORT *)(desc + 2) = (USHORT)(baseAddr & 0xFFFF);
        desc[4] = (UCHAR)((baseAddr >> 16) & 0xFF);
        desc[5] = 0xF3; /* Present, DPL=3, Data RW Accessed */
        desc[6] = 0xCF; /* 4KB Granularity, 32-bit, LimitHi=0xF */
        desc[7] = (UCHAR)((baseAddr >> 24) & 0xFF);
        __asm {
            mov ax, 063h
            mov gs, ax
        }
    }
}

static void VbeWrite(USHORT index, USHORT data) {
    WRITE_PORT_USHORT((PUSHORT)VBE_DISPI_IOPORT_INDEX, index);
    WRITE_PORT_USHORT((PUSHORT)VBE_DISPI_IOPORT_DATA, data);
}

static USHORT VbeRead(USHORT index) {
    WRITE_PORT_USHORT((PUSHORT)VBE_DISPI_IOPORT_INDEX, index);
    return READ_PORT_USHORT((PUSHORT)VBE_DISPI_IOPORT_DATA);
}

static ULONG PciReadConfig32(UCHAR bus, UCHAR slot, UCHAR func, UCHAR offset) {
    ULONG addr = 0x80000000UL
               | ((ULONG)bus << 16)
               | ((ULONG)(slot & 0x1F) << 11)
               | ((ULONG)(func & 0x07) << 8)
               | ((ULONG)(offset & 0xFC));
    WRITE_PORT_ULONG((PULONG)0x0CF8, addr);
    return READ_PORT_ULONG((PULONG)0x0CFC);
}

static void PciWriteConfig32(UCHAR bus, UCHAR slot, UCHAR func, UCHAR offset, ULONG val) {
    ULONG addr = 0x80000000UL
               | ((ULONG)bus << 16)
               | ((ULONG)(slot & 0x1F) << 11)
               | ((ULONG)(func & 0x07) << 8)
               | ((ULONG)(offset & 0xFC));
    WRITE_PORT_ULONG((PULONG)0x0CF8, addr);
    WRITE_PORT_ULONG((PULONG)0x0CFC, val);
}

static ULONG ProbePciVgaBar0(void) {
    UCHAR slot;
    for (slot = 0; slot < 32; slot++) {
        ULONG id = PciReadConfig32(0, slot, 0, 0x00);
        ULONG classRev;
        if (id == 0xFFFFFFFFUL || id == 0) continue;
        classRev = PciReadConfig32(0, slot, 0, 0x08);
        /* Match Bochs/QEMU Std VGA (0x11111234) or Display Controller class 0x03xx */
        if (id == 0x11111234UL || ((classRev >> 24) & 0xFF) == 0x03) {
            ULONG bar0 = PciReadConfig32(0, slot, 0, 0x10) & 0xFFFFFFF0UL;
            ULONG cmd  = PciReadConfig32(0, slot, 0, 0x04);
            /* Ensure PCI I/O + Memory space decoding enabled */
            if ((cmd & 0x03) != 0x03) {
                PciWriteConfig32(0, slot, 0, 0x04, cmd | 0x03);
            }
            SerDbgPrint("[fbdrv] Found PCI Display Adapter at slot ");
            SerDbgHex32(slot);
            SerDbgPrint(" ID=0x");
            SerDbgHex32(id);
            SerDbgPrint(" BAR0=0x");
            SerDbgHex32(bar0);
            SerDbgPrint("\n");
            if (bar0 != 0 && bar0 != 0xFFFFFFF0UL) {
                return bar0;
            }
        }
    }
    return DEFAULT_LFB_PHYS_ADDR;
}

static void ProgramVbeMode(PFBDRV_EXT ext, ULONG width, ULONG height, ULONG bpp) {
    if (width < 320 || width > 1920) width = 800;
    if (height < 200 || height > 1200) height = 600;
    if (bpp != 16 && bpp != 24 && bpp != 32) bpp = 32;

    /* Unblank VGA attribute controller flip-flop just in case */
    (void)READ_PORT_UCHAR((PUCHAR)0x03DA);
    WRITE_PORT_UCHAR((PUCHAR)0x03C0, 0x20);

    /* Program Bochs VBE DISPI registers */
    VbeWrite(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_DISABLED);
    VbeWrite(VBE_DISPI_INDEX_XRES, (USHORT)width);
    VbeWrite(VBE_DISPI_INDEX_YRES, (USHORT)height);
    VbeWrite(VBE_DISPI_INDEX_BPP, (USHORT)bpp);
    VbeWrite(VBE_DISPI_INDEX_BANK, 0);
    VbeWrite(VBE_DISPI_INDEX_VIRT_WIDTH, (USHORT)width);
    VbeWrite(VBE_DISPI_INDEX_VIRT_HEIGHT, (USHORT)height);
    VbeWrite(VBE_DISPI_INDEX_X_OFFSET, 0);
    VbeWrite(VBE_DISPI_INDEX_Y_OFFSET, 0);
    VbeWrite(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED);

    ext->Width = width;
    ext->Height = height;
    ext->Bpp = bpp;
    ext->Pitch = width * (bpp / 8);
    ext->SizeBytes = ext->Pitch * height;
    ext->GraphicsActive = TRUE;

    if (ext->LfbKernel && ext->SizeBytes <= ext->LfbMapSize) {
        RtlZeroMemory(ext->LfbKernel, ext->SizeBytes);
    }

    SerDbgPrint("[fbdrv] Switched VBE graphics mode: ");
    SerDbgHex32(width);
    SerDbgPrint("x");
    SerDbgHex32(height);
    SerDbgPrint("x");
    SerDbgHex32(bpp);
    SerDbgPrint("\n");
}

static NTSTATUS FbCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    (void)DeviceObject;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS FbWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PFBDRV_EXT ext = (PFBDRV_EXT)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG len = irpSp->Parameters.Write.Length;
    ULONG offset = irpSp->Parameters.Write.ByteOffset.LowPart;
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;

    if (!ext->GraphicsActive) {
        ProgramVbeMode(ext, ext->Width, ext->Height, ext->Bpp);
    }

    if (buf && ext->LfbKernel && offset < ext->SizeBytes) {
        if (offset + len > ext->SizeBytes) {
            len = ext->SizeBytes - offset;
        }
        RtlCopyMemory((PUCHAR)ext->LfbKernel + offset, buf, len);
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = len;
    } else {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS FbDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PFBDRV_EXT ext = (PFBDRV_EXT)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG info = 0;

    switch (code) {
    case IOCTL_FB_GET_INFO:
        if (outLen < sizeof(FB_MODE_INFO) || !buf) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            PFB_MODE_INFO mi = (PFB_MODE_INFO)buf;
            mi->Width        = ext->Width;
            mi->Height       = ext->Height;
            mi->Bpp          = ext->Bpp;
            mi->Pitch        = ext->Pitch;
            mi->SizeBytes    = ext->SizeBytes;
            mi->PhysAddr     = ext->PhysAddr;
            mi->VbeVersion   = ext->VbeVersion;
            mi->UserMappedVa = 0;
            info = sizeof(FB_MODE_INFO);
        }
        break;

    case IOCTL_FB_SET_MODE:
        if (inLen < sizeof(FB_MODE_INFO) || !buf) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            PFB_MODE_INFO req = (PFB_MODE_INFO)buf;
            ProgramVbeMode(ext, req->Width, req->Height, req->Bpp);
            if (outLen >= sizeof(FB_MODE_INFO)) {
                req->Width        = ext->Width;
                req->Height       = ext->Height;
                req->Bpp          = ext->Bpp;
                req->Pitch        = ext->Pitch;
                req->SizeBytes    = ext->SizeBytes;
                req->PhysAddr     = ext->PhysAddr;
                req->VbeVersion   = ext->VbeVersion;
                req->UserMappedVa = 0;
                info = sizeof(FB_MODE_INFO);
            }
        }
        break;

    case IOCTL_FB_PRESENT:
    case 0x00220004UL:
        if (!buf || inLen < sizeof(FB_PRESENT_REQ)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            if (!ext->GraphicsActive) {
                ProgramVbeMode(ext, ext->Width, ext->Height, ext->Bpp);
            }
            if (inLen >= ext->SizeBytes && ext->LfbKernel) {
                RtlCopyMemory(ext->LfbKernel, buf, ext->SizeBytes);
                info = ext->SizeBytes;
            } else {
                PFB_PRESENT_REQ req = (PFB_PRESENT_REQ)buf;
                if (req->UserBuffer && ext->LfbKernel && req->DstOffset < ext->SizeBytes) {
                    ULONG copyLen = req->ByteLength;
                    if (req->DstOffset + copyLen > ext->SizeBytes) {
                        copyLen = ext->SizeBytes - req->DstOffset;
                    }
                    __try {
                        RtlCopyMemory((PUCHAR)ext->LfbKernel + req->DstOffset, req->UserBuffer, copyLen);
                        info = copyLen;
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        status = GetExceptionCode();
                    }
                }
            }
        }
        break;

    case IOCTL_FB_MAP_USER:
        if (outLen < sizeof(FB_MODE_INFO) || !buf) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            PFB_MODE_INFO mi = (PFB_MODE_INFO)buf;
            PVOID userVa = NULL;
            if (!ext->GraphicsActive) {
                ProgramVbeMode(ext, ext->Width, ext->Height, ext->Bpp);
            }
            if (ext->LfbMdl) {
                __try {
                    userVa = MmMapLockedPagesSpecifyCache(
                        ext->LfbMdl,
                        UserMode,
                        MmNonCached,
                        NULL,
                        FALSE,
                        NormalPagePriority
                    );
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    userVa = NULL;
                }
            }
            mi->Width        = ext->Width;
            mi->Height       = ext->Height;
            mi->Bpp          = ext->Bpp;
            mi->Pitch        = ext->Pitch;
            mi->SizeBytes    = ext->SizeBytes;
            mi->PhysAddr     = ext->PhysAddr;
            mi->VbeVersion   = ext->VbeVersion;
            mi->UserMappedVa = (ULONG)userVa;
            info = sizeof(FB_MODE_INFO);
        }
        break;

    case IOCTL_FB_FILL_RECT:
        if (inLen < sizeof(FB_RECT_REQ) || !buf) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            PFB_RECT_REQ r = (FB_RECT_REQ *)buf;
            ULONG x, y, xEnd, yEnd;
            if (!ext->GraphicsActive) {
                ProgramVbeMode(ext, ext->Width, ext->Height, ext->Bpp);
            }
            xEnd = r->X + r->Width;
            yEnd = r->Y + r->Height;
            if (xEnd > ext->Width) xEnd = ext->Width;
            if (yEnd > ext->Height) yEnd = ext->Height;
            if (ext->LfbKernel && r->X < xEnd && r->Y < yEnd) {
                for (y = r->Y; y < yEnd; y++) {
                    PULONG row = (PULONG)((PUCHAR)ext->LfbKernel + y * ext->Pitch);
                    for (x = r->X; x < xEnd; x++) {
                        row[x] = r->Color;
                    }
                }
            }
        }
        break;

    case IOCTL_FB_SET_TLS_GDT:
    case 0x00220014UL:
        if (inLen < 2 * sizeof(ULONG) || !buf) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            PULONG u = (PULONG)buf;
            FbSetThreadTlsGdt(u[0], u[1]);
            if (outLen >= sizeof(FB_TLS_GDT_REQ)) {
                ((PFB_TLS_GDT_REQ)buf)->EntryNumber = 12;
                info = sizeof(FB_TLS_GDT_REQ);
            } else if (outLen >= sizeof(ULONG)) {
                u[0] = 12;
                info = sizeof(ULONG);
            }
        }
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static void FbUnload(PDRIVER_OBJECT DriverObject) {
    PDEVICE_OBJECT devObj = DriverObject->DeviceObject;
    UNICODE_STRING symName;

    RtlInitUnicodeString(&symName, L"\\DosDevices\\fb0");
    IoDeleteSymbolicLink(&symName);

    if (devObj) {
        PFBDRV_EXT ext = (PFBDRV_EXT)devObj->DeviceExtension;
        if (ext->LfbMdl) {
            IoFreeMdl(ext->LfbMdl);
            ext->LfbMdl = NULL;
        }
        if (ext->LfbKernel) {
            MmUnmapIoSpace(ext->LfbKernel, ext->LfbMapSize);
            ext->LfbKernel = NULL;
        }
        IoDeleteDevice(devObj);
    }
    SerDbgPrint("[fbdrv] Unloaded driver.\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNICODE_STRING devName, symName;
    PDEVICE_OBJECT devObj = NULL;
    PFBDRV_EXT ext;
    PHYSICAL_ADDRESS physAddr;
    NTSTATUS status;

    (void)RegistryPath;

    SerDbgPrint("\n=======================================================\n");
    SerDbgPrint("[fbdrv] Initializing Bochs/QEMU VBE Framebuffer Driver\n");
    SerDbgPrint("=======================================================\n");

    RtlInitUnicodeString(&devName, L"\\Device\\fb0");
    RtlInitUnicodeString(&symName, L"\\DosDevices\\fb0");

    status = IoCreateDevice(
        DriverObject,
        sizeof(FBDRV_EXT),
        &devName,
        FILE_DEVICE_FRAMEBUFFER,
        0,
        FALSE,
        &devObj
    );
    if (!NT_SUCCESS(status)) {
        SerDbgPrint("[fbdrv] ERROR: IoCreateDevice failed\n");
        return status;
    }

    devObj->Flags |= DO_BUFFERED_IO;
    ext = (PFBDRV_EXT)devObj->DeviceExtension;
    RtlZeroMemory(ext, sizeof(FBDRV_EXT));
    ext->DeviceObject = devObj;

    /* Detect VBE version and PCI BAR0 physical framebuffer address */
    VbeWrite(VBE_DISPI_INDEX_ID, 0xB0C5);
    ext->VbeVersion = (ULONG)VbeRead(VBE_DISPI_INDEX_ID);
    ext->PhysAddr   = ProbePciVgaBar0();
    ext->LfbMapSize = LFB_MAP_SIZE;

    /* Default mode parameters: 800x600x32bpp TrueColor */
    ext->Width      = 800;
    ext->Height     = 600;
    ext->Bpp        = 32;
    ext->Pitch      = 800 * 4;
    ext->SizeBytes  = 800 * 600 * 4;
    ext->GraphicsActive = FALSE;

    physAddr.QuadPart = (ULONGLONG)ext->PhysAddr;
    ext->LfbKernel = MmMapIoSpace(physAddr, ext->LfbMapSize, MmNonCached);
    if (!ext->LfbKernel) {
        SerDbgPrint("[fbdrv] ERROR: MmMapIoSpace failed for BAR0\n");
        IoDeleteDevice(devObj);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ext->LfbMdl = IoAllocateMdl(ext->LfbKernel, ext->LfbMapSize, FALSE, FALSE, NULL);
    if (ext->LfbMdl) {
        MmBuildMdlForNonPagedPool(ext->LfbMdl);
    }

    IoCreateSymbolicLink(&symName, &devName);

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = FbCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = FbCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = FbCreateClose;
    DriverObject->MajorFunction[IRP_MJ_WRITE]          = FbWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FbDeviceControl;
    DriverObject->DriverUnload                         = FbUnload;

    devObj->Flags &= ~DO_DEVICE_INITIALIZING;

    InstallLinuxKernelHooks();

    SerDbgPrint("[fbdrv] Mapped LFB Phys=0x");
    SerDbgHex32(ext->PhysAddr);
    SerDbgPrint(" -> KernelVA=0x");
    SerDbgHex32((ULONG)ext->LfbKernel);
    SerDbgPrint(" VBE=0x");
    SerDbgHex32(ext->VbeVersion);
    SerDbgPrint("\n");

    return STATUS_SUCCESS;
}
