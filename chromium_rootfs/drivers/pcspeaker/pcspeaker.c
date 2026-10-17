/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * rootfs/drivers/pcspeaker/pcspeaker.c
 * PC Speaker (PIT 8254) + CMOS Real-Time Clock (RTC) Kernel Driver
 * Creates \Device\PcSpeaker and \DosDevices\speaker (POSIX: /dev/speaker)
 */

#include <ntddk.h>

#define FILE_DEVICE_PCSPEAKER 0x00008322
#define IOCTL_SPEAKER_TONE    CTL_CODE(FILE_DEVICE_PCSPEAKER, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RTC_READ        CTL_CODE(FILE_DEVICE_PCSPEAKER, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _SPEAKER_TONE_REQ {
    ULONG FrequencyHz;   /* 0 = silence, 37..20000 Hz */
    ULONG DurationMs;    /* Duration in ms */
} SPEAKER_TONE_REQ, *PSPEAKER_TONE_REQ;

typedef struct _CMOS_RTC_TIME {
    USHORT Year;
    UCHAR  Month;
    UCHAR  Day;
    UCHAR  Hour;
    UCHAR  Minute;
    UCHAR  Second;
    UCHAR  Reserved;
} CMOS_RTC_TIME, *PCMOS_RTC_TIME;

static UCHAR ReadCmos(UCHAR reg) {
    WRITE_PORT_UCHAR((PUCHAR)0x70, reg);
    return READ_PORT_UCHAR((PUCHAR)0x71);
}

static UCHAR BcdToBin(UCHAR val) {
    return (UCHAR)((val & 0x0F) + ((val >> 4) * 10));
}

static void SetPitSpeaker(ULONG freqHz) {
    if (freqHz < 20 || freqHz > 20000) {
        UCHAR tmp = READ_PORT_UCHAR((PUCHAR)0x61) & 0xFC;
        WRITE_PORT_UCHAR((PUCHAR)0x61, tmp);
    } else {
        ULONG div = 1193182UL / freqHz;
        UCHAR tmp;
        WRITE_PORT_UCHAR((PUCHAR)0x43, 0xB6);
        WRITE_PORT_UCHAR((PUCHAR)0x42, (UCHAR)(div & 0xFF));
        WRITE_PORT_UCHAR((PUCHAR)0x42, (UCHAR)((div >> 8) & 0xFF));
        tmp = READ_PORT_UCHAR((PUCHAR)0x61);
        if ((tmp & 3) != 3) {
            WRITE_PORT_UCHAR((PUCHAR)0x61, (UCHAR)(tmp | 3));
        }
    }
}

static NTSTATUS SpkCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    (void)DeviceObject;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS SpkDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG info = 0;

    (void)DeviceObject;

    if (code == IOCTL_SPEAKER_TONE) {
        if (inLen >= sizeof(SPEAKER_TONE_REQ) && buf) {
            PSPEAKER_TONE_REQ req = (PSPEAKER_TONE_REQ)buf;
            SetPitSpeaker(req->FrequencyHz);
            if (req->DurationMs > 0 && req->FrequencyHz > 0) {
                LARGE_INTEGER delay;
                ULONG ms = (req->DurationMs > 500) ? 500 : req->DurationMs;
                delay.QuadPart = -((LONGLONG)ms * 10000i64);
                KeDelayExecutionThread(KernelMode, FALSE, &delay);
                SetPitSpeaker(0);
            }
        }
    } else if (code == IOCTL_RTC_READ) {
        if (outLen >= sizeof(CMOS_RTC_TIME) && buf) {
            PCMOS_RTC_TIME rtc = (PCMOS_RTC_TIME)buf;
            UCHAR sec  = ReadCmos(0x00);
            UCHAR min  = ReadCmos(0x02);
            UCHAR hour = ReadCmos(0x04);
            UCHAR day  = ReadCmos(0x07);
            UCHAR mon  = ReadCmos(0x08);
            UCHAR yr   = ReadCmos(0x09);
            UCHAR stsB = ReadCmos(0x0B);

            if (!(stsB & 0x04)) {
                sec  = BcdToBin(sec);
                min  = BcdToBin(min);
                hour = BcdToBin(hour & 0x7F);
                day  = BcdToBin(day);
                mon  = BcdToBin(mon);
                yr   = BcdToBin(yr);
            }
            rtc->Year     = (USHORT)(2000 + yr);
            rtc->Month    = mon;
            rtc->Day      = day;
            rtc->Hour     = hour;
            rtc->Minute   = min;
            rtc->Second   = sec;
            rtc->Reserved = 0;
            info = sizeof(CMOS_RTC_TIME);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
    } else {
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static void SpkUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symName;
    SetPitSpeaker(0);
    RtlInitUnicodeString(&symName, L"\\DosDevices\\speaker");
    IoDeleteSymbolicLink(&symName);
    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNICODE_STRING devName, symName;
    PDEVICE_OBJECT devObj = NULL;
    NTSTATUS status;

    (void)RegistryPath;

    RtlInitUnicodeString(&devName, L"\\Device\\PcSpeaker");
    RtlInitUnicodeString(&symName, L"\\DosDevices\\speaker");

    status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_PCSPEAKER, 0, FALSE, &devObj);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    devObj->Flags |= DO_BUFFERED_IO;
    IoCreateSymbolicLink(&symName, &devName);

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = SpkCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = SpkCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = SpkCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SpkDeviceControl;
    DriverObject->DriverUnload                         = SpkUnload;

    devObj->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
