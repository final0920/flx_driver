#pragma once

#include <ntddk.h>
#include <intrin.h>

/* ------------------------------------------------------------------ */
/*  池标签 / 设备标识                                                 */
/* ------------------------------------------------------------------ */

#define HV_POOL_TAG             'xVyH'
#define HV_DEVICE_NAME          L"\\Device\\HyperVX"
#define HV_SYMBOLIC_LINK        L"\\DosDevices\\HyperVX"

/* ------------------------------------------------------------------ */
/*  IOCTL 控制码                                                      */
/* ------------------------------------------------------------------ */

#define HV_DEVICE_TYPE          FILE_DEVICE_UNKNOWN
#define HV_IOCTL_BASE           0x800

#define IOCTL_HV_READ_MEMORY   CTL_CODE(HV_DEVICE_TYPE, HV_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_WRITE_MEMORY  CTL_CODE(HV_DEVICE_TYPE, HV_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_GET_PROCESS   CTL_CODE(HV_DEVICE_TYPE, HV_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ------------------------------------------------------------------ */
/*  IOCTL 请求/响应结构体                                             */
/* ------------------------------------------------------------------ */

typedef struct _HV_COPY_MEMORY {
    ULONG   ProcessId;
    PVOID   Address;            /* 目标进程中的地址                     */
    PVOID   Buffer;             /* 调用进程中的缓冲区                   */
    SIZE_T  Size;
} HV_COPY_MEMORY, *PHV_COPY_MEMORY;

typedef struct _HV_GET_PROCESS {
    ULONG   ProcessId;          /* 输入                                 */
    ULONG64 BaseAddress;        /* 输出 - 映像基址                      */
} HV_GET_PROCESS, *PHV_GET_PROCESS;

/* ------------------------------------------------------------------ */
/*  日志级别                                                          */
/* ------------------------------------------------------------------ */

#define HV_LOG_DEBUG    0
#define HV_LOG_INFO     1
#define HV_LOG_WARN     2
#define HV_LOG_ERROR    3

/* ------------------------------------------------------------------ */
/*  utils/log.c                                                       */
/* ------------------------------------------------------------------ */

VOID
HvLog(
    _In_ ULONG Level,
    _In_ PCSTR Format,
    ...
);

/* ------------------------------------------------------------------ */
/*  memory/mm_copy.c  -  跨进程内存读写                               */
/* ------------------------------------------------------------------ */

NTSTATUS
HvReadProcessMemory(
    _In_  ULONG   ProcessId,
    _In_  PVOID   SourceAddress,
    _In_  PVOID   DestBuffer,
    _In_  SIZE_T  Size,
    _Out_ PSIZE_T BytesCopied
);

NTSTATUS
HvWriteProcessMemory(
    _In_  ULONG   ProcessId,
    _In_  PVOID   DestAddress,
    _In_  PVOID   SourceBuffer,
    _In_  SIZE_T  Size,
    _Out_ PSIZE_T BytesCopied
);

NTSTATUS
HvGetProcessBase(
    _In_  ULONG    ProcessId,
    _Out_ PULONG64 BaseAddress
);

/* ------------------------------------------------------------------ */
/*  utils/memory.c  -  池分配辅助函数                                 */
/* ------------------------------------------------------------------ */

PVOID HvAllocate(_In_ SIZE_T Size);
VOID  HvFree(_In_opt_ PVOID Ptr);
