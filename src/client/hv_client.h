#pragma once

#include <windows.h>

/* ------------------------------------------------------------------ */
/*  IOCTL 控制码（必须与 driver/inc/common.h 保持一致）               */
/* ------------------------------------------------------------------ */

#define HV_DEVICE_TYPE          FILE_DEVICE_UNKNOWN
#define HV_IOCTL_BASE           0x800

#define IOCTL_HV_READ_MEMORY   CTL_CODE(HV_DEVICE_TYPE, HV_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_WRITE_MEMORY  CTL_CODE(HV_DEVICE_TYPE, HV_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_GET_PROCESS   CTL_CODE(HV_DEVICE_TYPE, HV_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ------------------------------------------------------------------ */
/*  共享结构体                                                        */
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
/*  客户端上下文                                                      */
/* ------------------------------------------------------------------ */

typedef struct _HV_CONTEXT {
    HANDLE DeviceHandle;
} HV_CONTEXT, *PHV_CONTEXT;

/* ------------------------------------------------------------------ */
/*  客户端 API                                                        */
/* ------------------------------------------------------------------ */

BOOL HvConnect    (PHV_CONTEXT Ctx);
VOID HvDisconnect (PHV_CONTEXT Ctx);

BOOL HvReadMemory    (PHV_CONTEXT Ctx, DWORD Pid, PVOID Addr, PVOID Buf, SIZE_T Size);
BOOL HvWriteMemory   (PHV_CONTEXT Ctx, DWORD Pid, PVOID Addr, PVOID Buf, SIZE_T Size);
BOOL HvGetProcessBase(PHV_CONTEXT Ctx, DWORD Pid, PULONG64 Base);
