#include "hv_client.h"

#define HV_DEVICE_PATH  L"\\\\.\\HyperVX"

/* ------------------------------------------------------------------ */
/*  连接 / 断开                                                       */
/* ------------------------------------------------------------------ */

BOOL
HvConnect(PHV_CONTEXT Ctx)
{
    Ctx->DeviceHandle = CreateFileW(
        HV_DEVICE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    return Ctx->DeviceHandle != INVALID_HANDLE_VALUE;
}

VOID
HvDisconnect(PHV_CONTEXT Ctx)
{
    if (Ctx->DeviceHandle && Ctx->DeviceHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(Ctx->DeviceHandle);
        Ctx->DeviceHandle = INVALID_HANDLE_VALUE;
    }
}

/* ------------------------------------------------------------------ */
/*  读 / 写 / 查询基址                                                */
/* ------------------------------------------------------------------ */

BOOL
HvReadMemory(
    PHV_CONTEXT Ctx,
    DWORD       Pid,
    PVOID       Addr,
    PVOID       Buf,
    SIZE_T      Size)
{
    HV_COPY_MEMORY Req = { 0 };
    DWORD Ret = 0;

    Req.ProcessId = Pid;
    Req.Address   = Addr;
    Req.Buffer    = Buf;
    Req.Size      = Size;

    return DeviceIoControl(
        Ctx->DeviceHandle,
        IOCTL_HV_READ_MEMORY,
        &Req, sizeof(Req),
        NULL, 0,
        &Ret, NULL);
}

BOOL
HvWriteMemory(
    PHV_CONTEXT Ctx,
    DWORD       Pid,
    PVOID       Addr,
    PVOID       Buf,
    SIZE_T      Size)
{
    HV_COPY_MEMORY Req = { 0 };
    DWORD Ret = 0;

    Req.ProcessId = Pid;
    Req.Address   = Addr;
    Req.Buffer    = Buf;
    Req.Size      = Size;

    return DeviceIoControl(
        Ctx->DeviceHandle,
        IOCTL_HV_WRITE_MEMORY,
        &Req, sizeof(Req),
        NULL, 0,
        &Ret, NULL);
}

BOOL
HvGetProcessBase(
    PHV_CONTEXT Ctx,
    DWORD       Pid,
    PULONG64    Base)
{
    HV_GET_PROCESS Req = { 0 };
    DWORD Ret = 0;

    Req.ProcessId = Pid;

    BOOL Ok = DeviceIoControl(
        Ctx->DeviceHandle,
        IOCTL_HV_GET_PROCESS,
        &Req, sizeof(Req),
        &Req, sizeof(Req),
        &Ret, NULL);

    if (Ok && Ret >= sizeof(HV_GET_PROCESS))
        *Base = Req.BaseAddress;

    return Ok;
}
