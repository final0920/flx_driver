#include "../inc/common.h"

/* ------------------------------------------------------------------ */
/*  未导出 NTAPI 声明                                                 */
/* ------------------------------------------------------------------ */

/* 跨进程虚拟内存拷贝，KernelMode 绕过 ProbeForRead/Write 检查 */
NTKERNELAPI
NTSTATUS
NTAPI
MmCopyVirtualMemory(
    _In_  PEPROCESS       SourceProcess,
    _In_  PVOID           SourceAddress,
    _In_  PEPROCESS       TargetProcess,
    _Out_ PVOID           TargetAddress,
    _In_  SIZE_T          BufferSize,
    _In_  KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T         ReturnSize
);

/* 返回进程 PEB 中的 ImageBaseAddress */
NTKERNELAPI
PVOID
NTAPI
PsGetProcessSectionBaseAddress(
    _In_ PEPROCESS Process
);

/* ------------------------------------------------------------------ */
/*  HvReadProcessMemory                                               */
/*  从目标进程拷贝到调用进程（KernelMode 权限）                       */
/* ------------------------------------------------------------------ */

NTSTATUS
HvReadProcessMemory(
    _In_  ULONG   ProcessId,
    _In_  PVOID   SourceAddress,
    _In_  PVOID   DestBuffer,
    _In_  SIZE_T  Size,
    _Out_ PSIZE_T BytesCopied)
{
    PEPROCESS TargetProc = NULL;
    NTSTATUS  Status;

    *BytesCopied = 0;

    if (Size == 0)
        return STATUS_INVALID_PARAMETER;

    Status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)ProcessId, &TargetProc);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = MmCopyVirtualMemory(
        TargetProc,            SourceAddress,
        PsGetCurrentProcess(), DestBuffer,
        Size, KernelMode, BytesCopied);

    ObDereferenceObject(TargetProc);
    return Status;
}

/* ------------------------------------------------------------------ */
/*  HvWriteProcessMemory                                              */
/*  从调用进程拷贝到目标进程（KernelMode 权限）                       */
/* ------------------------------------------------------------------ */

NTSTATUS
HvWriteProcessMemory(
    _In_  ULONG   ProcessId,
    _In_  PVOID   DestAddress,
    _In_  PVOID   SourceBuffer,
    _In_  SIZE_T  Size,
    _Out_ PSIZE_T BytesCopied)
{
    PEPROCESS TargetProc = NULL;
    NTSTATUS  Status;

    *BytesCopied = 0;

    if (Size == 0)
        return STATUS_INVALID_PARAMETER;

    Status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)ProcessId, &TargetProc);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = MmCopyVirtualMemory(
        PsGetCurrentProcess(), SourceBuffer,
        TargetProc,            DestAddress,
        Size, KernelMode, BytesCopied);

    ObDereferenceObject(TargetProc);
    return Status;
}

/* ------------------------------------------------------------------ */
/*  HvGetProcessBase                                                  */
/*  通过 PsGetProcessSectionBaseAddress 获取映像基址                  */
/* ------------------------------------------------------------------ */

NTSTATUS
HvGetProcessBase(
    _In_  ULONG    ProcessId,
    _Out_ PULONG64 BaseAddress)
{
    PEPROCESS Process = NULL;
    NTSTATUS  Status;

    *BaseAddress = 0;

    Status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)ProcessId, &Process);
    if (!NT_SUCCESS(Status))
        return Status;

    PVOID Base = PsGetProcessSectionBaseAddress(Process);
    ObDereferenceObject(Process);

    if (!Base)
        return STATUS_NOT_FOUND;

    *BaseAddress = (ULONG64)Base;
    return STATUS_SUCCESS;
}
