#include "inc/common.h"

/* ------------------------------------------------------------------ */
/*  全局变量                                                          */
/* ------------------------------------------------------------------ */

static PDEVICE_OBJECT g_DeviceObject   = NULL;
static BOOLEAN        g_VmxInitialized = FALSE;

/* ------------------------------------------------------------------ */
/*  前向声明                                                          */
/* ------------------------------------------------------------------ */

static NTSTATUS HvDispatchCreate(_In_ PDEVICE_OBJECT Dev, _In_ PIRP Irp);
static NTSTATUS HvDispatchClose (_In_ PDEVICE_OBJECT Dev, _In_ PIRP Irp);
static NTSTATUS HvDispatchIoctl (_In_ PDEVICE_OBJECT Dev, _In_ PIRP Irp);
static VOID     HvDriverUnload  (_In_ PDRIVER_OBJECT Drv);

/* ------------------------------------------------------------------ */
/*  IRP 完成辅助函数                                                  */
/* ------------------------------------------------------------------ */

static NTSTATUS
HvCompleteIrp(
    _In_ PIRP      Irp,
    _In_ NTSTATUS  Status,
    _In_ ULONG_PTR Information)
{
    Irp->IoStatus.Status      = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

/* ------------------------------------------------------------------ */
/*  IRP_MJ_CREATE / CLOSE                                             */
/* ------------------------------------------------------------------ */

static NTSTATUS
HvDispatchCreate(_In_ PDEVICE_OBJECT Dev, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(Dev);
    return HvCompleteIrp(Irp, STATUS_SUCCESS, 0);
}

static NTSTATUS
HvDispatchClose(_In_ PDEVICE_OBJECT Dev, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(Dev);
    return HvCompleteIrp(Irp, STATUS_SUCCESS, 0);
}

/* ------------------------------------------------------------------ */
/*  IRP_MJ_DEVICE_CONTROL  -  IOCTL 分发                              */
/* ------------------------------------------------------------------ */

static NTSTATUS
HvDispatchIoctl(_In_ PDEVICE_OBJECT Dev, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(Dev);

    PIO_STACK_LOCATION Stack  = IoGetCurrentIrpStackLocation(Irp);
    PVOID  SysBuf  = Irp->AssociatedIrp.SystemBuffer;
    ULONG  InLen   = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG  OutLen  = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG  Code    = Stack->Parameters.DeviceIoControl.IoControlCode;

    NTSTATUS  Status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR Info   = 0;

    switch (Code) {

    /* ----- 从目标进程读取内存到调用方缓冲区 ----------------------- */
    case IOCTL_HV_READ_MEMORY:
    {
        if (InLen < sizeof(HV_COPY_MEMORY)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PHV_COPY_MEMORY Req = (PHV_COPY_MEMORY)SysBuf;
        SIZE_T Copied = 0;

        Status = HvReadProcessMemory(
            Req->ProcessId, Req->Address,
            Req->Buffer,    Req->Size, &Copied);
        Info = Copied;

        HvLog(HV_LOG_DEBUG,
              "ReadMemory  PID=%lu Addr=%p Size=0x%llX -> 0x%08X (%llu copied)",
              Req->ProcessId, Req->Address,
              (ULONG64)Req->Size, Status, (ULONG64)Copied);
        break;
    }

    /* ----- 将调用方缓冲区写入目标进程内存 ------------------------- */
    case IOCTL_HV_WRITE_MEMORY:
    {
        if (InLen < sizeof(HV_COPY_MEMORY)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PHV_COPY_MEMORY Req = (PHV_COPY_MEMORY)SysBuf;
        SIZE_T Copied = 0;

        Status = HvWriteProcessMemory(
            Req->ProcessId, Req->Address,
            Req->Buffer,    Req->Size, &Copied);
        Info = Copied;

        HvLog(HV_LOG_DEBUG,
              "WriteMemory PID=%lu Addr=%p Size=0x%llX -> 0x%08X (%llu copied)",
              Req->ProcessId, Req->Address,
              (ULONG64)Req->Size, Status, (ULONG64)Copied);
        break;
    }

    /* ----- 查询进程映像基址 --------------------------------------- */
    case IOCTL_HV_GET_PROCESS:
    {
        if (InLen < sizeof(HV_GET_PROCESS) || OutLen < sizeof(HV_GET_PROCESS)) {
            Status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PHV_GET_PROCESS Req = (PHV_GET_PROCESS)SysBuf;

        Status = HvGetProcessBase(Req->ProcessId, &Req->BaseAddress);
        if (NT_SUCCESS(Status))
            Info = sizeof(HV_GET_PROCESS);

        HvLog(HV_LOG_DEBUG,
              "GetProcess  PID=%lu Base=0x%llX -> 0x%08X",
              Req->ProcessId, Req->BaseAddress, Status);
        break;
    }

    default:
        break;
    }

    return HvCompleteIrp(Irp, Status, Info);
}

/* ------------------------------------------------------------------ */
/*  驱动卸载                                                          */
/* ------------------------------------------------------------------ */

static VOID
HvDriverUnload(_In_ PDRIVER_OBJECT Drv)
{
    UNREFERENCED_PARAMETER(Drv);

    if (g_VmxInitialized) {
        VmxDeinit();
        g_VmxInitialized = FALSE;
        HvLog(HV_LOG_INFO, "VMX 已关闭");
    }

    UNICODE_STRING SymLink = RTL_CONSTANT_STRING(HV_SYMBOLIC_LINK);
    IoDeleteSymbolicLink(&SymLink);

    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    HvLog(HV_LOG_INFO, "HyperVX driver unloaded");
}

/* ------------------------------------------------------------------ */
/*  驱动入口                                                          */
/* ------------------------------------------------------------------ */

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS Status;
    UNICODE_STRING DevName = RTL_CONSTANT_STRING(HV_DEVICE_NAME);
    UNICODE_STRING SymLink = RTL_CONSTANT_STRING(HV_SYMBOLIC_LINK);
    BOOLEAN SymCreated = FALSE;

    /* --- 创建设备对象 --------------------------------------------- */
    Status = IoCreateDevice(
        DriverObject, 0, &DevName,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
        FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(Status)) {
        HvLog(HV_LOG_ERROR, "IoCreateDevice failed: 0x%08X", Status);
        goto Fail;
    }

    /* --- 创建符号链接供用户态访问 --------------------------------- */
    Status = IoCreateSymbolicLink(&SymLink, &DevName);
    if (!NT_SUCCESS(Status)) {
        HvLog(HV_LOG_ERROR, "IoCreateSymbolicLink failed: 0x%08X", Status);
        goto Fail;
    }
    SymCreated = TRUE;

    /* --- 分发表 --------------------------------------------------- */
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = HvDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = HvDispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HvDispatchIoctl;
    DriverObject->DriverUnload                          = HvDriverUnload;

    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    /* --- 初始化 VT-x Hypervisor（失败不阻止 IOCTL 功能） ------------ */
    Status = VmxInit();
    if (NT_SUCCESS(Status)) {
        g_VmxInitialized = TRUE;
        HvLog(HV_LOG_INFO, "VMX 初始化成功 - Hypervisor 已激活");
    } else {
        HvLog(HV_LOG_WARN, "VMX 初始化失败: 0x%08X (IOCTL 功能仍可用)", Status);
    }

    HvLog(HV_LOG_INFO, "HyperVX driver loaded  (DevObj=%p, VMX=%s)",
          g_DeviceObject, g_VmxInitialized ? "ON" : "OFF");
    return STATUS_SUCCESS;

Fail:
    if (SymCreated) IoDeleteSymbolicLink(&SymLink);
    if (g_DeviceObject) { IoDeleteDevice(g_DeviceObject); g_DeviceObject = NULL; }
    return Status;
}
