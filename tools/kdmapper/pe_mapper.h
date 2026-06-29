#pragma once

#include "intel_driver.h"

/* ------------------------------------------------------------------ */
/*  PE 手动映射                                                       */
/* ------------------------------------------------------------------ */

/* 将 .sys 文件手动映射到内核内存并调用 DriverEntry */
BOOL MapDriverToKernel(LPCWSTR DriverPath);

/* ------------------------------------------------------------------ */
/*  反取证痕迹清理                                                    */
/* ------------------------------------------------------------------ */

/* 清理 PiDDBCacheTable 中的漏洞驱动记录 */
BOOL CleanPiDDBCacheTable(ULONG64 NtBase);

/* 清理 MmUnloadedDrivers 列表 */
BOOL CleanMmUnloadedDrivers(ULONG64 NtBase);

/* 清理 CI.dll g_KernelHashBucketList 哈希桶 */
BOOL CleanKernelHashBucketList(ULONG64 NtBase);

/* 执行全部清理 */
BOOL CleanAllTraces(void);
