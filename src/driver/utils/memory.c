#include "../inc/common.h"

/* ------------------------------------------------------------------ */
/*  池分配辅助  -  带标签的 NonPagedPool 封装 (Win7+ 兼容)            */
/* ------------------------------------------------------------------ */

#pragma warning(push)
#pragma warning(disable: 4996) /* ExAllocatePoolWithTag 在新 WDK 标记废弃 */
PVOID
HvAllocate(_In_ SIZE_T Size)
{
    PVOID p = ExAllocatePoolWithTag(NonPagedPool, Size, HV_POOL_TAG);
    if (p) RtlZeroMemory(p, Size);
    return p;
}
#pragma warning(pop)

VOID
HvFree(_In_opt_ PVOID Ptr)
{
    if (Ptr)
        ExFreePoolWithTag(Ptr, HV_POOL_TAG);
}
