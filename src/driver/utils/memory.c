#include "../inc/common.h"

/* ------------------------------------------------------------------ */
/*  池分配辅助  -  带标签的 NonPagedPool 封装                         */
/*  ExAllocatePool2 默认零初始化（Win10 2004+）                       */
/* ------------------------------------------------------------------ */

PVOID
HvAllocate(_In_ SIZE_T Size)
{
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, HV_POOL_TAG);
}

VOID
HvFree(_In_opt_ PVOID Ptr)
{
    if (Ptr)
        ExFreePoolWithTag(Ptr, HV_POOL_TAG);
}
