#include "../inc/common.h"
#include "../inc/vmx.h"
#include "../inc/ept.h"

/* ================================================================== */
/*  EPT 页表 - Phase 5                                                */
/*                                                                    */
/*  恒等映射全部物理内存 (2MB 大页) + MTRR 内存类型 +                 */
/*  运行时大页拆分 (Phase 6 Hook 用) + INVEPT                         */
/* ================================================================== */

/* ------------------------------------------------------------------ */
/*  MTRR MSR 索引                                                     */
/* ------------------------------------------------------------------ */

#define IA32_MTRRCAP              0x00FE
#define IA32_MTRR_DEF_TYPE_MSR    0x02FF
#define IA32_MTRR_PHYSBASE(n)     (0x0200 + 2 * (n))
#define IA32_MTRR_PHYSMASK(n)     (0x0201 + 2 * (n))

/* ------------------------------------------------------------------ */
/*  初始化 MTRR 缓存                                                  */
/* ------------------------------------------------------------------ */

static VOID
EptInitMtrr(PMTRR_STATE Mtrr)
{
    RtlZeroMemory(Mtrr, sizeof(MTRR_STATE));

    ULONG64 defType = AsmReadMsr(IA32_MTRR_DEF_TYPE_MSR);
    Mtrr->DefaultType  = (UCHAR)(defType & 0xFF);
    Mtrr->FixedEnabled = (BOOLEAN)((defType >> 10) & 1);
    Mtrr->MtrrEnabled  = (BOOLEAN)((defType >> 11) & 1);

    if (!Mtrr->MtrrEnabled) {
        Mtrr->DefaultType = EPT_MT_UC;
        return;
    }

    ULONG64 cap = AsmReadMsr(IA32_MTRRCAP);
    Mtrr->VariableCount = (ULONG)(cap & 0xFF);
    if (Mtrr->VariableCount > MTRR_MAX_VARIABLE)
        Mtrr->VariableCount = MTRR_MAX_VARIABLE;

    for (ULONG i = 0; i < Mtrr->VariableCount; i++) {
        ULONG64 base = AsmReadMsr(IA32_MTRR_PHYSBASE(i));
        ULONG64 mask = AsmReadMsr(IA32_MTRR_PHYSMASK(i));

        Mtrr->Variable[i].Valid = (BOOLEAN)((mask >> 11) & 1);
        Mtrr->Variable[i].Type  = (UCHAR)(base & 0xFF);
        Mtrr->Variable[i].Base  = base & ~0xFFFULL;
        Mtrr->Variable[i].Mask  = mask & ~0xFFFULL;
    }

    HvLog(HV_LOG_INFO, "MTRR: %lu 个可变范围, 默认类型=%u",
          Mtrr->VariableCount, Mtrr->DefaultType);
}

/* ------------------------------------------------------------------ */
/*  查询物理地址的 MTRR 内存类型                                      */
/* ------------------------------------------------------------------ */

static UCHAR
EptGetMtrrType(PMTRR_STATE Mtrr, ULONG64 PhysAddr)
{
    if (!Mtrr->MtrrEnabled)
        return EPT_MT_UC;

    UCHAR result = 0xFF;

    for (ULONG i = 0; i < Mtrr->VariableCount; i++) {
        if (!Mtrr->Variable[i].Valid)
            continue;

        if ((PhysAddr & Mtrr->Variable[i].Mask) ==
            (Mtrr->Variable[i].Base & Mtrr->Variable[i].Mask))
        {
            /* UC 优先级最高 (Intel SDM Vol3 12.11.4.1) */
            if (Mtrr->Variable[i].Type == EPT_MT_UC)
                return EPT_MT_UC;
            if (result == 0xFF)
                result = Mtrr->Variable[i].Type;
            else if (result == EPT_MT_WB && Mtrr->Variable[i].Type == EPT_MT_WT)
                result = EPT_MT_WT;
            else if (result == EPT_MT_WT && Mtrr->Variable[i].Type == EPT_MT_WB)
                result = EPT_MT_WT;
        }
    }

    return (result != 0xFF) ? result : Mtrr->DefaultType;
}

/* ------------------------------------------------------------------ */
/*  分配一页 EPT 表并追踪 PA↔VA 映射                                  */
/* ------------------------------------------------------------------ */

static PEPT_ENTRY
EptAllocatePage(PEPT_STATE Ept, PULONG64 OutPhysical)
{
    if (Ept->PageCount >= EPT_MAX_PAGES) {
        HvLog(HV_LOG_ERROR, "EPT 页追踪已满 (%u)", EPT_MAX_PAGES);
        return NULL;
    }

    PHYSICAL_ADDRESS maxAddr;
    maxAddr.QuadPart = MAXULONG64;

    PVOID va = MmAllocateContiguousMemory(PAGE_SIZE, maxAddr);
    if (!va) return NULL;

    RtlZeroMemory(va, PAGE_SIZE);

    ULONG64 pa = MmGetPhysicalAddress(va).QuadPart;
    *OutPhysical = pa;

    Ept->Pages[Ept->PageCount].Va = va;
    Ept->Pages[Ept->PageCount].Pa = pa;
    Ept->PageCount++;

    return (PEPT_ENTRY)va;
}

/* ------------------------------------------------------------------ */
/*  PA → VA 查找 (线性扫描, 仅在 Hook 安装时调用)                     */
/* ------------------------------------------------------------------ */

static PVOID
EptPhysToVirt(PEPT_STATE Ept, ULONG64 PhysAddr)
{
    for (ULONG i = 0; i < Ept->PageCount; i++) {
        if (Ept->Pages[i].Pa == PhysAddr)
            return Ept->Pages[i].Va;
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  获取最大物理地址                                                   */
/* ------------------------------------------------------------------ */

static ULONG64
EptGetMaxPhysicalAddress(VOID)
{
    ULONG64 maxAddr = 0;
    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();

    if (ranges) {
        for (ULONG i = 0;
             ranges[i].BaseAddress.QuadPart || ranges[i].NumberOfBytes.QuadPart;
             i++)
        {
            ULONG64 end = ranges[i].BaseAddress.QuadPart +
                          ranges[i].NumberOfBytes.QuadPart;
            if (end > maxAddr) maxAddr = end;
        }
        ExFreePool(ranges);
    }

    /* 上取到下个 GB 边界 + 4GB MMIO 余量, 上限 512GB */
    maxAddr = (maxAddr + (1ULL << 30) - 1) & ~((1ULL << 30) - 1);
    maxAddr += 4ULL << 30;

    if (maxAddr > (512ULL << 30))
        maxAddr = 512ULL << 30;

    if (maxAddr == 0)
        maxAddr = 4ULL << 30;   /* 至少 4GB */

    return maxAddr;
}

/* ------------------------------------------------------------------ */
/*  构造 EPTP 值                                                      */
/*  Bits 2:0 = 内存类型 (6=WB)                                       */
/*  Bits 5:3 = 页遍历长度-1 (3=四级)                                 */
/*  Bit  6   = Accessed/Dirty 启用                                    */
/*  Bits 51:12 = PML4 物理地址                                        */
/* ------------------------------------------------------------------ */

static ULONG64
EptBuildEptp(ULONG64 Pml4Physical)
{
    return Pml4Physical | (EPT_MT_WB) | (3ULL << 3) | (1ULL << 6);
}

/* ------------------------------------------------------------------ */
/*  EPT 初始化: 恒等映射全部物理内存 (2MB 大页)                       */
/* ------------------------------------------------------------------ */

NTSTATUS
EptInit(PEPT_STATE Ept)
{
    RtlZeroMemory(Ept, sizeof(EPT_STATE));

    /* 1. 缓存 MTRR */
    EptInitMtrr(&Ept->Mtrr);

    /* 2. 确定映射范围 */
    ULONG64 maxAddr = EptGetMaxPhysicalAddress();
    ULONG pdptEntryCount = (ULONG)(maxAddr >> 30);
    if (pdptEntryCount > 512) pdptEntryCount = 512;
    if (pdptEntryCount == 0)  pdptEntryCount = 1;

    HvLog(HV_LOG_INFO, "EPT 恒等映射: 0 → 0x%llX (%lu GB, 2MB 大页)",
          maxAddr, pdptEntryCount);

    /* 3. 分配 PML4 */
    Ept->Pml4 = EptAllocatePage(Ept, &Ept->Pml4Physical);
    if (!Ept->Pml4) return STATUS_INSUFFICIENT_RESOURCES;

    /* 4. 分配 PDPT */
    ULONG64 pdptPa;
    PEPT_ENTRY pdpt = EptAllocatePage(Ept, &pdptPa);
    if (!pdpt) return STATUS_INSUFFICIENT_RESOURCES;

    /* PML4[0] → PDPT */
    Ept->Pml4[0].Read    = 1;
    Ept->Pml4[0].Write   = 1;
    Ept->Pml4[0].Execute = 1;
    Ept->Pml4[0].Pfn     = pdptPa >> 12;

    /* 5. 对每个 1GB 范围分配 PD, 填充 2MB 大页 */
    for (ULONG i = 0; i < pdptEntryCount; i++) {
        ULONG64 pdPa;
        PEPT_ENTRY pd = EptAllocatePage(Ept, &pdPa);
        if (!pd) return STATUS_INSUFFICIENT_RESOURCES;

        /* PDPT[i] → PD[i] */
        pdpt[i].Read    = 1;
        pdpt[i].Write   = 1;
        pdpt[i].Execute = 1;
        pdpt[i].Pfn     = pdPa >> 12;

        /* PD: 512 × 2MB 大页 */
        for (ULONG j = 0; j < EPT_ENTRY_COUNT; j++) {
            ULONG64 physAddr = ((ULONG64)i << 30) | ((ULONG64)j << 21);
            UCHAR   memType  = EptGetMtrrType(&Ept->Mtrr, physAddr);

            pd[j].Read       = 1;
            pd[j].Write      = 1;
            pd[j].Execute    = 1;
            pd[j].MemoryType = memType;
            pd[j].LargePage  = 1;
            pd[j].Pfn        = physAddr >> 12;
        }
    }

    /* 6. 构造 EPTP */
    Ept->Eptp = EptBuildEptp(Ept->Pml4Physical);

    HvLog(HV_LOG_INFO, "EPT 初始化完成: EPTP=0x%llX, 页表=%lu 页",
          Ept->Eptp, Ept->PageCount);

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  EPT 销毁: 释放所有追踪页                                          */
/* ------------------------------------------------------------------ */

VOID
EptDeinit(PEPT_STATE Ept)
{
    for (ULONG i = 0; i < Ept->PageCount; i++) {
        if (Ept->Pages[i].Va)
            MmFreeContiguousMemory(Ept->Pages[i].Va);
    }
    Ept->PageCount = 0;
    Ept->Pml4 = NULL;

    HvLog(HV_LOG_INFO, "EPT 已销毁");
}

/* ------------------------------------------------------------------ */
/*  EPT 遍历: 获取 GPA 对应的 PDE (2MB 粒度)                         */
/* ------------------------------------------------------------------ */

static PEPT_ENTRY
EptGetPde(PEPT_STATE Ept, ULONG64 PhysAddr)
{
    ULONG pml4Idx = (ULONG)((PhysAddr >> 39) & 0x1FF);
    ULONG pdptIdx = (ULONG)((PhysAddr >> 30) & 0x1FF);
    ULONG pdIdx   = (ULONG)((PhysAddr >> 21) & 0x1FF);

    /* PML4 → PDPT */
    if (!(Ept->Pml4[pml4Idx].Value & 7))
        return NULL;

    ULONG64 pdptPa = (ULONG64)Ept->Pml4[pml4Idx].Pfn << 12;
    PEPT_ENTRY pdpt = (PEPT_ENTRY)EptPhysToVirt(Ept, pdptPa);
    if (!pdpt) return NULL;

    /* PDPT → PD */
    if (!(pdpt[pdptIdx].Value & 7))
        return NULL;

    ULONG64 pdPa = (ULONG64)pdpt[pdptIdx].Pfn << 12;
    PEPT_ENTRY pd = (PEPT_ENTRY)EptPhysToVirt(Ept, pdPa);
    if (!pd) return NULL;

    return &pd[pdIdx];
}

/* ------------------------------------------------------------------ */
/*  获取 GPA 对应的 PTE (4KB 粒度, 需已拆分)                         */
/* ------------------------------------------------------------------ */

PEPT_ENTRY
EptGetPte(PEPT_STATE Ept, ULONG64 PhysAddr)
{
    PEPT_ENTRY pde = EptGetPde(Ept, PhysAddr);
    if (!pde || pde->LargePage)
        return NULL;    /* 还是 2MB 大页, 未拆分 */

    ULONG ptIdx = (ULONG)((PhysAddr >> 12) & 0x1FF);

    ULONG64 ptPa = (ULONG64)pde->Pfn << 12;
    PEPT_ENTRY pt = (PEPT_ENTRY)EptPhysToVirt(Ept, ptPa);
    if (!pt) return NULL;

    return &pt[ptIdx];
}

/* ------------------------------------------------------------------ */
/*  大页拆分: 2MB → 512 × 4KB                                        */
/*                                                                    */
/*  把一个 2MB PDE 大页拆成 512 个 4KB PTE,                           */
/*  每个 PTE 继承原大页的 RWX 和内存类型                              */
/* ------------------------------------------------------------------ */

NTSTATUS
EptSplitLargePage(PEPT_STATE Ept, ULONG64 PhysAddr)
{
    PEPT_ENTRY pde = EptGetPde(Ept, PhysAddr);
    if (!pde) {
        HvLog(HV_LOG_ERROR, "EPT Split: GPA=0x%llX 无 PDE", PhysAddr);
        return STATUS_NOT_FOUND;
    }

    if (!pde->LargePage) {
        /* 已经是 4KB 页, 无需再拆 */
        return STATUS_SUCCESS;
    }

    /* 保存原大页属性 */
    ULONG64 basePfn   = pde->Pfn & ~0x1FFULL; /* 2MB 对齐: 清低 9 位 */
    UCHAR   memType   = (UCHAR)pde->MemoryType;
    BOOLEAN read      = (BOOLEAN)pde->Read;
    BOOLEAN write     = (BOOLEAN)pde->Write;
    BOOLEAN execute   = (BOOLEAN)pde->Execute;

    /* 分配新 PT */
    ULONG64 ptPa;
    PEPT_ENTRY pt = EptAllocatePage(Ept, &ptPa);
    if (!pt) return STATUS_INSUFFICIENT_RESOURCES;

    /* 填充 512 个 4KB PTE */
    for (ULONG k = 0; k < EPT_ENTRY_COUNT; k++) {
        pt[k].Read       = read;
        pt[k].Write      = write;
        pt[k].Execute    = execute;
        pt[k].MemoryType = memType;
        pt[k].LargePage  = 0;
        pt[k].Pfn        = basePfn + k;
    }

    /* 更新 PDE: 指向新 PT, 清大页位 */
    pde->LargePage  = 0;
    pde->MemoryType = 0;   /* 非叶子项: 类型字段保留为 0 */
    pde->IgnorePat  = 0;
    pde->Pfn        = ptPa >> 12;
    /* RWX 保持 (非叶子项的 RWX 控制子级的可访问性) */

    HvLog(HV_LOG_DEBUG, "EPT Split: 2MB → 4KB @ GPA=0x%llX", PhysAddr);

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  修改 4KB 页的 RWX 属性 (需先 Split)                               */
/* ------------------------------------------------------------------ */

VOID
EptSetPageAttributes(
    PEPT_STATE Ept,
    ULONG64   PhysAddr,
    BOOLEAN   Read,
    BOOLEAN   Write,
    BOOLEAN   Execute)
{
    PEPT_ENTRY pte = EptGetPte(Ept, PhysAddr);
    if (!pte) {
        HvLog(HV_LOG_ERROR, "EPT SetAttr: GPA=0x%llX 未拆分", PhysAddr);
        return;
    }

    pte->Read    = Read;
    pte->Write   = Write;
    pte->Execute = Execute;
}

/* ------------------------------------------------------------------ */
/*  INVEPT 刷新 EPT TLB 缓存                                         */
/* ------------------------------------------------------------------ */

VOID
EptInvalidate(PEPT_STATE Ept)
{
    INVEPT_DESC desc;
    desc.EptPointer = Ept->Eptp;
    desc.Reserved   = 0;
    AsmInvept(INVEPT_ALL_CONTEXT, &desc);
}
