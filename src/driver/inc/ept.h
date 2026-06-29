#pragma once

/* ================================================================== */
/*  EPT (Extended Page Tables) 定义 - Phase 5                         */
/*                                                                    */
/*  PML4 → PDPT → PD(2MB) → PT(4KB)  恒等映射物理内存                */
/*  MTRR-aware 内存类型 + 大页拆分 + 属性修改 + INVEPT                */
/* ================================================================== */

/* ------------------------------------------------------------------ */
/*  EPT 内存类型 (Intel SDM Table 28-6)                               */
/* ------------------------------------------------------------------ */

#define EPT_MT_UC   0   /* Uncacheable                                */
#define EPT_MT_WC   1   /* Write Combining                            */
#define EPT_MT_WT   4   /* Write Through                              */
#define EPT_MT_WP   5   /* Write Protected                            */
#define EPT_MT_WB   6   /* Write Back                                 */

/* ------------------------------------------------------------------ */
/*  EPT 页表项 (PML4E / PDPTE / PDE / PTE 统一格式)                   */
/* ------------------------------------------------------------------ */

typedef union _EPT_ENTRY {
    ULONG64 Value;
    struct {
        ULONG64 Read        : 1;   /* 0  — 读访问                     */
        ULONG64 Write       : 1;   /* 1  — 写访问                     */
        ULONG64 Execute     : 1;   /* 2  — 执行访问                   */
        ULONG64 MemoryType  : 3;   /* 5:3  — 内存类型 (仅叶子项)      */
        ULONG64 IgnorePat   : 1;   /* 6    — 忽略 PAT (仅叶子项)      */
        ULONG64 LargePage   : 1;   /* 7    — 大页 (PDE=2MB/PDPTE=1GB) */
        ULONG64 Accessed    : 1;   /* 8                               */
        ULONG64 Dirty       : 1;   /* 9    — (仅叶子项)               */
        ULONG64 UserExecute : 1;   /* 10                              */
        ULONG64 Reserved0   : 1;   /* 11                              */
        ULONG64 Pfn         : 40;  /* 51:12 — 物理页帧号              */
        ULONG64 Reserved1   : 12;  /* 63:52                           */
    };
} EPT_ENTRY, *PEPT_ENTRY;

C_ASSERT(sizeof(EPT_ENTRY) == 8);

#define EPT_ENTRY_COUNT     512
#define EPT_TABLE_SIZE      PAGE_SIZE

/* ------------------------------------------------------------------ */
/*  MTRR 缓存状态                                                     */
/* ------------------------------------------------------------------ */

#define MTRR_MAX_VARIABLE   16

typedef struct _MTRR_RANGE {
    ULONG64 Base;
    ULONG64 Mask;
    UCHAR   Type;
    BOOLEAN Valid;
} MTRR_RANGE, *PMTRR_RANGE;

typedef struct _MTRR_STATE {
    UCHAR      DefaultType;
    BOOLEAN    MtrrEnabled;
    BOOLEAN    FixedEnabled;
    MTRR_RANGE Variable[MTRR_MAX_VARIABLE];
    ULONG      VariableCount;
} MTRR_STATE, *PMTRR_STATE;

/* ------------------------------------------------------------------ */
/*  EPT 页追踪 (PA↔VA 映射)                                          */
/* ------------------------------------------------------------------ */

#define EPT_MAX_PAGES   1024

typedef struct _EPT_PAGE_ENTRY {
    PVOID   Va;
    ULONG64 Pa;
} EPT_PAGE_ENTRY;

/* ------------------------------------------------------------------ */
/*  EPT 全局状态                                                      */
/* ------------------------------------------------------------------ */

typedef struct _EPT_STATE {
    PEPT_ENTRY      Pml4;
    ULONG64         Pml4Physical;
    ULONG64         Eptp;
    MTRR_STATE      Mtrr;

    EPT_PAGE_ENTRY  Pages[EPT_MAX_PAGES];
    ULONG           PageCount;
} EPT_STATE, *PEPT_STATE;

/* ------------------------------------------------------------------ */
/*  函数声明                                                          */
/* ------------------------------------------------------------------ */

/* 初始化/销毁 */
NTSTATUS EptInit(PEPT_STATE Ept);
VOID     EptDeinit(PEPT_STATE Ept);

/* 大页拆分: 2MB → 512 × 4KB */
NTSTATUS EptSplitLargePage(PEPT_STATE Ept, ULONG64 PhysAddr);

/* 获取 4KB 粒度 PTE (需先 Split, 否则返回 NULL) */
PEPT_ENTRY EptGetPte(PEPT_STATE Ept, ULONG64 PhysAddr);

/* 修改 4KB 页属性 (RWX) */
VOID EptSetPageAttributes(PEPT_STATE Ept, ULONG64 PhysAddr,
                          BOOLEAN Read, BOOLEAN Write, BOOLEAN Execute);

/* INVEPT 刷新 EPT TLB */
VOID EptInvalidate(PEPT_STATE Ept);
