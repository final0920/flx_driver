#include "../inc/common.h"
#include "../inc/vmx.h"

/* ================================================================== */
/*  VT-x 核心 - VMCS 配置与每核初始化                                 */
/*                                                                    */
/*  流程：检查 CPU 能力 → 分配 VMXON/VMCS region →                    */
/*  VMXON → 配置 VMCS → VMLAUNCH → 进入 Guest 模式                   */
/* ================================================================== */

/* ------------------------------------------------------------------ */
/*  全局 VMX 状态                                                     */
/* ------------------------------------------------------------------ */

static VMX_STATE g_VmxState = { 0 };

PVMX_STATE VmxGetState(VOID) { return &g_VmxState; }

/* ------------------------------------------------------------------ */
/*  辅助：调整 VMX 控制域（按 MSR 约束设置必须为 1/0 的位）           */
/* ------------------------------------------------------------------ */

static ULONG
VmxAdjustControls(ULONG Desired, ULONG MsrIndex)
{
    LARGE_INTEGER msr;
    msr.QuadPart = AsmReadMsr(MsrIndex);
    Desired |= msr.LowPart;        /* 位为 1 → 必须置 1 */
    Desired &= msr.HighPart;       /* 位为 0 → 必须清 0 */
    return Desired;
}

/* ------------------------------------------------------------------ */
/*  辅助：获取段 Base (从 GDT 解析)                                   */
/* ------------------------------------------------------------------ */

static ULONG64
VmxGetSegmentBase(ULONG64 GdtBase, USHORT Selector)
{
    if (!Selector || (Selector & 0x4))   /* NULL 或 LDT 选择子 */
        return 0;

    PSEGMENT_DESCRIPTOR desc =
        (PSEGMENT_DESCRIPTOR)(GdtBase + (Selector & ~7));

    ULONG64 base = desc->BaseLow |
                   ((ULONG64)desc->BaseMiddle << 16) |
                   ((ULONG64)desc->BaseHigh << 24);

    /* 系统段 (TSS/LDT) 在 x64 下占 16 字节，高 32 位在下一个 QWORD */
    if (!(desc->AccessByte & 0x10)) {
        PULONG32 high = (PULONG32)((PUCHAR)desc + 8);
        base |= ((ULONG64)*high) << 32;
    }

    return base;
}

/* ------------------------------------------------------------------ */
/*  辅助：获取段 Access Rights (VMX 格式)                             */
/* ------------------------------------------------------------------ */

static ULONG
VmxGetSegmentAR(ULONG64 GdtBase, USHORT Selector)
{
    if (!Selector)
        return VMX_SEGMENT_AR_UNUSABLE;

    PSEGMENT_DESCRIPTOR desc =
        (PSEGMENT_DESCRIPTOR)(GdtBase + (Selector & ~7));

    /* Bits: Type(3:0) | S(4) | DPL(6:5) | P(7) | reserved(11:8)
             | AVL(12) | L(13) | D/B(14) | G(15) */
    ULONG ar = desc->AccessByte & 0xFF;
    ar |= ((ULONG)(desc->Granularity) & 0xF0) << 4;

    /* 清除 Unusable 标志 (P 位为 1 → 可用) */
    if (!(ar & 0x80))
        ar |= VMX_SEGMENT_AR_UNUSABLE;

    return ar;
}

/* ------------------------------------------------------------------ */
/*  CPU VT-x 能力检测                                                 */
/* ------------------------------------------------------------------ */

BOOLEAN
VmxCheckSupport(VOID)
{
    int cpuInfo[4];

    /* CPUID.1:ECX[5] = VMX 支持 */
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & (1 << 5))) {
        HvLog(HV_LOG_ERROR, "CPU 不支持 VMX");
        return FALSE;
    }

    /* IA32_FEATURE_CONTROL: Lock=1 且 VMX outside SMX=1 */
    ULONG64 fc = AsmReadMsr(IA32_FEATURE_CONTROL);
    if (!(fc & FEATURE_CONTROL_LOCK)) {
        HvLog(HV_LOG_WARN, "IA32_FEATURE_CONTROL 未锁定，尝试启用 VMX");
        fc |= FEATURE_CONTROL_LOCK | FEATURE_CONTROL_VMXON_OUTSIDE;
        AsmWriteMsr(IA32_FEATURE_CONTROL, fc);
    } else if (!(fc & FEATURE_CONTROL_VMXON_OUTSIDE)) {
        HvLog(HV_LOG_ERROR, "BIOS 禁用了 VMX (IA32_FEATURE_CONTROL.VMX=0)");
        return FALSE;
    }

    /* IA32_VMX_BASIC 获取 VMCS revision ID */
    ULONG64 vmxBasic = AsmReadMsr(IA32_VMX_BASIC);
    g_VmxState.VmcsRevisionId = (ULONG)(vmxBasic & 0x7FFFFFFF);

    /* 检查 EPT/VPID 支持 */
    ULONG64 procCtls = AsmReadMsr(IA32_VMX_PROCBASED_CTLS);
    if (procCtls >> 32 & PRI_SECONDARY_CONTROLS) {
        ULONG64 procCtls2 = AsmReadMsr(IA32_VMX_PROCBASED_CTLS2);
        g_VmxState.EptSupported  = (BOOLEAN)((procCtls2 >> 32) & SEC_ENABLE_EPT);
        g_VmxState.VpidSupported = (BOOLEAN)((procCtls2 >> 32) & SEC_ENABLE_VPID);
    }

    HvLog(HV_LOG_INFO, "VMX 支持确认: RevID=0x%X EPT=%d VPID=%d",
          g_VmxState.VmcsRevisionId,
          g_VmxState.EptSupported,
          g_VmxState.VpidSupported);

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  分配 4KB 对齐的物理连续内存 (VMXON/VMCS region)                   */
/* ------------------------------------------------------------------ */

static PVOID
VmxAllocateRegion(PULONG64 OutPhysical)
{
    PHYSICAL_ADDRESS maxAddr;
    maxAddr.QuadPart = MAXULONG64;

    PVOID va = MmAllocateContiguousMemory(PAGE_SIZE, maxAddr);
    if (!va) return NULL;

    RtlZeroMemory(va, PAGE_SIZE);

    /* 写入 VMCS Revision ID */
    *(PULONG)va = g_VmxState.VmcsRevisionId;

    *OutPhysical = MmGetPhysicalAddress(va).QuadPart;
    return va;
}

/* ------------------------------------------------------------------ */
/*  配置 VMCS 控制域                                                  */
/* ------------------------------------------------------------------ */

static VOID
VmxSetupControlFields(VOID)
{
    /* --- Pin-based Controls --- */
    /* NMI exiting + Virtual NMIs */
    ULONG pinCtls = PIN_NMI_EXITING | PIN_VIRTUAL_NMI;
    pinCtls = VmxAdjustControls(pinCtls, IA32_VMX_PINBASED_CTLS);
    AsmVmWrite(VMCS_CTRL_PIN_BASED, pinCtls);

    /* --- Primary Processor-based Controls --- */
    /* 启用二级控制 + MSR Bitmap + CR3 拦截 */
    ULONG priCtls = PRI_SECONDARY_CONTROLS |
                    PRI_USE_MSR_BITMAPS |
                    PRI_CR3_LOAD_EXITING |
                    PRI_CR3_STORE_EXITING;
    priCtls = VmxAdjustControls(priCtls, IA32_VMX_PROCBASED_CTLS);
    AsmVmWrite(VMCS_CTRL_PRIMARY_PROC, priCtls);

    /* --- Secondary Processor-based Controls --- */
    /* EPT + VPID + RDTSCP 穿透 */
    ULONG secCtls = SEC_ENABLE_EPT | SEC_ENABLE_VPID | SEC_RDTSCP;
    if (g_VmxState.EptSupported)
        secCtls |= SEC_ENABLE_EPT;
    if (g_VmxState.VpidSupported)
        secCtls |= SEC_ENABLE_VPID;
    secCtls = VmxAdjustControls(secCtls, IA32_VMX_PROCBASED_CTLS2);
    AsmVmWrite(VMCS_CTRL_SECONDARY_PROC, secCtls);

    /* --- VM-Exit Controls --- */
    /* 64-bit host + 保存/加载 EFER/PAT */
    ULONG exitCtls = EXIT_HOST_ADDR_SPACE_SIZE |
                     EXIT_SAVE_IA32_EFER |
                     EXIT_LOAD_IA32_EFER |
                     EXIT_SAVE_IA32_PAT |
                     EXIT_LOAD_IA32_PAT;
    exitCtls = VmxAdjustControls(exitCtls, IA32_VMX_EXIT_CTLS);
    AsmVmWrite(VMCS_CTRL_EXIT, exitCtls);

    /* --- VM-Entry Controls --- */
    /* IA-32e mode guest + 加载 EFER/PAT */
    ULONG entryCtls = ENTRY_IA32E_MODE_GUEST |
                      ENTRY_LOAD_IA32_EFER |
                      ENTRY_LOAD_IA32_PAT;
    entryCtls = VmxAdjustControls(entryCtls, IA32_VMX_ENTRY_CTLS);
    AsmVmWrite(VMCS_CTRL_ENTRY, entryCtls);

    /* --- CR0/CR4 掩码和影子 --- */
    /* 暂不拦截 CR0，仅拦截 CR4.VMXE (bit 13) */
    AsmVmWrite(VMCS_CTRL_CR0_MASK, 0);
    AsmVmWrite(VMCS_CTRL_CR0_SHADOW, AsmReadCr0());
    AsmVmWrite(VMCS_CTRL_CR4_MASK, (1ULL << 13));  /* CR4.VMXE */
    AsmVmWrite(VMCS_CTRL_CR4_SHADOW, AsmReadCr4() & ~(1ULL << 13));

    /* 异常位图: 暂不拦截任何异常 */
    AsmVmWrite(VMCS_CTRL_EXCEPTION_BITMAP, 0);

    /* MSR Store/Load 计数: 暂为 0 */
    AsmVmWrite(VMCS_CTRL_EXIT_MSR_STORE_COUNT, 0);
    AsmVmWrite(VMCS_CTRL_EXIT_MSR_LOAD_COUNT, 0);
    AsmVmWrite(VMCS_CTRL_ENTRY_MSR_LOAD_COUNT, 0);

    /* VPID = 1 (所有 Guest 共用) */
    AsmVmWrite(VMCS_CTRL_VPID, 1);

    /* EPT Pointer: Phase 5 填充，暂置 0 */
    AsmVmWrite(VMCS_CTRL_EPT_POINTER, 0);

    /* CR3 Target Count = 0 */
    AsmVmWrite(VMCS_CTRL_CR3_TARGET_COUNT, 0);

    /* VMCS Link Pointer = -1 (无嵌套 VMCS) */
    AsmVmWrite(VMCS_GUEST_VMCS_LINK, (ULONG64)-1);
}

/* ------------------------------------------------------------------ */
/*  配置 VMCS Host 状态域                                             */
/* ------------------------------------------------------------------ */

static VOID
VmxSetupHostState(PVMX_PROCESSOR_CTX ProcCtx)
{
    DESC_TABLE_REG gdtr, idtr;
    AsmGetGdtr(&gdtr);
    AsmGetIdtr(&idtr);

    /* 控制寄存器 */
    AsmVmWrite(VMCS_HOST_CR0, AsmReadCr0());
    AsmVmWrite(VMCS_HOST_CR3, AsmReadCr3());
    AsmVmWrite(VMCS_HOST_CR4, AsmReadCr4());

    /* RSP = Host 栈顶, RIP = VM-Exit 入口 */
    AsmVmWrite(VMCS_HOST_RSP,
               (ULONG64)ProcCtx->HostStack + VMX_HOST_STACK_SIZE - 8);
    AsmVmWrite(VMCS_HOST_RIP, (ULONG64)AsmVmExitHandler);

    /* 段选择子 (RPL 清零) */
    AsmVmWrite(VMCS_HOST_CS_SEL, AsmGetCs() & 0xF8);
    AsmVmWrite(VMCS_HOST_SS_SEL, AsmGetSs() & 0xF8);
    AsmVmWrite(VMCS_HOST_DS_SEL, AsmGetDs() & 0xF8);
    AsmVmWrite(VMCS_HOST_ES_SEL, AsmGetEs() & 0xF8);
    AsmVmWrite(VMCS_HOST_FS_SEL, AsmGetFs() & 0xF8);
    AsmVmWrite(VMCS_HOST_GS_SEL, AsmGetGs() & 0xF8);
    AsmVmWrite(VMCS_HOST_TR_SEL, AsmGetTr() & 0xF8);

    /* 段基址 */
    AsmVmWrite(VMCS_HOST_FS_BASE,   AsmReadMsr(IA32_FS_BASE));
    AsmVmWrite(VMCS_HOST_GS_BASE,   AsmReadMsr(IA32_GS_BASE));
    AsmVmWrite(VMCS_HOST_TR_BASE,   VmxGetSegmentBase(gdtr.Base, AsmGetTr()));
    AsmVmWrite(VMCS_HOST_GDTR_BASE, gdtr.Base);
    AsmVmWrite(VMCS_HOST_IDTR_BASE, idtr.Base);

    /* MSR */
    AsmVmWrite(VMCS_HOST_SYSENTER_CS,  AsmReadMsr(IA32_SYSENTER_CS));
    AsmVmWrite(VMCS_HOST_SYSENTER_ESP, AsmReadMsr(IA32_SYSENTER_ESP));
    AsmVmWrite(VMCS_HOST_SYSENTER_EIP, AsmReadMsr(IA32_SYSENTER_EIP));
    AsmVmWrite(VMCS_HOST_EFER,         AsmReadMsr(IA32_EFER));
    AsmVmWrite(VMCS_HOST_PAT,          AsmReadMsr(IA32_PAT));
}

/* ------------------------------------------------------------------ */
/*  配置 VMCS Guest 状态域 (从当前 CPU 状态复制)                      */
/* ------------------------------------------------------------------ */

static VOID
VmxSetupGuestState(VOID)
{
    DESC_TABLE_REG gdtr, idtr;
    AsmGetGdtr(&gdtr);
    AsmGetIdtr(&idtr);

    /* 控制寄存器 */
    ULONG64 cr0 = AsmReadCr0();
    ULONG64 cr3 = AsmReadCr3();
    ULONG64 cr4 = AsmReadCr4();

    /* CR0/CR4 必须满足 FIXED0/FIXED1 约束 */
    cr0 |= AsmReadMsr(IA32_VMX_CR0_FIXED0);
    cr0 &= AsmReadMsr(IA32_VMX_CR0_FIXED1);
    cr4 |= AsmReadMsr(IA32_VMX_CR4_FIXED0);
    cr4 &= AsmReadMsr(IA32_VMX_CR4_FIXED1);

    AsmVmWrite(VMCS_GUEST_CR0, cr0);
    AsmVmWrite(VMCS_GUEST_CR3, cr3);
    AsmVmWrite(VMCS_GUEST_CR4, cr4);

    AsmVmWrite(VMCS_GUEST_DR7, __readdr(7));

    /* 段选择子 */
    AsmVmWrite(VMCS_GUEST_CS_SEL,   AsmGetCs());
    AsmVmWrite(VMCS_GUEST_SS_SEL,   AsmGetSs());
    AsmVmWrite(VMCS_GUEST_DS_SEL,   AsmGetDs());
    AsmVmWrite(VMCS_GUEST_ES_SEL,   AsmGetEs());
    AsmVmWrite(VMCS_GUEST_FS_SEL,   AsmGetFs());
    AsmVmWrite(VMCS_GUEST_GS_SEL,   AsmGetGs());
    AsmVmWrite(VMCS_GUEST_TR_SEL,   AsmGetTr());
    AsmVmWrite(VMCS_GUEST_LDTR_SEL, AsmGetLdtr());

    /* 段 Limit */
    AsmVmWrite(VMCS_GUEST_CS_LIMIT,   __segmentlimit(AsmGetCs()));
    AsmVmWrite(VMCS_GUEST_SS_LIMIT,   __segmentlimit(AsmGetSs()));
    AsmVmWrite(VMCS_GUEST_DS_LIMIT,   __segmentlimit(AsmGetDs()));
    AsmVmWrite(VMCS_GUEST_ES_LIMIT,   __segmentlimit(AsmGetEs()));
    AsmVmWrite(VMCS_GUEST_FS_LIMIT,   __segmentlimit(AsmGetFs()));
    AsmVmWrite(VMCS_GUEST_GS_LIMIT,   __segmentlimit(AsmGetGs()));
    AsmVmWrite(VMCS_GUEST_TR_LIMIT,   __segmentlimit(AsmGetTr()));
    AsmVmWrite(VMCS_GUEST_LDTR_LIMIT, __segmentlimit(AsmGetLdtr()));
    AsmVmWrite(VMCS_GUEST_GDTR_LIMIT, gdtr.Limit);
    AsmVmWrite(VMCS_GUEST_IDTR_LIMIT, idtr.Limit);

    /* 段 Access Rights */
    AsmVmWrite(VMCS_GUEST_CS_AR,   VmxGetSegmentAR(gdtr.Base, AsmGetCs()));
    AsmVmWrite(VMCS_GUEST_SS_AR,   VmxGetSegmentAR(gdtr.Base, AsmGetSs()));
    AsmVmWrite(VMCS_GUEST_DS_AR,   VmxGetSegmentAR(gdtr.Base, AsmGetDs()));
    AsmVmWrite(VMCS_GUEST_ES_AR,   VmxGetSegmentAR(gdtr.Base, AsmGetEs()));
    AsmVmWrite(VMCS_GUEST_FS_AR,   VmxGetSegmentAR(gdtr.Base, AsmGetFs()));
    AsmVmWrite(VMCS_GUEST_GS_AR,   VmxGetSegmentAR(gdtr.Base, AsmGetGs()));
    AsmVmWrite(VMCS_GUEST_TR_AR,   VmxGetSegmentAR(gdtr.Base, AsmGetTr()));
    AsmVmWrite(VMCS_GUEST_LDTR_AR, VmxGetSegmentAR(gdtr.Base, AsmGetLdtr()));

    /* 段 Base */
    AsmVmWrite(VMCS_GUEST_CS_BASE,   VmxGetSegmentBase(gdtr.Base, AsmGetCs()));
    AsmVmWrite(VMCS_GUEST_SS_BASE,   VmxGetSegmentBase(gdtr.Base, AsmGetSs()));
    AsmVmWrite(VMCS_GUEST_DS_BASE,   VmxGetSegmentBase(gdtr.Base, AsmGetDs()));
    AsmVmWrite(VMCS_GUEST_ES_BASE,   VmxGetSegmentBase(gdtr.Base, AsmGetEs()));
    AsmVmWrite(VMCS_GUEST_FS_BASE,   AsmReadMsr(IA32_FS_BASE));
    AsmVmWrite(VMCS_GUEST_GS_BASE,   AsmReadMsr(IA32_GS_BASE));
    AsmVmWrite(VMCS_GUEST_TR_BASE,   VmxGetSegmentBase(gdtr.Base, AsmGetTr()));
    AsmVmWrite(VMCS_GUEST_LDTR_BASE, VmxGetSegmentBase(gdtr.Base, AsmGetLdtr()));
    AsmVmWrite(VMCS_GUEST_GDTR_BASE, gdtr.Base);
    AsmVmWrite(VMCS_GUEST_IDTR_BASE, idtr.Base);

    /* RFLAGS: 从当前 CPU 获取 */
    AsmVmWrite(VMCS_GUEST_RFLAGS, __readeflags());

    /* MSR */
    AsmVmWrite(VMCS_GUEST_SYSENTER_CS,  AsmReadMsr(IA32_SYSENTER_CS));
    AsmVmWrite(VMCS_GUEST_SYSENTER_ESP, AsmReadMsr(IA32_SYSENTER_ESP));
    AsmVmWrite(VMCS_GUEST_SYSENTER_EIP, AsmReadMsr(IA32_SYSENTER_EIP));
    AsmVmWrite(VMCS_GUEST_DEBUGCTL,     AsmReadMsr(IA32_DEBUGCTL));
    AsmVmWrite(VMCS_GUEST_EFER,         AsmReadMsr(IA32_EFER));
    AsmVmWrite(VMCS_GUEST_PAT,          AsmReadMsr(IA32_PAT));

    /* Activity/Interruptibility: Active, 无挂起 */
    AsmVmWrite(VMCS_GUEST_ACTIVITY, 0);
    AsmVmWrite(VMCS_GUEST_INTERRUPTIBILITY, 0);
    AsmVmWrite(VMCS_GUEST_PENDING_DBG, 0);

    /* Guest RSP/RIP 由 AsmVmxLaunch 在 vmlaunch 前设置 */
}

/* ------------------------------------------------------------------ */
/*  每核 VMX 初始化 (DPC 回调，在目标 CPU 上执行)                     */
/* ------------------------------------------------------------------ */

static VOID
VmxInitProcessor(
    _In_ struct _KDPC  *Dpc,
    _In_opt_ PVOID      Context,
    _In_opt_ PVOID      Arg1,
    _In_opt_ PVOID      Arg2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    PLONG pSuccess = (PLONG)Context;
    ULONG cpuIndex = KeGetCurrentProcessorNumberEx(NULL);

    PVMX_PROCESSOR_CTX procCtx = &g_VmxState.Processors[cpuIndex];

    HvLog(HV_LOG_INFO, "VMX 初始化 CPU #%lu", cpuIndex);

    /* 1. 分配 VMXON region */
    procCtx->VmxonRegion = VmxAllocateRegion(&procCtx->VmxonPhysical);
    if (!procCtx->VmxonRegion) {
        HvLog(HV_LOG_ERROR, "CPU #%lu: VMXON region 分配失败", cpuIndex);
        return;
    }

    /* 2. 分配 VMCS region */
    procCtx->VmcsRegion = VmxAllocateRegion(&procCtx->VmcsPhysical);
    if (!procCtx->VmcsRegion) {
        HvLog(HV_LOG_ERROR, "CPU #%lu: VMCS region 分配失败", cpuIndex);
        return;
    }

    /* 3. 分配 Host 栈 */
    procCtx->HostStack = HvAllocate(VMX_HOST_STACK_SIZE);
    if (!procCtx->HostStack) {
        HvLog(HV_LOG_ERROR, "CPU #%lu: Host 栈分配失败", cpuIndex);
        return;
    }

    /* 4. 启用 CR4.VMXE */
    ULONG64 cr4 = AsmReadCr4();
    AsmWriteCr4(cr4 | (1ULL << 13));

    /* 5. VMXON */
    if (!AsmVmxOn(&procCtx->VmxonPhysical)) {
        HvLog(HV_LOG_ERROR, "CPU #%lu: VMXON 失败", cpuIndex);
        AsmWriteCr4(cr4);
        return;
    }

    /* 6. VMCLEAR + VMPTRLD */
    if (!AsmVmClear(&procCtx->VmcsPhysical)) {
        HvLog(HV_LOG_ERROR, "CPU #%lu: VMCLEAR 失败", cpuIndex);
        AsmVmxOff();
        AsmWriteCr4(cr4);
        return;
    }

    if (!AsmVmPtrld(&procCtx->VmcsPhysical)) {
        HvLog(HV_LOG_ERROR, "CPU #%lu: VMPTRLD 失败", cpuIndex);
        AsmVmxOff();
        AsmWriteCr4(cr4);
        return;
    }

    /* 7. 配置 VMCS */
    VmxSetupControlFields();
    VmxSetupHostState(procCtx);
    VmxSetupGuestState();

    /* 8. VMLAUNCH */
    if (!AsmVmxLaunch()) {
        ULONG64 errCode = AsmVmRead(0x4400); /* VM_INSTRUCTION_ERROR */
        HvLog(HV_LOG_ERROR, "CPU #%lu: VMLAUNCH 失败, error=%llu", cpuIndex, errCode);
        AsmVmxOff();
        AsmWriteCr4(cr4);
        return;
    }

    procCtx->Launched = TRUE;
    InterlockedIncrement(pSuccess);
    HvLog(HV_LOG_INFO, "CPU #%lu: VMX 启动成功 → Guest 模式", cpuIndex);
}

/* ------------------------------------------------------------------ */
/*  每核 VMX 卸载                                                     */
/* ------------------------------------------------------------------ */

static VOID
VmxDeinitProcessor(
    _In_ struct _KDPC  *Dpc,
    _In_opt_ PVOID      Context,
    _In_opt_ PVOID      Arg1,
    _In_opt_ PVOID      Arg2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    ULONG cpuIndex = KeGetCurrentProcessorNumberEx(NULL);
    PVMX_PROCESSOR_CTX procCtx = &g_VmxState.Processors[cpuIndex];

    if (procCtx->Launched) {
        /* VMCALL 通知 hypervisor 退出 */
        AsmVmCall(0xDEAD, 0);
        procCtx->Launched = FALSE;
    }

    /* 释放资源 */
    if (procCtx->VmxonRegion) {
        MmFreeContiguousMemory(procCtx->VmxonRegion);
        procCtx->VmxonRegion = NULL;
    }
    if (procCtx->VmcsRegion) {
        MmFreeContiguousMemory(procCtx->VmcsRegion);
        procCtx->VmcsRegion = NULL;
    }
    if (procCtx->HostStack) {
        HvFree(procCtx->HostStack);
        procCtx->HostStack = NULL;
    }

    HvLog(HV_LOG_INFO, "CPU #%lu: VMX 已关闭", cpuIndex);
}

/* ------------------------------------------------------------------ */
/*  全局初始化/卸载 (遍历所有 CPU)                                    */
/* ------------------------------------------------------------------ */

NTSTATUS
VmxInit(VOID)
{
    if (!VmxCheckSupport())
        return STATUS_NOT_SUPPORTED;

    g_VmxState.ProcessorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    g_VmxState.Processors = (PVMX_PROCESSOR_CTX)HvAllocate(
        g_VmxState.ProcessorCount * sizeof(VMX_PROCESSOR_CTX));
    if (!g_VmxState.Processors)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(g_VmxState.Processors,
                  g_VmxState.ProcessorCount * sizeof(VMX_PROCESSOR_CTX));

    HvLog(HV_LOG_INFO, "开始 VMX 初始化，共 %lu 核", g_VmxState.ProcessorCount);

    /* 在每个 CPU 上执行初始化 */
    LONG successCount = 0;

    for (ULONG i = 0; i < g_VmxState.ProcessorCount; i++) {
        KDPC dpc;
        PROCESSOR_NUMBER procNum;
        KeGetProcessorNumberFromIndex(i, &procNum);

        KeInitializeDpc(&dpc, VmxInitProcessor, &successCount);
        KeSetTargetProcessorDpcEx(&dpc, &procNum);
        KeSetImportanceDpc(&dpc, HighImportance);
        KeInsertQueueDpc(&dpc, NULL, NULL);
    }

    /* 等待所有 DPC 完成 */
    LARGE_INTEGER delay;
    delay.QuadPart = -10000 * 100; /* 100ms */
    KeDelayExecutionThread(KernelMode, FALSE, &delay);

    if (successCount < (LONG)g_VmxState.ProcessorCount) {
        HvLog(HV_LOG_WARN, "VMX 部分初始化: %ld/%lu 核成功",
              successCount, g_VmxState.ProcessorCount);
    } else {
        HvLog(HV_LOG_INFO, "VMX 全部 %lu 核初始化成功", g_VmxState.ProcessorCount);
    }

    return (successCount > 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

VOID
VmxDeinit(VOID)
{
    if (!g_VmxState.Processors)
        return;

    for (ULONG i = 0; i < g_VmxState.ProcessorCount; i++) {
        KDPC dpc;
        PROCESSOR_NUMBER procNum;
        KeGetProcessorNumberFromIndex(i, &procNum);

        KeInitializeDpc(&dpc, VmxDeinitProcessor, NULL);
        KeSetTargetProcessorDpcEx(&dpc, &procNum);
        KeSetImportanceDpc(&dpc, HighImportance);
        KeInsertQueueDpc(&dpc, NULL, NULL);
    }

    LARGE_INTEGER delay;
    delay.QuadPart = -10000 * 100;
    KeDelayExecutionThread(KernelMode, FALSE, &delay);

    HvFree(g_VmxState.Processors);
    g_VmxState.Processors = NULL;

    HvLog(HV_LOG_INFO, "VMX 全局卸载完成");
}

/* ------------------------------------------------------------------ */
/*  VM-Exit 分发桩 (Phase 4 实现完整逻辑)                             */
/*  返回 FALSE = vmresume, TRUE = 退出 VMX                            */
/* ------------------------------------------------------------------ */

BOOLEAN
VmExitDispatch(PGUEST_CONTEXT GuestCtx)
{
    UNREFERENCED_PARAMETER(GuestCtx);

    ULONG64 reason = AsmVmRead(VMCS_EXIT_REASON) & 0xFFFF;

    switch (reason) {
    case EXIT_REASON_VMCALL:
        if (GuestCtx->Rcx == 0xDEAD) {
            /* 关闭 VMX 请求 */
            ULONG64 instrLen = AsmVmRead(VMCS_EXIT_INSTR_LEN);
            ULONG64 rip = AsmVmRead(VMCS_GUEST_RIP);
            AsmVmWrite(VMCS_GUEST_RIP, rip + instrLen);
            return TRUE;
        }
        break;

    case EXIT_REASON_CPUID:
    {
        int cpuInfo[4];
        __cpuidex(cpuInfo, (int)GuestCtx->Rax, (int)GuestCtx->Rcx);
        GuestCtx->Rax = cpuInfo[0];
        GuestCtx->Rbx = cpuInfo[1];
        GuestCtx->Rcx = cpuInfo[2];
        GuestCtx->Rdx = cpuInfo[3];

        ULONG64 instrLen = AsmVmRead(VMCS_EXIT_INSTR_LEN);
        ULONG64 rip = AsmVmRead(VMCS_GUEST_RIP);
        AsmVmWrite(VMCS_GUEST_RIP, rip + instrLen);
        return FALSE;
    }

    default:
        break;
    }

    /* 未处理的 exit → 推进 RIP 并继续 */
    {
        ULONG64 instrLen = AsmVmRead(VMCS_EXIT_INSTR_LEN);
        ULONG64 rip = AsmVmRead(VMCS_GUEST_RIP);
        AsmVmWrite(VMCS_GUEST_RIP, rip + instrLen);
    }
    return FALSE;
}
