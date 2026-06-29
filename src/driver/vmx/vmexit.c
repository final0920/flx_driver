#include "../inc/common.h"
#include "../inc/vmx.h"

/* ================================================================== */
/*  VM-Exit 分发器 (Phase 4)                                          */
/*                                                                    */
/*  分发优先级: EPT VIOLATION → CPUID → CR ACCESS → MSR R/W →        */
/*  RDTSC/P → MOV DR → NMI → VMCALL → INVD → XSETBV → VMX指令       */
/* ================================================================== */

/* ------------------------------------------------------------------ */
/*  辅助：推进 Guest RIP 跳过当前指令                                 */
/* ------------------------------------------------------------------ */

static VOID
VmAdvanceRip(VOID)
{
    ULONG64 len = AsmVmRead(VMCS_EXIT_INSTR_LEN);
    ULONG64 rip = AsmVmRead(VMCS_GUEST_RIP);
    AsmVmWrite(VMCS_GUEST_RIP, rip + len);

    /* 清除 STI / MOV SS 阻塞标志 */
    ULONG64 interruptibility = AsmVmRead(VMCS_GUEST_INTERRUPTIBILITY);
    if (interruptibility & 3)
        AsmVmWrite(VMCS_GUEST_INTERRUPTIBILITY, interruptibility & ~3ULL);
}

/* ------------------------------------------------------------------ */
/*  辅助：按 Exit Qualification 中 GPR 编号获取寄存器指针             */
/*  编号: 0=RAX 1=RCX 2=RDX 3=RBX 4=RSP 5=RBP 6=RSI 7=RDI 8-15=R8+ */
/* ------------------------------------------------------------------ */

static PULONG64
VmGetGprPtr(PGUEST_CONTEXT Ctx, ULONG Index)
{
    switch (Index) {
    case 0:  return &Ctx->Rax;
    case 1:  return &Ctx->Rcx;
    case 2:  return &Ctx->Rdx;
    case 3:  return &Ctx->Rbx;
    case 4:  return NULL;        /* RSP → 通过 VMCS_GUEST_RSP 访问 */
    case 5:  return &Ctx->Rbp;
    case 6:  return &Ctx->Rsi;
    case 7:  return &Ctx->Rdi;
    case 8:  return &Ctx->R8;
    case 9:  return &Ctx->R9;
    case 10: return &Ctx->R10;
    case 11: return &Ctx->R11;
    case 12: return &Ctx->R12;
    case 13: return &Ctx->R13;
    case 14: return &Ctx->R14;
    case 15: return &Ctx->R15;
    default: return &Ctx->Rax;
    }
}

/* ------------------------------------------------------------------ */
/*  辅助：注入事件到 Guest (VM-Entry Interruption-Information)        */
/*                                                                    */
/*  Type: 0=External 2=NMI 3=HW Exception 4=SW Interrupt 6=SW Exc    */
/* ------------------------------------------------------------------ */

#define INTR_TYPE_EXTERNAL      0
#define INTR_TYPE_NMI           2
#define INTR_TYPE_HW_EXCEPTION  3
#define INTR_TYPE_SW_INTERRUPT  4
#define INTR_TYPE_SW_EXCEPTION  6

static VOID
VmInjectEvent(ULONG Vector, ULONG Type, BOOLEAN HasErrorCode, ULONG ErrorCode)
{
    ULONG info = Vector | (Type << 8) | (1UL << 31);
    if (HasErrorCode) {
        info |= (1UL << 11);
        AsmVmWrite(VMCS_CTRL_ENTRY_EXCEPTION_EC, ErrorCode);
    }
    AsmVmWrite(VMCS_CTRL_ENTRY_INTR_INFO, info);

    if (Type == INTR_TYPE_SW_INTERRUPT || Type == INTR_TYPE_SW_EXCEPTION)
        AsmVmWrite(VMCS_CTRL_ENTRY_INSTR_LEN, AsmVmRead(VMCS_EXIT_INSTR_LEN));
}

/* ================================================================== */
/*  各 Exit Reason 处理函数                                           */
/* ================================================================== */

/* ------------------------------------------------------------------ */
/*  CPUID (Reason 10) — 隐藏 VMX 与 Hypervisor 存在                  */
/* ------------------------------------------------------------------ */

static VOID
VmHandleCpuid(PGUEST_CONTEXT Ctx)
{
    int info[4];
    int leaf    = (int)Ctx->Rax;
    int subleaf = (int)Ctx->Rcx;

    __cpuidex(info, leaf, subleaf);

    switch (leaf) {
    case 1:
        /* 清除 VMX (bit 5) 和 Hypervisor Present (bit 31) */
        info[2] &= ~((1 << 5) | (1 << 31));
        break;

    case 0x40000000:
    case 0x40000001:
    case 0x40000002:
    case 0x40000003:
    case 0x40000004:
    case 0x40000005:
    case 0x40000006:
        /* 清空 Hypervisor 标识 — 让 Guest 看不到任何 HV 签名 */
        info[0] = info[1] = info[2] = info[3] = 0;
        break;
    }

    Ctx->Rax = (ULONG64)(ULONG)info[0];
    Ctx->Rbx = (ULONG64)(ULONG)info[1];
    Ctx->Rcx = (ULONG64)(ULONG)info[2];
    Ctx->Rdx = (ULONG64)(ULONG)info[3];

    VmAdvanceRip();
}

/* ------------------------------------------------------------------ */
/*  CR Access (Reason 28) — CR0/3/4 读写 + CLTS/LMSW                 */
/*                                                                    */
/*  Exit Qualification:                                               */
/*  3:0  = CR 编号    5:4 = 类型(0=MOVtoCR 1=MOVfromCR 2=CLTS 3=LMSW)*/
/*  11:8 = GPR 编号   31:16 = LMSW 源数据                            */
/* ------------------------------------------------------------------ */

static VOID
VmHandleCrAccess(PGUEST_CONTEXT Ctx)
{
    ULONG64 qual = AsmVmRead(VMCS_EXIT_QUALIFICATION);

    ULONG crNum  = (ULONG)(qual & 0xF);
    ULONG type   = (ULONG)((qual >> 4) & 3);
    ULONG gprIdx = (ULONG)((qual >> 8) & 0xF);

    PULONG64 gprPtr = VmGetGprPtr(Ctx, gprIdx);
    ULONG64  gprVal = gprPtr ? *gprPtr : AsmVmRead(VMCS_GUEST_RSP);

    switch (type) {
    case 0:  /* MOV to CR */
        switch (crNum) {
        case 0: {
            /* CR0 写入: 满足 FIXED 约束后更新 Guest + 影子 */
            ULONG64 cr0 = gprVal;
            cr0 |= AsmReadMsr(IA32_VMX_CR0_FIXED0);
            cr0 &= AsmReadMsr(IA32_VMX_CR0_FIXED1);
            AsmVmWrite(VMCS_GUEST_CR0, cr0);
            AsmVmWrite(VMCS_CTRL_CR0_SHADOW, gprVal);
            break;
        }
        case 3:
            /* CR3 加载: 更新 Guest CR3 + INVVPID 刷 TLB */
            AsmVmWrite(VMCS_GUEST_CR3, gprVal);
            {
                INVVPID_DESC desc = { 1, 0 };
                AsmInvvpid(INVVPID_SINGLE_CONTEXT, &desc);
            }
            break;
        case 4: {
            /* CR4 写入: 满足 FIXED + 影子隐藏 VMXE */
            ULONG64 cr4 = gprVal;
            cr4 |= AsmReadMsr(IA32_VMX_CR4_FIXED0);
            cr4 &= AsmReadMsr(IA32_VMX_CR4_FIXED1);
            AsmVmWrite(VMCS_GUEST_CR4, cr4);
            AsmVmWrite(VMCS_CTRL_CR4_SHADOW, gprVal & ~(1ULL << 13));
            break;
        }
        }
        break;

    case 1:  /* MOV from CR */
    {
        ULONG64 val = 0;
        switch (crNum) {
        case 0: val = AsmVmRead(VMCS_CTRL_CR0_SHADOW); break;
        case 3: val = AsmVmRead(VMCS_GUEST_CR3);       break;
        case 4: val = AsmVmRead(VMCS_CTRL_CR4_SHADOW); break;
        }
        if (gprPtr) *gprPtr = val;
        else        AsmVmWrite(VMCS_GUEST_RSP, val);
        break;
    }

    case 2:  /* CLTS — 清除 CR0.TS */
        AsmVmWrite(VMCS_GUEST_CR0,
                   AsmVmRead(VMCS_GUEST_CR0) & ~(1ULL << 3));
        AsmVmWrite(VMCS_CTRL_CR0_SHADOW,
                   AsmVmRead(VMCS_CTRL_CR0_SHADOW) & ~(1ULL << 3));
        break;

    case 3:  /* LMSW — 加载 CR0 低 16 位 */
    {
        ULONG64 data = (qual >> 16) & 0xFFFF;
        ULONG64 cr0  = AsmVmRead(VMCS_GUEST_CR0);
        /* LMSW 只能设置 PE/MP/EM/TS (低 4 位), 不能清除 PE */
        cr0 = (cr0 & ~0xFULL) | (data & 0xF) | (cr0 & 1);
        cr0 |= AsmReadMsr(IA32_VMX_CR0_FIXED0);
        cr0 &= AsmReadMsr(IA32_VMX_CR0_FIXED1);
        AsmVmWrite(VMCS_GUEST_CR0, cr0);
        break;
    }
    }

    VmAdvanceRip();
}

/* ------------------------------------------------------------------ */
/*  MSR Read (Reason 31) — RDMSR 拦截                                */
/* ------------------------------------------------------------------ */

static VOID
VmHandleMsrRead(PGUEST_CONTEXT Ctx)
{
    ULONG32 idx = (ULONG32)Ctx->Rcx;
    ULONG64 val = 0;

    switch (idx) {
    case IA32_FEATURE_CONTROL:
        /* 隐藏 VMX: 清除 VMX 启用位 */
        val = AsmReadMsr(IA32_FEATURE_CONTROL);
        val &= ~(FEATURE_CONTROL_VMXON_OUTSIDE | (1ULL << 1));
        break;

    /* IA32_VMX_* 系列: 注入 #GP(0) — 让 Guest 认为 VMX MSR 不存在 */
    case IA32_VMX_BASIC:
    case IA32_VMX_PINBASED_CTLS:
    case IA32_VMX_PROCBASED_CTLS:
    case IA32_VMX_EXIT_CTLS:
    case IA32_VMX_ENTRY_CTLS:
    case IA32_VMX_MISC:
    case IA32_VMX_CR0_FIXED0:
    case IA32_VMX_CR0_FIXED1:
    case IA32_VMX_CR4_FIXED0:
    case IA32_VMX_CR4_FIXED1:
    case IA32_VMX_PROCBASED_CTLS2:
    case IA32_VMX_EPT_VPID_CAP:
    case IA32_VMX_TRUE_PINBASED_CTLS:
    case IA32_VMX_TRUE_PROCBASED_CTLS:
    case IA32_VMX_TRUE_EXIT_CTLS:
    case IA32_VMX_TRUE_ENTRY_CTLS:
        VmInjectEvent(13, INTR_TYPE_HW_EXCEPTION, TRUE, 0);
        return;  /* 不推进 RIP — 异常从当前指令重试 */

    default:
        val = AsmReadMsr(idx);
        break;
    }

    Ctx->Rax = val & 0xFFFFFFFF;
    Ctx->Rdx = val >> 32;
    VmAdvanceRip();
}

/* ------------------------------------------------------------------ */
/*  MSR Write (Reason 32) — WRMSR 拦截                               */
/* ------------------------------------------------------------------ */

static VOID
VmHandleMsrWrite(PGUEST_CONTEXT Ctx)
{
    ULONG32 idx = (ULONG32)Ctx->Rcx;
    ULONG64 val = (Ctx->Rax & 0xFFFFFFFF) | (Ctx->Rdx << 32);

    switch (idx) {
    case IA32_FEATURE_CONTROL:
        /* 静默丢弃 — 不允许 Guest 修改 VMX 控制 */
        break;

    case IA32_VMX_BASIC:
    case IA32_VMX_PINBASED_CTLS:
    case IA32_VMX_PROCBASED_CTLS:
    case IA32_VMX_EXIT_CTLS:
    case IA32_VMX_ENTRY_CTLS:
    case IA32_VMX_MISC:
    case IA32_VMX_CR0_FIXED0:
    case IA32_VMX_CR0_FIXED1:
    case IA32_VMX_CR4_FIXED0:
    case IA32_VMX_CR4_FIXED1:
    case IA32_VMX_PROCBASED_CTLS2:
    case IA32_VMX_EPT_VPID_CAP:
    case IA32_VMX_TRUE_PINBASED_CTLS:
    case IA32_VMX_TRUE_PROCBASED_CTLS:
    case IA32_VMX_TRUE_EXIT_CTLS:
    case IA32_VMX_TRUE_ENTRY_CTLS:
        VmInjectEvent(13, INTR_TYPE_HW_EXCEPTION, TRUE, 0);
        return;

    default:
        AsmWriteMsr(idx, val);
        break;
    }

    VmAdvanceRip();
}

/* ------------------------------------------------------------------ */
/*  RDTSC (Reason 16) — 加上 TSC Offset 保持时间一致                 */
/* ------------------------------------------------------------------ */

static VOID
VmHandleRdtsc(PGUEST_CONTEXT Ctx)
{
    ULONG64 tsc = __rdtsc();
    tsc += (ULONG64)AsmVmRead(VMCS_CTRL_TSC_OFFSET);

    Ctx->Rax = tsc & 0xFFFFFFFF;
    Ctx->Rdx = tsc >> 32;
    VmAdvanceRip();
}

/* ------------------------------------------------------------------ */
/*  RDTSCP (Reason 51) — TSC + TSC_AUX                               */
/* ------------------------------------------------------------------ */

static VOID
VmHandleRdtscp(PGUEST_CONTEXT Ctx)
{
    unsigned int aux;
    ULONG64 tsc = __rdtscp(&aux);
    tsc += (ULONG64)AsmVmRead(VMCS_CTRL_TSC_OFFSET);

    Ctx->Rax = tsc & 0xFFFFFFFF;
    Ctx->Rdx = tsc >> 32;
    Ctx->Rcx = aux;
    VmAdvanceRip();
}

/* ------------------------------------------------------------------ */
/*  MOV DR (Reason 29) — 调试寄存器访问                              */
/*                                                                    */
/*  Exit Qualification: 2:0=DR编号 4=方向(0=写DR 1=读DR) 11:8=GPR    */
/* ------------------------------------------------------------------ */

static VOID
VmHandleMovDr(PGUEST_CONTEXT Ctx)
{
    ULONG64 qual = AsmVmRead(VMCS_EXIT_QUALIFICATION);

    ULONG drNum  = (ULONG)(qual & 7);
    ULONG dir    = (ULONG)((qual >> 4) & 1);
    ULONG gprIdx = (ULONG)((qual >> 8) & 0xF);

    PULONG64 gprPtr = VmGetGprPtr(Ctx, gprIdx);
    if (!gprPtr) {
        VmAdvanceRip();
        return;
    }

    if (dir == 0) {
        /* MOV to DR */
        switch (drNum) {
        case 0: __writedr(0, (unsigned __int64)*gprPtr); break;
        case 1: __writedr(1, (unsigned __int64)*gprPtr); break;
        case 2: __writedr(2, (unsigned __int64)*gprPtr); break;
        case 3: __writedr(3, (unsigned __int64)*gprPtr); break;
        case 6: __writedr(6, (unsigned __int64)*gprPtr); break;
        case 7: AsmVmWrite(VMCS_GUEST_DR7, *gprPtr);    break;
        }
    } else {
        /* MOV from DR */
        switch (drNum) {
        case 0: *gprPtr = __readdr(0); break;
        case 1: *gprPtr = __readdr(1); break;
        case 2: *gprPtr = __readdr(2); break;
        case 3: *gprPtr = __readdr(3); break;
        case 6: *gprPtr = __readdr(6); break;
        case 7: *gprPtr = AsmVmRead(VMCS_GUEST_DR7); break;
        }
    }

    VmAdvanceRip();
}

/* ------------------------------------------------------------------ */
/*  Exception / NMI (Reason 0) — 重注入到 Guest                      */
/* ------------------------------------------------------------------ */

static VOID
VmHandleExceptionNmi(VOID)
{
    ULONG64 intrInfo = AsmVmRead(VMCS_EXIT_INTR_INFO);
    ULONG vector = (ULONG)(intrInfo & 0xFF);
    ULONG type   = (ULONG)((intrInfo >> 8) & 7);

    if (type == INTR_TYPE_NMI && vector == 2) {
        /* NMI: 直接重注入 */
        VmInjectEvent(2, INTR_TYPE_NMI, FALSE, 0);
    } else {
        /* 硬件异常: 带错误码重注入 */
        BOOLEAN hasEc = (BOOLEAN)((intrInfo >> 11) & 1);
        ULONG ec = hasEc ? (ULONG)AsmVmRead(VMCS_EXIT_INTR_ERROR_CODE) : 0;
        VmInjectEvent(vector, type, hasEc, ec);
    }
}

/* ------------------------------------------------------------------ */
/*  VMCALL (Reason 18) — Hypercall 接口                              */
/*  返回 TRUE = 退出 VMX                                              */
/* ------------------------------------------------------------------ */

#define VMCALL_VMX_SHUTDOWN     0xDEAD
/* Phase 6 预留:
   #define VMCALL_EPT_HOOK      0x0001
   #define VMCALL_EPT_UNHOOK    0x0002 */

static BOOLEAN
VmHandleVmcall(PGUEST_CONTEXT Ctx)
{
    ULONG64 num = Ctx->Rcx;

    switch (num) {
    case VMCALL_VMX_SHUTDOWN:
        VmAdvanceRip();
        return TRUE;

    default:
        Ctx->Rax = (ULONG64)STATUS_INVALID_PARAMETER;
        break;
    }

    VmAdvanceRip();
    return FALSE;
}

/* ------------------------------------------------------------------ */
/*  EPT Violation (Reason 48) — Phase 6 实现完整 Hook 分发            */
/*                                                                    */
/*  Exit Qualification: 0=Read 1=Write 2=Fetch 3=Readable 4=Writable */
/*                      5=Executable 7=GLA valid 8=GPA-caused         */
/* ------------------------------------------------------------------ */

static VOID
VmHandleEptViolation(VOID)
{
    ULONG64 qual = AsmVmRead(VMCS_EXIT_QUALIFICATION);
    ULONG64 gpa  = AsmVmRead(VMCS_GUEST_PHYSICAL_ADDR);

    UNREFERENCED_PARAMETER(qual);

    HvLog(HV_LOG_DEBUG, "EPT Violation: GPA=0x%llX qual=0x%llX", gpa, qual);

    /* Phase 6: EptHandleViolation(gpa, qual) 在此处接管
       当前阶段: 不推进 RIP (EPT violation 由硬件重试) */
}

/* ------------------------------------------------------------------ */
/*  EPT Misconfiguration (Reason 49) — 不可恢复错误                  */
/* ------------------------------------------------------------------ */

static VOID
VmHandleEptMisconfig(VOID)
{
    ULONG64 gpa = AsmVmRead(VMCS_GUEST_PHYSICAL_ADDR);
    HvLog(HV_LOG_ERROR, "EPT Misconfiguration: GPA=0x%llX", gpa);
    KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0xDEAD0004, gpa, 0, 0);
}

/* ------------------------------------------------------------------ */
/*  INVD (Reason 13) — 替换为安全的 WBINVD                           */
/* ------------------------------------------------------------------ */

static VOID
VmHandleInvd(VOID)
{
    __wbinvd();
    VmAdvanceRip();
}

/* ------------------------------------------------------------------ */
/*  XSETBV (Reason 55) — 透传 XCR 写入                               */
/* ------------------------------------------------------------------ */

static VOID
VmHandleXsetbv(PGUEST_CONTEXT Ctx)
{
    _xsetbv((ULONG32)Ctx->Rcx,
            (Ctx->Rax & 0xFFFFFFFF) | (Ctx->Rdx << 32));
    VmAdvanceRip();
}

/* ------------------------------------------------------------------ */
/*  VMX 嵌套指令 (Reason 19-27) — 不支持, 注入 #UD                   */
/* ------------------------------------------------------------------ */

static VOID
VmHandleVmxInstruction(VOID)
{
    VmInjectEvent(6, INTR_TYPE_HW_EXCEPTION, FALSE, 0);
}

/* ------------------------------------------------------------------ */
/*  Triple Fault (Reason 2) — 不可恢复                               */
/* ------------------------------------------------------------------ */

static VOID
VmHandleTripleFault(VOID)
{
    HvLog(HV_LOG_ERROR, "Triple Fault — 不可恢复");
    KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0xDEAD0002, 0, 0, 0);
}

/* ================================================================== */
/*  主分发函数                                                        */
/*  返回 FALSE → vmresume, TRUE → 退出 VMX                           */
/* ================================================================== */

BOOLEAN
VmExitDispatch(PGUEST_CONTEXT GuestCtx)
{
    ULONG reason = (ULONG)(AsmVmRead(VMCS_EXIT_REASON) & 0xFFFF);

    switch (reason) {

    /* --- 高频路径在前 --- */

    case EXIT_REASON_EPT_VIOLATION:
        VmHandleEptViolation();
        break;

    case EXIT_REASON_CPUID:
        VmHandleCpuid(GuestCtx);
        break;

    case EXIT_REASON_CR_ACCESS:
        VmHandleCrAccess(GuestCtx);
        break;

    case EXIT_REASON_MSR_READ:
        VmHandleMsrRead(GuestCtx);
        break;

    case EXIT_REASON_MSR_WRITE:
        VmHandleMsrWrite(GuestCtx);
        break;

    case EXIT_REASON_RDTSC:
        VmHandleRdtsc(GuestCtx);
        break;

    case EXIT_REASON_RDTSCP:
        VmHandleRdtscp(GuestCtx);
        break;

    case EXIT_REASON_MOV_DR:
        VmHandleMovDr(GuestCtx);
        break;

    case EXIT_REASON_VMCALL:
        return VmHandleVmcall(GuestCtx);

    case EXIT_REASON_EXCEPTION_NMI:
        VmHandleExceptionNmi();
        break;

    /* --- 低频路径 --- */

    case EXIT_REASON_INVD:
        VmHandleInvd();
        break;

    case EXIT_REASON_XSETBV:
        VmHandleXsetbv(GuestCtx);
        break;

    case EXIT_REASON_TRIPLE_FAULT:
        VmHandleTripleFault();
        break;

    case EXIT_REASON_EPT_MISCONFIG:
        VmHandleEptMisconfig();
        break;

    /* VMX 嵌套指令 → #UD */
    case EXIT_REASON_VMCLEAR:
    case EXIT_REASON_VMLAUNCH:
    case EXIT_REASON_VMPTRLD:
    case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:
    case EXIT_REASON_VMRESUME:
    case EXIT_REASON_VMWRITE:
    case EXIT_REASON_VMXOFF:
    case EXIT_REASON_VMXON:
        VmHandleVmxInstruction();
        break;

    default:
        HvLog(HV_LOG_WARN, "未处理 VM-Exit: reason=%lu", reason);
        VmAdvanceRip();
        break;
    }

    return FALSE;
}
