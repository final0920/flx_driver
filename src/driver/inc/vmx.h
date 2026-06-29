#pragma once

#include <ntddk.h>

/* ================================================================== */
/*  VMX 常量定义 (Intel SDM Volume 3, Appendix B)                     */
/* ================================================================== */

/* ------------------------------------------------------------------ */
/*  IA32 MSR 索引                                                     */
/* ------------------------------------------------------------------ */

#define IA32_FEATURE_CONTROL            0x003A
#define IA32_DEBUGCTL                   0x01D9
#define IA32_PAT                        0x0277

#define IA32_VMX_BASIC                  0x0480
#define IA32_VMX_PINBASED_CTLS          0x0481
#define IA32_VMX_PROCBASED_CTLS         0x0482
#define IA32_VMX_EXIT_CTLS              0x0483
#define IA32_VMX_ENTRY_CTLS             0x0484
#define IA32_VMX_MISC                   0x0485
#define IA32_VMX_CR0_FIXED0             0x0486
#define IA32_VMX_CR0_FIXED1             0x0487
#define IA32_VMX_CR4_FIXED0             0x0488
#define IA32_VMX_CR4_FIXED1             0x0489
#define IA32_VMX_PROCBASED_CTLS2        0x048B
#define IA32_VMX_EPT_VPID_CAP           0x048C
#define IA32_VMX_TRUE_PINBASED_CTLS     0x048D
#define IA32_VMX_TRUE_PROCBASED_CTLS    0x048E
#define IA32_VMX_TRUE_EXIT_CTLS         0x048F
#define IA32_VMX_TRUE_ENTRY_CTLS        0x0490

#define IA32_SYSENTER_CS                0x0174
#define IA32_SYSENTER_ESP               0x0175
#define IA32_SYSENTER_EIP               0x0176
#define IA32_EFER                       0xC0000080
#define IA32_FS_BASE                    0xC0000100
#define IA32_GS_BASE                    0xC0000101
#define IA32_KERNEL_GS_BASE             0xC0000102

/* IA32_FEATURE_CONTROL 位 */
#define FEATURE_CONTROL_LOCK            (1ULL << 0)
#define FEATURE_CONTROL_VMXON_OUTSIDE   (1ULL << 2)

/* ------------------------------------------------------------------ */
/*  VMCS 字段编码                                                     */
/* ------------------------------------------------------------------ */

/* --- 16-bit Guest State --- */
#define VMCS_GUEST_ES_SEL               0x0800
#define VMCS_GUEST_CS_SEL               0x0802
#define VMCS_GUEST_SS_SEL               0x0804
#define VMCS_GUEST_DS_SEL               0x0806
#define VMCS_GUEST_FS_SEL               0x0808
#define VMCS_GUEST_GS_SEL               0x080A
#define VMCS_GUEST_LDTR_SEL             0x080C
#define VMCS_GUEST_TR_SEL               0x080E
#define VMCS_GUEST_INTR_STATUS          0x0810
#define VMCS_GUEST_PML_INDEX            0x0812

/* --- 16-bit Host State --- */
#define VMCS_HOST_ES_SEL                0x0C00
#define VMCS_HOST_CS_SEL                0x0C02
#define VMCS_HOST_SS_SEL                0x0C04
#define VMCS_HOST_DS_SEL                0x0C06
#define VMCS_HOST_FS_SEL                0x0C08
#define VMCS_HOST_GS_SEL                0x0C0A
#define VMCS_HOST_TR_SEL                0x0C0C

/* --- 16-bit Control --- */
#define VMCS_CTRL_VPID                  0x0000

/* --- 64-bit Control --- */
#define VMCS_CTRL_IO_BITMAP_A           0x2000
#define VMCS_CTRL_IO_BITMAP_B           0x2002
#define VMCS_CTRL_MSR_BITMAP            0x2004
#define VMCS_CTRL_EXIT_MSR_STORE        0x2006
#define VMCS_CTRL_EXIT_MSR_LOAD         0x2008
#define VMCS_CTRL_ENTRY_MSR_LOAD        0x200A
#define VMCS_CTRL_EXEC_VMCS_PTR         0x200C
#define VMCS_CTRL_TSC_OFFSET            0x2010
#define VMCS_CTRL_EPT_POINTER           0x201A

/* --- 64-bit Read-only --- */
#define VMCS_GUEST_PHYSICAL_ADDR        0x2400

/* --- 64-bit Guest State --- */
#define VMCS_GUEST_VMCS_LINK            0x2800
#define VMCS_GUEST_DEBUGCTL             0x2802
#define VMCS_GUEST_PAT                  0x2804
#define VMCS_GUEST_EFER                 0x2806

/* --- 64-bit Host State --- */
#define VMCS_HOST_PAT                   0x2C00
#define VMCS_HOST_EFER                  0x2C02

/* --- 32-bit Control --- */
#define VMCS_CTRL_PIN_BASED             0x4000
#define VMCS_CTRL_PRIMARY_PROC          0x4002
#define VMCS_CTRL_EXCEPTION_BITMAP      0x4004
#define VMCS_CTRL_PF_ERROR_MASK         0x4006
#define VMCS_CTRL_PF_ERROR_MATCH        0x4008
#define VMCS_CTRL_CR3_TARGET_COUNT      0x400A
#define VMCS_CTRL_EXIT                  0x400C
#define VMCS_CTRL_EXIT_MSR_STORE_COUNT  0x400E
#define VMCS_CTRL_EXIT_MSR_LOAD_COUNT   0x4010
#define VMCS_CTRL_ENTRY                 0x4012
#define VMCS_CTRL_ENTRY_MSR_LOAD_COUNT  0x4014
#define VMCS_CTRL_ENTRY_INTR_INFO       0x4016
#define VMCS_CTRL_ENTRY_EXCEPTION_EC    0x4018
#define VMCS_CTRL_ENTRY_INSTR_LEN       0x401A
#define VMCS_CTRL_SECONDARY_PROC        0x401E

/* --- 32-bit Read-only --- */
#define VMCS_VM_INSTRUCTION_ERROR       0x4400
#define VMCS_EXIT_REASON                0x4402
#define VMCS_EXIT_INTR_INFO             0x4404
#define VMCS_EXIT_INTR_ERROR_CODE       0x4406
#define VMCS_IDT_VECTORING_INFO         0x4408
#define VMCS_IDT_VECTORING_ERROR_CODE   0x440A
#define VMCS_EXIT_INSTR_LEN             0x440C
#define VMCS_EXIT_INSTR_INFO            0x440E

/* --- 32-bit Guest State --- */
#define VMCS_GUEST_ES_LIMIT             0x4800
#define VMCS_GUEST_CS_LIMIT             0x4802
#define VMCS_GUEST_SS_LIMIT             0x4804
#define VMCS_GUEST_DS_LIMIT             0x4806
#define VMCS_GUEST_FS_LIMIT             0x4808
#define VMCS_GUEST_GS_LIMIT             0x480A
#define VMCS_GUEST_LDTR_LIMIT           0x480C
#define VMCS_GUEST_TR_LIMIT             0x480E
#define VMCS_GUEST_GDTR_LIMIT           0x4810
#define VMCS_GUEST_IDTR_LIMIT           0x4812
#define VMCS_GUEST_ES_AR                0x4814
#define VMCS_GUEST_CS_AR                0x4816
#define VMCS_GUEST_SS_AR                0x4818
#define VMCS_GUEST_DS_AR                0x481A
#define VMCS_GUEST_FS_AR                0x481C
#define VMCS_GUEST_GS_AR               0x481E
#define VMCS_GUEST_LDTR_AR              0x4820
#define VMCS_GUEST_TR_AR                0x4822
#define VMCS_GUEST_INTERRUPTIBILITY     0x4824
#define VMCS_GUEST_ACTIVITY             0x4826
#define VMCS_GUEST_SMBASE               0x4828
#define VMCS_GUEST_SYSENTER_CS          0x482A

/* --- 32-bit Host State --- */
#define VMCS_HOST_SYSENTER_CS           0x4C00

/* --- Natural-width Control --- */
#define VMCS_CTRL_CR0_MASK              0x6000
#define VMCS_CTRL_CR4_MASK              0x6002
#define VMCS_CTRL_CR0_SHADOW            0x6004
#define VMCS_CTRL_CR4_SHADOW            0x6006

/* --- Natural-width Read-only --- */
#define VMCS_EXIT_QUALIFICATION         0x6400
#define VMCS_IO_RCX                     0x6402
#define VMCS_IO_RSI                     0x6404
#define VMCS_IO_RDI                     0x6406
#define VMCS_IO_RIP                     0x6408
#define VMCS_GUEST_LINEAR_ADDR          0x640A

/* --- Natural-width Guest State --- */
#define VMCS_GUEST_CR0                  0x6800
#define VMCS_GUEST_CR3                  0x6802
#define VMCS_GUEST_CR4                  0x6804
#define VMCS_GUEST_ES_BASE              0x6806
#define VMCS_GUEST_CS_BASE              0x6808
#define VMCS_GUEST_SS_BASE              0x680A
#define VMCS_GUEST_DS_BASE              0x680C
#define VMCS_GUEST_FS_BASE              0x680E
#define VMCS_GUEST_GS_BASE              0x6810
#define VMCS_GUEST_LDTR_BASE            0x6812
#define VMCS_GUEST_TR_BASE              0x6814
#define VMCS_GUEST_GDTR_BASE            0x6816
#define VMCS_GUEST_IDTR_BASE            0x6818
#define VMCS_GUEST_DR7                  0x681A
#define VMCS_GUEST_RSP                  0x681C
#define VMCS_GUEST_RIP                  0x681E
#define VMCS_GUEST_RFLAGS               0x6820
#define VMCS_GUEST_PENDING_DBG          0x6822
#define VMCS_GUEST_SYSENTER_ESP         0x6824
#define VMCS_GUEST_SYSENTER_EIP         0x6826

/* --- Natural-width Host State --- */
#define VMCS_HOST_CR0                   0x6C00
#define VMCS_HOST_CR3                   0x6C02
#define VMCS_HOST_CR4                   0x6C04
#define VMCS_HOST_FS_BASE               0x6C06
#define VMCS_HOST_GS_BASE               0x6C08
#define VMCS_HOST_TR_BASE               0x6C0A
#define VMCS_HOST_GDTR_BASE             0x6C0C
#define VMCS_HOST_IDTR_BASE             0x6C0E
#define VMCS_HOST_SYSENTER_ESP          0x6C10
#define VMCS_HOST_SYSENTER_EIP          0x6C12
#define VMCS_HOST_RSP                   0x6C14
#define VMCS_HOST_RIP                   0x6C16

/* ------------------------------------------------------------------ */
/*  VM-Exit 原因编号                                                  */
/* ------------------------------------------------------------------ */

#define EXIT_REASON_EXCEPTION_NMI       0
#define EXIT_REASON_EXTERNAL_INTERRUPT  1
#define EXIT_REASON_TRIPLE_FAULT        2
#define EXIT_REASON_INIT                3
#define EXIT_REASON_SIPI                4
#define EXIT_REASON_IO_SMI              5
#define EXIT_REASON_OTHER_SMI           6
#define EXIT_REASON_INTERRUPT_WINDOW    7
#define EXIT_REASON_NMI_WINDOW          8
#define EXIT_REASON_TASK_SWITCH         9
#define EXIT_REASON_CPUID               10
#define EXIT_REASON_GETSEC              11
#define EXIT_REASON_HLT                 12
#define EXIT_REASON_INVD                13
#define EXIT_REASON_INVLPG              14
#define EXIT_REASON_RDPMC               15
#define EXIT_REASON_RDTSC               16
#define EXIT_REASON_RSM                 17
#define EXIT_REASON_VMCALL              18
#define EXIT_REASON_VMCLEAR             19
#define EXIT_REASON_VMLAUNCH            20
#define EXIT_REASON_VMPTRLD             21
#define EXIT_REASON_VMPTRST             22
#define EXIT_REASON_VMREAD              23
#define EXIT_REASON_VMRESUME            24
#define EXIT_REASON_VMWRITE             25
#define EXIT_REASON_VMXOFF              26
#define EXIT_REASON_VMXON               27
#define EXIT_REASON_CR_ACCESS           28
#define EXIT_REASON_MOV_DR              29
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32
#define EXIT_REASON_INVALID_GUEST       33
#define EXIT_REASON_MSR_LOADING         34
#define EXIT_REASON_MWAIT               36
#define EXIT_REASON_MTF                 37
#define EXIT_REASON_MONITOR             39
#define EXIT_REASON_PAUSE               40
#define EXIT_REASON_MACHINE_CHECK       41
#define EXIT_REASON_TPR_BELOW           43
#define EXIT_REASON_APIC_ACCESS         44
#define EXIT_REASON_GDTR_IDTR           46
#define EXIT_REASON_LDTR_TR             47
#define EXIT_REASON_EPT_VIOLATION       48
#define EXIT_REASON_EPT_MISCONFIG       49
#define EXIT_REASON_INVEPT              50
#define EXIT_REASON_RDTSCP              51
#define EXIT_REASON_PREEMPT_TIMER       52
#define EXIT_REASON_INVVPID             53
#define EXIT_REASON_WBINVD              54
#define EXIT_REASON_XSETBV              55

/* ------------------------------------------------------------------ */
/*  Pin-based / Primary / Secondary / Exit / Entry 控制位              */
/* ------------------------------------------------------------------ */

/* Pin-based */
#define PIN_EXTERNAL_INTERRUPT          (1UL << 0)
#define PIN_NMI_EXITING                 (1UL << 3)
#define PIN_VIRTUAL_NMI                 (1UL << 5)
#define PIN_PREEMPT_TIMER               (1UL << 6)

/* Primary Processor-based */
#define PRI_INTERRUPT_WINDOW            (1UL << 2)
#define PRI_USE_TSC_OFFSETTING          (1UL << 3)
#define PRI_HLT_EXITING                 (1UL << 7)
#define PRI_INVLPG_EXITING              (1UL << 9)
#define PRI_MWAIT_EXITING               (1UL << 10)
#define PRI_RDPMC_EXITING               (1UL << 11)
#define PRI_RDTSC_EXITING               (1UL << 12)
#define PRI_CR3_LOAD_EXITING            (1UL << 15)
#define PRI_CR3_STORE_EXITING           (1UL << 16)
#define PRI_CR8_LOAD_EXITING            (1UL << 19)
#define PRI_CR8_STORE_EXITING           (1UL << 20)
#define PRI_USE_TPR_SHADOW              (1UL << 21)
#define PRI_NMI_WINDOW_EXITING          (1UL << 22)
#define PRI_MOV_DR_EXITING              (1UL << 23)
#define PRI_UNCONDITIONAL_IO            (1UL << 24)
#define PRI_USE_IO_BITMAPS              (1UL << 25)
#define PRI_MONITOR_TRAP_FLAG           (1UL << 27)
#define PRI_USE_MSR_BITMAPS             (1UL << 28)
#define PRI_MONITOR_EXITING             (1UL << 29)
#define PRI_PAUSE_EXITING               (1UL << 30)
#define PRI_SECONDARY_CONTROLS          (1UL << 31)

/* Secondary Processor-based */
#define SEC_ENABLE_EPT                  (1UL << 1)
#define SEC_RDTSCP                      (1UL << 3)
#define SEC_ENABLE_VPID                 (1UL << 5)
#define SEC_WBINVD_EXITING              (1UL << 6)
#define SEC_UNRESTRICTED_GUEST          (1UL << 7)
#define SEC_ENABLE_INVPCID              (1UL << 12)
#define SEC_ENABLE_XSAVES              (1UL << 20)

/* VM-Exit Controls */
#define EXIT_SAVE_DBG_CONTROLS          (1UL << 2)
#define EXIT_HOST_ADDR_SPACE_SIZE       (1UL << 9)
#define EXIT_LOAD_IA32_PAT              (1UL << 19)
#define EXIT_SAVE_IA32_PAT              (1UL << 18)
#define EXIT_SAVE_IA32_EFER             (1UL << 20)
#define EXIT_LOAD_IA32_EFER             (1UL << 21)

/* VM-Entry Controls */
#define ENTRY_LOAD_DBG_CONTROLS         (1UL << 2)
#define ENTRY_IA32E_MODE_GUEST          (1UL << 9)
#define ENTRY_LOAD_IA32_PAT             (1UL << 14)
#define ENTRY_LOAD_IA32_EFER            (1UL << 15)

/* ------------------------------------------------------------------ */
/*  描述符表/段选择子结构                                             */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)

typedef struct _SEGMENT_DESCRIPTOR {
    USHORT LimitLow;
    USHORT BaseLow;
    UCHAR  BaseMiddle;
    UCHAR  AccessByte;
    UCHAR  Granularity;
    UCHAR  BaseHigh;
} SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;

typedef struct _DESC_TABLE_REG {
    USHORT  Limit;
    ULONG64 Base;
} DESC_TABLE_REG, *PDESC_TABLE_REG;

#pragma pack(pop)

/* Segment AR (Access Rights) 辅助宏 */
#define VMX_SEGMENT_AR_UNUSABLE         0x10000

/* ------------------------------------------------------------------ */
/*  Guest 寄存器上下文 (VM-Exit 时由汇编保存)                         */
/* ------------------------------------------------------------------ */

typedef struct _GUEST_CONTEXT {
    ULONG64 R15;
    ULONG64 R14;
    ULONG64 R13;
    ULONG64 R12;
    ULONG64 R11;
    ULONG64 R10;
    ULONG64 R9;
    ULONG64 R8;
    ULONG64 Rdi;
    ULONG64 Rsi;
    ULONG64 Rbp;
    ULONG64 Rdx;
    ULONG64 Rcx;
    ULONG64 Rbx;
    ULONG64 Rax;
} GUEST_CONTEXT, *PGUEST_CONTEXT;

/* ------------------------------------------------------------------ */
/*  每核 VMX 上下文                                                   */
/* ------------------------------------------------------------------ */

#define VMX_HOST_STACK_SIZE     (8 * PAGE_SIZE)

typedef struct _VMX_PROCESSOR_CTX {
    PVOID       VmxonRegion;
    PVOID       VmcsRegion;
    PVOID       HostStack;
    PVOID       MsrBitmap;
    ULONG64     VmxonPhysical;
    ULONG64     VmcsPhysical;
    ULONG64     MsrBitmapPhysical;
    BOOLEAN     Launched;
} VMX_PROCESSOR_CTX, *PVMX_PROCESSOR_CTX;

typedef struct _VMX_STATE {
    PVMX_PROCESSOR_CTX Processors;
    ULONG              ProcessorCount;
    ULONG              VmcsRevisionId;
    BOOLEAN            EptSupported;
    BOOLEAN            VpidSupported;
} VMX_STATE, *PVMX_STATE;

/* ------------------------------------------------------------------ */
/*  INVEPT / INVVPID 描述符                                           */
/* ------------------------------------------------------------------ */

typedef struct _INVEPT_DESC {
    ULONG64 EptPointer;
    ULONG64 Reserved;
} INVEPT_DESC, *PINVEPT_DESC;

typedef struct _INVVPID_DESC {
    ULONG64 Vpid;
    ULONG64 LinearAddress;
} INVVPID_DESC, *PINVVPID_DESC;

#define INVEPT_SINGLE_CONTEXT   1
#define INVEPT_ALL_CONTEXT      2
#define INVVPID_SINGLE_CONTEXT  1
#define INVVPID_ALL_CONTEXT     2

/* ------------------------------------------------------------------ */
/*  汇编层函数声明 (asm.asm)                                          */
/* ------------------------------------------------------------------ */

/* VMX 指令 */
UCHAR  AsmVmxOn(ULONG64 *VmxonRegionPa);
VOID   AsmVmxOff(VOID);
UCHAR  AsmVmClear(ULONG64 *VmcsRegionPa);
UCHAR  AsmVmPtrld(ULONG64 *VmcsRegionPa);
ULONG64 AsmVmRead(ULONG64 Field);
VOID   AsmVmWrite(ULONG64 Field, ULONG64 Value);
VOID   AsmVmCall(ULONG64 HypercallNum, ULONG64 Arg1);

/* 缓存无效化 */
VOID AsmInvept(ULONG Type, PINVEPT_DESC Desc);
VOID AsmInvvpid(ULONG Type, PINVVPID_DESC Desc);

/* 控制寄存器 */
ULONG64 AsmReadCr0(VOID);
VOID    AsmWriteCr0(ULONG64 Value);
ULONG64 AsmReadCr3(VOID);
VOID    AsmWriteCr3(ULONG64 Value);
ULONG64 AsmReadCr4(VOID);
VOID    AsmWriteCr4(ULONG64 Value);

/* MSR */
ULONG64 AsmReadMsr(ULONG32 Index);
VOID    AsmWriteMsr(ULONG32 Index, ULONG64 Value);

/* 描述符表 */
VOID AsmGetGdtr(PDESC_TABLE_REG Out);
VOID AsmGetIdtr(PDESC_TABLE_REG Out);

/* 段选择子 */
USHORT AsmGetCs(VOID);
USHORT AsmGetSs(VOID);
USHORT AsmGetDs(VOID);
USHORT AsmGetEs(VOID);
USHORT AsmGetFs(VOID);
USHORT AsmGetGs(VOID);
USHORT AsmGetTr(VOID);
USHORT AsmGetLdtr(VOID);

/* VMX 启动 (设置 Guest RSP/RIP 后 vmlaunch) */
BOOLEAN AsmVmxLaunch(VOID);

/* VM-Exit 入口桩 (设为 Host RIP) */
VOID AsmVmExitHandler(VOID);

/* ------------------------------------------------------------------ */
/*  VMX 核心函数声明 (vmx.c)                                          */
/* ------------------------------------------------------------------ */

BOOLEAN VmxCheckSupport(VOID);
NTSTATUS VmxInit(VOID);
VOID VmxDeinit(VOID);
PVMX_STATE VmxGetState(VOID);

/* VM-Exit 分发 (vmexit.c, Phase 4 实现) */
BOOLEAN VmExitDispatch(PGUEST_CONTEXT GuestCtx);
