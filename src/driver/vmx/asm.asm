; ====================================================================
;  HyperVX - VT-x 汇编原语层 (x64 MASM)
;  封装所有 VMX 指令、CR/MSR 读写、描述符表操作、VM-Exit 入口
; ====================================================================

OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

; VMCS 字段 (汇编中使用)
VMCS_GUEST_RSP      EQU 0681Ch
VMCS_GUEST_RIP      EQU 0681Eh
VMCS_GUEST_RFLAGS   EQU 06820h

; C 函数外部声明
EXTERN VmExitDispatch:PROC

.code

; ====================================================================
;  VMX 指令包装
; ====================================================================

; ------------------------------------------------------------------
;  UCHAR AsmVmxOn(ULONG64 *VmxonRegionPa)
;  rcx = 指向 VMXON 区域物理地址的指针
;  返回: CF=1 失败→0, 成功→1
; ------------------------------------------------------------------
AsmVmxOn PROC
    vmxon   QWORD PTR [rcx]
    jc      VmxOnFail
    jz      VmxOnFail
    mov     al, 1
    ret
VmxOnFail:
    xor     al, al
    ret
AsmVmxOn ENDP

; ------------------------------------------------------------------
;  VOID AsmVmxOff(VOID)
; ------------------------------------------------------------------
AsmVmxOff PROC
    vmxoff
    ret
AsmVmxOff ENDP

; ------------------------------------------------------------------
;  UCHAR AsmVmClear(ULONG64 *VmcsRegionPa)
; ------------------------------------------------------------------
AsmVmClear PROC
    vmclear QWORD PTR [rcx]
    jc      VmClearFail
    jz      VmClearFail
    mov     al, 1
    ret
VmClearFail:
    xor     al, al
    ret
AsmVmClear ENDP

; ------------------------------------------------------------------
;  UCHAR AsmVmPtrld(ULONG64 *VmcsRegionPa)
; ------------------------------------------------------------------
AsmVmPtrld PROC
    vmptrld QWORD PTR [rcx]
    jc      VmPtrldFail
    jz      VmPtrldFail
    mov     al, 1
    ret
VmPtrldFail:
    xor     al, al
    ret
AsmVmPtrld ENDP

; ------------------------------------------------------------------
;  ULONG64 AsmVmRead(ULONG64 Field)
;  rcx = VMCS 字段编码
;  返回: rax = 字段值
; ------------------------------------------------------------------
AsmVmRead PROC
    vmread  rax, rcx
    ret
AsmVmRead ENDP

; ------------------------------------------------------------------
;  VOID AsmVmWrite(ULONG64 Field, ULONG64 Value)
;  rcx = VMCS 字段编码, rdx = 值
; ------------------------------------------------------------------
AsmVmWrite PROC
    vmwrite rcx, rdx
    ret
AsmVmWrite ENDP

; ------------------------------------------------------------------
;  UCHAR AsmVmLaunch(VOID)
;  成功: 返回 TRUE (在 Guest 上下文中)
;  失败: 返回 FALSE
; ------------------------------------------------------------------
AsmVmxLaunch PROC
    pushfq
    push    rbx
    push    rdi
    push    rsi
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15

    ; 将当前 RSP 写入 Guest RSP
    mov     rdx, rsp
    mov     rcx, VMCS_GUEST_RSP
    vmwrite rcx, rdx

    ; Guest RIP = GuestResume 标签
    lea     rdx, GuestResume
    mov     rcx, VMCS_GUEST_RIP
    vmwrite rcx, rdx

    vmlaunch

    ; vmlaunch 失败才会到这里
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rsi
    pop     rdi
    pop     rbx
    popfq
    xor     eax, eax        ; FALSE
    ret

GuestResume:
    ; vmlaunch 成功 → Guest 模式从此处恢复
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rsi
    pop     rdi
    pop     rbx
    popfq
    mov     eax, 1          ; TRUE
    ret
AsmVmxLaunch ENDP

; ------------------------------------------------------------------
;  VOID AsmVmCall(ULONG64 HypercallNum, ULONG64 Arg1)
;  rcx = 超调用号, rdx = 参数
; ------------------------------------------------------------------
AsmVmCall PROC
    vmcall
    ret
AsmVmCall ENDP

; ====================================================================
;  INVEPT / INVVPID
; ====================================================================

; ------------------------------------------------------------------
;  VOID AsmInvept(ULONG Type, PINVEPT_DESC Desc)
;  ecx = type, rdx = descriptor 指针
; ------------------------------------------------------------------
AsmInvept PROC
    invept  rcx, OWORD PTR [rdx]
    ret
AsmInvept ENDP

; ------------------------------------------------------------------
;  VOID AsmInvvpid(ULONG Type, PINVVPID_DESC Desc)
; ------------------------------------------------------------------
AsmInvvpid PROC
    invvpid rcx, OWORD PTR [rdx]
    ret
AsmInvvpid ENDP

; ====================================================================
;  控制寄存器读写
; ====================================================================

AsmReadCr0 PROC
    mov     rax, cr0
    ret
AsmReadCr0 ENDP

AsmWriteCr0 PROC
    mov     cr0, rcx
    ret
AsmWriteCr0 ENDP

AsmReadCr3 PROC
    mov     rax, cr3
    ret
AsmReadCr3 ENDP

AsmWriteCr3 PROC
    mov     cr3, rcx
    ret
AsmWriteCr3 ENDP

AsmReadCr4 PROC
    mov     rax, cr4
    ret
AsmReadCr4 ENDP

AsmWriteCr4 PROC
    mov     cr4, rcx
    ret
AsmWriteCr4 ENDP

; ====================================================================
;  MSR 读写
; ====================================================================

; ------------------------------------------------------------------
;  ULONG64 AsmReadMsr(ULONG32 Index)
;  ecx = MSR 索引
;  返回: rax = [edx:eax]
; ------------------------------------------------------------------
AsmReadMsr PROC
    rdmsr
    shl     rdx, 32
    or      rax, rdx
    ret
AsmReadMsr ENDP

; ------------------------------------------------------------------
;  VOID AsmWriteMsr(ULONG32 Index, ULONG64 Value)
;  ecx = MSR 索引, rdx = 值
; ------------------------------------------------------------------
AsmWriteMsr PROC
    mov     rax, rdx
    shr     rdx, 32
    wrmsr
    ret
AsmWriteMsr ENDP

; ====================================================================
;  描述符表
; ====================================================================

; ------------------------------------------------------------------
;  VOID AsmGetGdtr(PDESC_TABLE_REG Out)
;  rcx = 输出缓冲区
; ------------------------------------------------------------------
AsmGetGdtr PROC
    sgdt    FWORD PTR [rcx]
    ret
AsmGetGdtr ENDP

; ------------------------------------------------------------------
;  VOID AsmGetIdtr(PDESC_TABLE_REG Out)
; ------------------------------------------------------------------
AsmGetIdtr PROC
    sidt    FWORD PTR [rcx]
    ret
AsmGetIdtr ENDP

; ====================================================================
;  段选择子读取
; ====================================================================

AsmGetCs PROC
    mov     ax, cs
    ret
AsmGetCs ENDP

AsmGetSs PROC
    mov     ax, ss
    ret
AsmGetSs ENDP

AsmGetDs PROC
    mov     ax, ds
    ret
AsmGetDs ENDP

AsmGetEs PROC
    mov     ax, es
    ret
AsmGetEs ENDP

AsmGetFs PROC
    mov     ax, fs
    ret
AsmGetFs ENDP

AsmGetGs PROC
    mov     ax, gs
    ret
AsmGetGs ENDP

AsmGetTr PROC
    str     ax
    ret
AsmGetTr ENDP

AsmGetLdtr PROC
    sldt    ax
    ret
AsmGetLdtr ENDP

; ====================================================================
;  VM-Exit 入口桩
;
;  当 VM-Exit 发生时，CPU 加载 Host 状态:
;    RSP = Host RSP (VMCS), RIP = Host RIP → 此处
;  Guest GPR 仍在寄存器中，需手动保存
; ====================================================================

AsmVmExitHandler PROC
    ; 保存 Guest 通用寄存器 (与 GUEST_CONTEXT 结构布局一致)
    push    rax
    push    rbx
    push    rcx
    push    rdx
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15

    ; rcx = GUEST_CONTEXT* (栈顶指针)
    mov     rcx, rsp

    ; 影子空间 + 对齐 (15 次 push = 120 字节, sub 28h 补齐16字节对齐)
    sub     rsp, 28h
    call    VmExitDispatch
    add     rsp, 28h

    ; al = TRUE → 退出 VMX, FALSE → vmresume 继续 Guest
    test    al, al
    jnz     DoVmxOff

    ; 恢复 Guest GPR
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rdx
    pop     rcx
    pop     rbx
    pop     rax

    ; 恢复 Guest 执行
    vmresume
    ; vmresume 不应该返回, 到这里说明出错
    int     3

DoVmxOff:
    ; 读取 Guest RSP/RIP 用于恢复
    ; 先从 VMCS 读，存到 r15/r14 (临时)
    mov     rcx, VMCS_GUEST_RIP
    vmread  r14, rcx
    mov     rcx, VMCS_GUEST_RSP
    vmread  r15, rcx
    mov     rcx, VMCS_GUEST_RFLAGS
    vmread  r13, rcx

    ; 恢复 Guest GPR (除 r13/r14/r15 已被占用)
    pop     r12             ; 原 r15 位置 → 丢弃 (已用 VMCS 的值)
    pop     r12             ; 原 r14
    pop     r12             ; 原 r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rdx
    pop     rcx
    pop     rbx
    pop     rax

    ; 关闭 VMX
    vmxoff

    ; 切换到 Guest 栈
    mov     rsp, r15

    ; 恢复 RFLAGS
    push    r13
    popfq

    ; 跳转到 Guest RIP 继续执行
    jmp     r14

AsmVmExitHandler ENDP

END
