#include "../inc/common.h"
#include <stdarg.h>
#include <ntstrsafe.h>

/* ------------------------------------------------------------------ */
/*  HvLog  -  基于 DbgPrintEx 的分级日志                              */
/*  始终以 DPFLTR_ERROR_LEVEL 输出，确保 WinDbg/DbgView 可见          */
/* ------------------------------------------------------------------ */

static const PCSTR g_LevelTag[] = { "DBG", "INF", "WRN", "ERR" };

VOID
HvLog(
    _In_ ULONG Level,
    _In_ PCSTR Format,
    ...)
{
    if (Level > HV_LOG_ERROR)
        Level = HV_LOG_ERROR;

    CHAR Buf[512];
    va_list ap;

    va_start(ap, Format);
    NTSTATUS st = RtlStringCbVPrintfA(Buf, sizeof(Buf), Format, ap);
    va_end(ap);

    if (NT_SUCCESS(st) || st == STATUS_BUFFER_OVERFLOW) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[HyperVX][%s] %s\n", g_LevelTag[Level], Buf);
    }
}
