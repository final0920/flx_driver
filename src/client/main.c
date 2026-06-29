#include "hv_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  十六进制转储                                                      */
/* ------------------------------------------------------------------ */

static void
HexDump(const void *Data, SIZE_T Size, ULONG64 Base)
{
    const BYTE *p = (const BYTE *)Data;
    for (SIZE_T off = 0; off < Size; off += 16) {
        printf("  %016llX  ", Base + off);
        for (SIZE_T j = 0; j < 16; j++) {
            if (off + j < Size)
                printf("%02X ", p[off + j]);
            else
                printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" |");
        for (SIZE_T j = 0; j < 16 && off + j < Size; j++) {
            BYTE c = p[off + j];
            printf("%c", (c >= 0x20 && c < 0x7F) ? c : '.');
        }
        printf("|\n");
    }
}

/* ------------------------------------------------------------------ */
/*  命令实现                                                          */
/* ------------------------------------------------------------------ */

static int
CmdRead(PHV_CONTEXT Ctx, int argc, char **argv)
{
    if (argc < 3) return 1;

    DWORD   pid  = (DWORD)strtoul(argv[0], NULL, 0);
    ULONG64 addr = strtoull(argv[1], NULL, 16);
    SIZE_T  size = (SIZE_T)strtoull(argv[2], NULL, 0);

    if (!size || size > 0x10000) {
        printf("[-] size must be 1..65536\n");
        return 1;
    }

    BYTE *buf = (BYTE *)malloc(size);
    if (!buf) { printf("[-] malloc failed\n"); return 1; }

    if (HvReadMemory(Ctx, pid, (PVOID)addr, buf, size)) {
        printf("[+] Read %llu bytes  PID %lu @ 0x%llX:\n",
               (ULONG64)size, pid, addr);
        HexDump(buf, size, addr);
    } else {
        printf("[-] ReadMemory failed: %lu\n", GetLastError());
    }

    free(buf);
    return 0;
}

static int
CmdWrite(PHV_CONTEXT Ctx, int argc, char **argv)
{
    if (argc < 3) return 1;

    DWORD   pid  = (DWORD)strtoul(argv[0], NULL, 0);
    ULONG64 addr = strtoull(argv[1], NULL, 16);
    const char *hex = argv[2];
    SIZE_T hlen = strlen(hex);

    if (hlen == 0 || hlen % 2 != 0) {
        printf("[-] hex string must be even length\n");
        return 1;
    }

    SIZE_T size = hlen / 2;
    BYTE *buf = (BYTE *)malloc(size);
    if (!buf) { printf("[-] malloc failed\n"); return 1; }

    for (SIZE_T i = 0; i < size; i++) {
        unsigned int b;
        if (sscanf_s(hex + i * 2, "%02X", &b) != 1) {
            printf("[-] bad hex at offset %llu\n", (ULONG64)i);
            free(buf);
            return 1;
        }
        buf[i] = (BYTE)b;
    }

    if (HvWriteMemory(Ctx, pid, (PVOID)addr, buf, size)) {
        printf("[+] Wrote %llu bytes  PID %lu @ 0x%llX\n",
               (ULONG64)size, pid, addr);
    } else {
        printf("[-] WriteMemory failed: %lu\n", GetLastError());
    }

    free(buf);
    return 0;
}

static int
CmdBase(PHV_CONTEXT Ctx, int argc, char **argv)
{
    if (argc < 1) return 1;

    DWORD pid = (DWORD)strtoul(argv[0], NULL, 0);
    ULONG64 base = 0;

    if (HvGetProcessBase(Ctx, pid, &base)) {
        printf("[+] PID %lu  ImageBase = 0x%llX\n", pid, base);
    } else {
        printf("[-] GetProcessBase failed: %lu\n", GetLastError());
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  入口                                                              */
/* ------------------------------------------------------------------ */

static void
PrintUsage(void)
{
    printf("HyperVX Client v1.0\n\n");
    printf("  hv_client read  <pid> <addr_hex> <size>\n");
    printf("  hv_client write <pid> <addr_hex> <hex_bytes>\n");
    printf("  hv_client base  <pid>\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    HV_CONTEXT ctx = { 0 };
    if (!HvConnect(&ctx)) {
        printf("[-] Cannot open HyperVX device: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] Connected to HyperVX driver\n");

    int rc = 1;
    const char *cmd = argv[1];

    if      (_stricmp(cmd, "read")  == 0) rc = CmdRead (&ctx, argc - 2, argv + 2);
    else if (_stricmp(cmd, "write") == 0) rc = CmdWrite(&ctx, argc - 2, argv + 2);
    else if (_stricmp(cmd, "base")  == 0) rc = CmdBase (&ctx, argc - 2, argv + 2);
    else { printf("[-] Unknown command: %s\n", cmd); PrintUsage(); }

    HvDisconnect(&ctx);
    return rc;
}
