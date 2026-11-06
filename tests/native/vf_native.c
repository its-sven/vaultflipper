// SPDX-FileCopyrightText: 2026 Sven Würth
// SPDX-License-Identifier: MIT
//
/* Native test harness for the portable core (runs on the build machine).
 *   vf_native pubkey <device_secret_hex>
 *   vf_native open <file> <pin> <device_secret_hex>
 *   vf_native search <file> <pin> <device_secret_hex> <query>
 *   vf_native totp <secret_field> <unix_time>
 * The device secret stands in for the Flipper's crypto enclave. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vf_core.h"
#include "vf_totp.h"

static int unhex(const char* s, uint8_t* out, size_t n) {
    if(strlen(s) != n * 2) return -1;
    for(size_t i = 0; i < n; i++) {
        unsigned v;
        if(sscanf(s + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static bool file_read(void* ctx, uint32_t offset, void* buf, size_t len) {
    FILE* f = ctx;
    if(fseek(f, (long)offset, SEEK_SET) != 0) return false;
    return fread(buf, 1, len, f) == len;
}

int main(int argc, char** argv) {
    uint8_t secret[32], sk[32], pk[32];
    if(argc >= 3 && strcmp(argv[1], "pubkey") == 0) {
        if(unhex(argv[2], secret, 32)) return 2;
        vf_device_keypair(secret, sk, pk);
        for(int i = 0; i < 32; i++)
            printf("%02x", pk[i]);
        char fp[10];
        vf_fingerprint(pk, fp);
        printf(" %s\n", fp);
        return 0;
    }
    if(argc >= 4 && strcmp(argv[1], "totp") == 0) {
        VfTotp t;
        if(!vf_totp_parse(argv[2], &t)) {
            printf("INVALID\n");
            return 1;
        }
        uint64_t now = strtoull(argv[3], NULL, 10);
        char code[VF_TOTP_CODE_MAX];
        vf_totp_code(&t, now, code);
        printf("%s %u\n", code, (unsigned)vf_totp_remaining(&t, now));
        return 0;
    }
    bool search = argc >= 6 && strcmp(argv[1], "search") == 0;
    if(!(argc >= 5 && (strcmp(argv[1], "open") == 0 || search))) {
        fprintf(stderr, "usage: vf_native pubkey <hex> | open <file> <pin> <hex> | search ... <q>\n");
        return 2;
    }
    if(unhex(argv[4], secret, 32)) return 2;
    vf_device_keypair(secret, sk, pk);
    FILE* fp = fopen(argv[2], "rb");
    if(!fp) return 2;

    VfFile file;
    VfDir dir;
    VfResult r = vf_file_open(&file, file_read, fp);
    if(r == VfOk) r = vf_file_unlock(&file, sk, argv[3], strlen(argv[3]), NULL, 0, &dir);
    if(r != VfOk) {
        printf("ERROR %d\n", r);
        fclose(fp);
        return 1;
    }
    printf(
        "META layout=%s synced=%s count=%u pages=%u accounts=%u codes=%u\n",
        dir.meta.f[VfFieldLayout],
        dir.meta.f[VfFieldSynced],
        (unsigned)dir.entry_count,
        dir.page_count,
        dir.account_count,
        (unsigned)dir.code_count);
    int rc = 0;
    for(uint16_t i = 0; i < dir.page_count; i++) {
        const VfPageInfo* pi = &dir.pages[i];
        const char* acc = pi->account == VF_CODES_ACCOUNT ? "#codes" : dir.accounts[pi->account];
        VfPage page;
        r = vf_page_load(&file, &dir, i, &page);
        if(r != VfOk) {
            printf("PAGE %u ERROR %d\n", i, r);
            rc = 1;
            continue;
        }
        if(!search) {
            printf(
                "PAGE %u %s|%s|%s..%s|%u\n",
                i,
                acc,
                pi->group,
                pi->first,
                pi->last,
                page.count);
        }
        for(uint16_t j = 0; j < page.count; j++) {
            const VfRecord* e = &page.entries[j];
            if(search && !vf_contains(e->f[VfFieldName], argv[5])) continue;
            printf(
                "ENTRY %s|%s|%s|%s|%s|%s|%s\n",
                acc,
                pi->group,
                e->f[VfFieldName],
                e->f[VfFieldUser],
                e->f[VfFieldPass],
                e->f[VfFieldTotp],
                e->f[VfFieldUri]);
        }
        vf_page_free(&page);
    }
    vf_dir_free(&dir);
    vf_file_close(&file);
    fclose(fp);
    return rc;
}
