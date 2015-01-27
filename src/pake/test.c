/*
 * Copyright (c) 2015 Red Hat, Inc.
 * Copyright (c) 2015 Nathaniel McCallum <npmccallum@redhat.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "spake.h"
#include "jpake.h"

#include <openssl/err.h>
#include <openssl/engine.h>

#include <string.h>
#include <stdint.h>

#define ONE_OF(a, b) ((a != NULL) ^ (b != NULL))

#define OK "\e[0;32m"
#define FAIL "\e[0;31m"
#define RESET "\e[0m"

typedef int
(*pake_func)(const pake_ctx *pctx, const ASN1_OCTET_STRING *inmsg,
             const ASN1_OCTET_STRING *inprv, ASN1_OCTET_STRING **outmsg,
             ASN1_OCTET_STRING **outprv, EC_POINT **key);

static BIGNUM *
make_order(EC_GROUP *grp, BN_CTX *ctx)
{
    BIGNUM *ord;

    ord = BN_new();
    if (ord == NULL)
        return NULL;

    if (!EC_GROUP_get_order(grp, ord, ctx)) {
        BN_free(ord);
        return NULL;
    }

    return ord;
}

static bool
test(pake_func pake, EC_GROUP *grp, const EVP_MD *md,
     const char *cpwd, const char *spwd, BN_CTX *ctx)
{
    pake_ctx sctx = {
        .cname = "alice",
        .sname = "bob",
        .kdc = true,
        .ctx = ctx,
        .sec = BN_bin2bn((uint8_t *) spwd, strlen(spwd), NULL),
        .grp = grp,
        .ord = make_order(grp, ctx),
        .md = md
    };

    pake_ctx cctx = {
        .cname = "alice",
        .sname = "bob",
        .kdc = false,
        .ctx = ctx,
        .sec = BN_bin2bn((uint8_t *) cpwd, strlen(cpwd), NULL),
        .grp = grp,
        .ord = make_order(grp, ctx),
        .md = md
    };

    ASN1_OCTET_STRING *sinmsg = NULL;
    ASN1_OCTET_STRING *cinmsg = NULL;
    ASN1_OCTET_STRING *soutmsg = NULL;
    ASN1_OCTET_STRING *coutmsg = NULL;
    ASN1_OCTET_STRING *sinprv = NULL;
    ASN1_OCTET_STRING *cinprv = NULL;
    ASN1_OCTET_STRING *soutprv = NULL;
    ASN1_OCTET_STRING *coutprv = NULL;
    EC_POINT *skey = NULL;
    EC_POINT *ckey = NULL;
    bool result = false;
    int retval;

    if (cctx.sec == NULL || cctx.ord == NULL
        || sctx.sec == NULL || sctx.ord == NULL)
        goto egress;

    while (true) {
        /* Do the server side. */
        retval = pake(&sctx, sinmsg, sinprv, &soutmsg, &soutprv, &skey);
        if (retval != 0 || ONE_OF(soutmsg, soutprv) || !ONE_OF(soutmsg, skey))
            goto egress;

        /* Do the client side. */
        retval = pake(&cctx, cinmsg, cinprv, &coutmsg, &coutprv, &ckey);
        if (retval != 0 || ONE_OF(coutmsg, coutprv) || !ONE_OF(coutmsg, ckey))
            goto egress;

        /* Make sure that the client and server results are the same. */
        if (ONE_OF(soutmsg, coutmsg))
            goto egress;

        /* If a key was specified, we are done. */
        if (skey != NULL && ckey != NULL) {
            result = EC_POINT_cmp(grp, ckey, skey, ctx) == 0;
            if (strcmp(cpwd, spwd) != 0)
                result = !result;
            goto egress;
        }

        /* Exchange messages. */
        ASN1_OCTET_STRING_free(sinmsg);
        ASN1_OCTET_STRING_free(sinprv);
        ASN1_OCTET_STRING_free(cinmsg);
        ASN1_OCTET_STRING_free(cinprv);
        sinmsg = coutmsg;
        sinprv = soutprv;
        cinmsg = soutmsg;
        cinprv = coutprv;
        soutmsg = NULL;
        soutprv = NULL;
        coutmsg = NULL;
        coutprv = NULL;
    }

egress:
    ASN1_OCTET_STRING_free(soutmsg);
    ASN1_OCTET_STRING_free(soutprv);
    ASN1_OCTET_STRING_free(coutmsg);
    ASN1_OCTET_STRING_free(coutprv);
    ASN1_OCTET_STRING_free(sinmsg);
    ASN1_OCTET_STRING_free(sinprv);
    ASN1_OCTET_STRING_free(cinmsg);
    ASN1_OCTET_STRING_free(cinprv);
    BN_free(sctx.sec);
    BN_free(sctx.ord);
    BN_free(cctx.sec);
    BN_free(cctx.ord);
    EC_POINT_free(skey);
    EC_POINT_free(ckey);
    return result;
}

#include <sys/time.h>

static unsigned long
gettime(void)
{
    struct timeval tv = {};
    unsigned long sec;

    while (gettimeofday(&tv, NULL) != 0)
        continue;

    sec = tv.tv_sec - 60 * 60 * 24 * 365 * 45;

    return sec * 1000 + tv.tv_usec / 1000;
}

int
main()
{
    static const struct {
        pake_func func;
        const char *name;
    } PAKES[] = {
        { SPAKE, "SPAKE" },
        { JPAKE, "JPAKE" },
        {}
    };

    const EVP_MD *HASHES[] = {
    #ifndef OPENSSL_NO_MD5
        EVP_md5(),
    #endif
    #ifndef OPENSSL_NO_SHA
        EVP_sha1(),
    #endif
    #ifndef OPENSSL_NO_SHA256
        EVP_sha224(),
        EVP_sha256(),
    #endif
    #ifndef OPENSSL_NO_SHA512
        EVP_sha384(),
        EVP_sha512(),
    #endif
    #ifndef OPENSSL_NO_WHIRLPOOL
        EVP_whirlpool(),
    #endif
        NULL
    };

    bool megafail = false;
    BN_CTX *ctx;

    EC_builtin_curve curves[EC_get_builtin_curves(NULL, 0)];
    EC_get_builtin_curves(curves, sizeof(curves) / sizeof(*curves));
    OpenSSL_add_all_digests();

    ctx = BN_CTX_new();
    if (ctx == NULL)
        return 1;

    for (size_t i = 0; PAKES[i].func != NULL; i++) {
        for (size_t j = 0; j < sizeof(curves) / sizeof(*curves); j++) {
            EC_GROUP *grp;

            grp = EC_GROUP_new_by_curve_name(curves[j].nid);
            if (grp == NULL)
                continue;

            if (OBJ_nid2obj(curves[j].nid) == NULL)
                continue;

            for (size_t k = 0; HASHES[k] != NULL; k++) {
                unsigned long before = 0;
                unsigned long after = 0;
                bool fail = false;

                before = gettime();
                fail |= !test(PAKES[i].func, grp, HASHES[k], "foo", "foo", ctx);
                fail |= !test(PAKES[i].func, grp, HASHES[k], "foo", "bar", ctx);
                after = gettime();
                megafail |= fail;

                printf("%s⚫%s %5s %-10s %30s %05lu\n",
                       fail ? FAIL : OK, RESET,
                       PAKES[i].name,
                       OBJ_nid2sn(EVP_MD_type(HASHES[k])),
                       OBJ_nid2sn(curves[j].nid),
                       after - before);
            }

            EC_GROUP_free(grp);
        }
    }

    BN_CTX_free(ctx);

    ENGINE_cleanup();
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    return megafail ? 1 : 0;
}
