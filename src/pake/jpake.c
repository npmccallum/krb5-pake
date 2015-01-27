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

#include "jpake.h"
#include "asn1.h"
#include "conv.h"
#include "hash.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    ASN1_OCTET_STRING *prv;
    ASN1_OCTET_STRING *pub;
    ASN1_OCTET_STRING *g;
} JPAKE_PRV;

ASN1_SEQUENCE(JPAKE_PRV) = {
    ASN1_SIMPLE(JPAKE_PRV, prv, ASN1_OCTET_STRING),
    ASN1_SIMPLE(JPAKE_PRV, pub, ASN1_OCTET_STRING),
    ASN1_SIMPLE(JPAKE_PRV, g, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(JPAKE_PRV)

IMPLEMENT_ASN1_FUNCTIONS(JPAKE_PRV)

static BIGNUM *
make_zero(void)
{
    unsigned char z = 0;
    return BN_bin2bn(&z, sizeof(z), NULL);
}

static BIGNUM *
make_random(const pake_ctx *pctx, bool one)
{
    BIGNUM *zero = NULL;
    BIGNUM *prv = NULL;

    prv = BN_new();
    if (prv == NULL)
        return NULL;

    if (!one) {
        zero = make_zero();
        if (zero == NULL)
            goto error;
    }

    do {
        if (!BN_rand_range(prv, pctx->ord)) {
            BN_free(prv);
            return NULL;
        }
    } while(zero != NULL && BN_cmp(prv, zero) == 0);

    BN_free(zero);
    return prv;

error:
    BN_free(zero);
    BN_free(prv);
    return NULL;
}

/* h = H(g, g^r, g^x, name) */
static bool
hash_zkp(const pake_ctx *pctx, const char *name, const EC_POINT *gv,
         const EC_POINT *gx, uint8_t *hash)
{
    const EC_POINT *g;
    EVP_MD_CTX mdctx;
    bool err = false;

    g = EC_GROUP_get0_generator(pctx->grp);

    if (!EVP_DigestInit(&mdctx, pctx->md))
        return false;
    err |= !hash_append_point(&mdctx, pctx->grp, g, pctx->ctx);
    err |= !hash_append_point(&mdctx, pctx->grp, gv, pctx->ctx);
    err |= !hash_append_point(&mdctx, pctx->grp, gx, pctx->ctx);
    err |= !hash_append_data(&mdctx, (uint8_t *) name, strlen(name));
    err |= !EVP_DigestFinal(&mdctx, hash, NULL);

    return !err;
}

static bool
make_key(const pake_ctx *pctx, const EC_POINT *g, const BIGNUM *prv,
         const EC_POINT *pub, JPAKE_KEY *jkey)
{
    uint8_t hash[EVP_MD_size(pctx->md)];
    EC_POINT *gv = NULL;
    BIGNUM *acc = NULL;
    BIGNUM *v = NULL;
    bool ret = false;

    if (g == NULL)
        g = EC_GROUP_get0_generator(pctx->grp);

    gv = EC_POINT_new(pctx->grp);
    v = make_random(pctx, true);
    if (gv == NULL || v == NULL)
        goto error;

    /* Do the Schnorr signature. */
    if (!EC_POINT_mul(pctx->grp, gv, NULL, g, v, pctx->ctx))
        goto error;
    if (!hash_zkp(pctx, pctx->kdc ? pctx->sname : pctx->cname, gv, pub, hash))
        goto error;
    acc = BN_bin2bn(hash, sizeof(hash), NULL);
    if (acc == NULL
        || !BN_mod_mul(acc, prv, acc, pctx->ord, pctx->ctx)
        || !BN_mod_sub(acc, v, acc, pctx->ord, pctx->ctx))
        goto error;

    /* Encode the results. */
    jkey->gv = point2os(pctx->grp, gv, pctx->ctx);
    jkey->r = bn2os(acc, pctx->ctx);
    jkey->x = point2os(pctx->grp, pub, pctx->ctx);
    if (jkey->gv == NULL || jkey->r == NULL || jkey->x == NULL)
        goto error;

    ret = true;

error:
    EC_POINT_free(gv);
    BN_free(acc);
    BN_free(v);
    return ret;
}

static bool
make_prv(const pake_ctx *pctx, const BIGNUM *prv, const ASN1_OCTET_STRING *pub,
         const EC_POINT *g, JPAKE_PRV *jprv)
{
    jprv->pub = ASN1_OCTET_STRING_dup(pub);
    jprv->prv = bn2os(prv, pctx->ctx);
    jprv->g = point2os(pctx->grp, g, pctx->ctx);
    return jprv->pub != NULL && jprv->prv != NULL && jprv->g != NULL;
}

static EC_POINT *
verify_key(const pake_ctx *pctx, bool one, const EC_POINT *g, const JPAKE_KEY *key)
{
    uint8_t hash[EVP_MD_size(pctx->md)];
    EC_POINT *gvv = NULL;
    EC_POINT *gv = NULL;
    EC_POINT *x = NULL;
    EC_POINT *p = NULL;
    BIGNUM *tmp = NULL;
    BIGNUM *r = NULL;
    bool ret = false;

    if (g == NULL)
        g = EC_GROUP_get0_generator(pctx->grp);

    gvv = EC_POINT_new(pctx->grp);
    gv = os2point(pctx->grp, key->gv, pctx->ctx);
    x = os2point(pctx->grp, key->x, pctx->ctx);
    r = os2bn(key->r, pctx->ctx);
    p = EC_POINT_new(pctx->grp);
    if (gvv == NULL || gv == NULL || x == NULL || r == NULL || p == NULL)
        goto error;

    if (!hash_zkp(pctx, pctx->kdc ? pctx->cname : pctx->sname, gv, x, hash))
        goto error;

    tmp = BN_bin2bn(hash, sizeof(hash), NULL);
    if (tmp == NULL)
        goto error;

    if (!EC_POINT_mul(pctx->grp, p, NULL, g, r, pctx->ctx)
        || !EC_POINT_mul(pctx->grp, gvv, NULL, x, tmp, pctx->ctx)
        || !EC_POINT_add(pctx->grp, gvv, gvv, p, pctx->ctx))
        goto error;

    ret = EC_POINT_cmp(pctx->grp, gv, gvv, pctx->ctx) == 0;
    if (ret && !one) {
        BN_free(tmp);
        ret = false;

        tmp = make_zero();
        if (tmp == NULL)
            goto error;

        if (!EC_POINT_mul(pctx->grp, p, NULL, g, tmp, pctx->ctx))
            goto error;

        ret = EC_POINT_cmp(pctx->grp, x, p, pctx->ctx) != 0;
    }

error:
    EC_POINT_free(gvv);
    EC_POINT_free(gv);
    EC_POINT_free(p);
    BN_free(tmp);
    BN_free(r);
    if (!ret) {
        EC_POINT_free(x);
        return NULL;
    }
    return x;
}

static int
step1(const pake_ctx *pctx, JPAKE_STEP1 *step1, JPAKE_PRV *prv)
{
    int retval = ENOMEM;
    EC_POINT *X1 = NULL;
    EC_POINT *X2 = NULL;
    BIGNUM *x1 = NULL;
    BIGNUM *x2 = NULL;

    X1 = EC_POINT_new(pctx->grp);
    X2 = EC_POINT_new(pctx->grp);
    x1 = make_random(pctx, true);
    x2 = make_random(pctx, false);
    if (x1 == NULL || x2 == NULL)
        goto error;

    /* Calculate the public keys. */
    if (!EC_POINT_mul(pctx->grp, X1, x1, NULL, NULL, pctx->ctx)
        || !EC_POINT_mul(pctx->grp, X2, x2, NULL, NULL, pctx->ctx))
        goto error;

    /* Encode it. */
    if (!make_key(pctx, NULL, x1, X1, step1->x1)
        || !make_key(pctx, NULL, x2, X2, step1->x2))
        goto error;

    /* Start computing the generator for step3. */
    if (!EC_POINT_add(pctx->grp, X1, X1, X2, pctx->ctx))
        goto error;

    if (!make_prv(pctx, x2, step1->x1->x, X1, prv))
        goto error;

    retval = 0;

error:
    EC_POINT_free(X1);
    EC_POINT_free(X2);
    BN_free(x1);
    BN_free(x2);
    return retval;
}

static int
step2(const pake_ctx *pctx, const JPAKE_STEP1 *step1, const JPAKE_PRV *inprv,
      JPAKE_KEY *step2, JPAKE_PRV *outprv)
{
    int retval = ENOMEM;
    EC_POINT *x1 = NULL;
    EC_POINT *x3 = NULL;
    EC_POINT *x4 = NULL;
    EC_POINT *g = NULL;
    BIGNUM *x2 = NULL;
    BIGNUM *S = NULL;

    S = BN_new();
    x1 = os2point(pctx->grp, inprv->pub, pctx->ctx);
    x2 = os2bn(inprv->prv, pctx->ctx);
    g = os2point(pctx->grp, inprv->g, pctx->ctx);
    if (S == NULL || x1 == NULL || x2 == NULL || g == NULL)
        goto egress;

    x3 = verify_key(pctx, true, NULL, step1->x1);
    x4 = verify_key(pctx, false, NULL, step1->x2);
    if (x3 == NULL || x4 == NULL) {
        retval = EINVAL;
        goto egress;
    }

    /* Calculate the generator used to verify the next ZKP. */
    if (!EC_POINT_add(pctx->grp, g, g, x3, pctx->ctx))
        goto egress;

    /* S = sec * x2
     * x1 = x1 + x3 + x4
     * x3 = x1 * S
     */
    if (!BN_mod_mul(S, x2, pctx->sec, pctx->ord, pctx->ctx)
        || !EC_POINT_add(pctx->grp, x1, x1, x3, pctx->ctx)
        || !EC_POINT_add(pctx->grp, x1, x1, x4, pctx->ctx)
        || !EC_POINT_mul(pctx->grp, x3, NULL, x1, S, pctx->ctx))
        goto egress;

    if (!make_key(pctx, x1, S, x3, step2))
        goto egress;

    if (!make_prv(pctx, x2, step1->x2->x, g, outprv))
        goto egress;

    retval = 0;

egress:
    EC_POINT_free(x1);
    EC_POINT_free(x3);
    EC_POINT_free(x4);
    EC_POINT_free(g);
    BN_free(x2);
    BN_free(S);
    return retval;
}

static int
step3(const pake_ctx *pctx, const JPAKE_KEY *step2, const JPAKE_PRV *prv,
      EC_POINT *key)
{
    EC_POINT *x4 = NULL;
    EC_POINT *x = NULL;
    EC_POINT *g = NULL;
    BIGNUM *x2 = NULL;

    /* Restore values from private. */
    x4 = os2point(pctx->grp, prv->pub, pctx->ctx);
    x2 = os2bn(prv->prv, pctx->ctx);
    g = os2point(pctx->grp, prv->g, pctx->ctx);
    if (x4 == NULL || x2 == NULL || g == NULL)
        goto error;

    /* Verify the incoming key. */
    x = verify_key(pctx, true, g, step2);
    if (x == NULL)
        return EINVAL;

    /* Finish the algorithm: K = (x - x4 * x2 * sec) ^ x2. */
    if (!EC_POINT_mul(pctx->grp, g, NULL, x4, x2, pctx->ctx)
        || !EC_POINT_mul(pctx->grp, g, NULL, g, pctx->sec, pctx->ctx)
        || !EC_POINT_invert(pctx->grp, g, pctx->ctx)
        || !EC_POINT_add(pctx->grp, g, x, g, pctx->ctx)
        || !EC_POINT_mul(pctx->grp, key, NULL, g, x2, pctx->ctx))
        goto error;

    EC_POINT_free(x4);
    EC_POINT_free(x);
    EC_POINT_free(g);
    BN_free(x2);
    return 0;

error:
    EC_POINT_free(x4);
    EC_POINT_free(x);
    EC_POINT_free(g);
    BN_free(x2);
    return ENOMEM;
}

int
JPAKE(const pake_ctx *pctx, const ASN1_OCTET_STRING *inmsg,
      const ASN1_OCTET_STRING *inprv, ASN1_OCTET_STRING **outmsg,
      ASN1_OCTET_STRING **outprv, EC_POINT **key)
{
    JPAKE_MESSAGE *joutmsg = NULL;
    JPAKE_MESSAGE *jinmsg = NULL;
    JPAKE_PRV *joutprv = NULL;
    JPAKE_PRV *jinprv = NULL;
    EC_POINT *k = NULL;
    int retval = 0;

    /* Decode the input. */
    if (inmsg != NULL && inprv != NULL) {
        jinmsg = os2item(inmsg, JPAKE_MESSAGE);
        jinprv = os2item(inprv, JPAKE_PRV);
        if (jinmsg == NULL || jinprv == NULL) {
            retval = ENOMEM;
            goto egress;
        }
    }

    /* If we are on step1 or step2, make an out message and prv. */
    if (jinmsg == NULL || jinmsg->type == JPAKE_MESSAGE_TYPE_STEP1) {
        joutmsg = JPAKE_MESSAGE_new();
        joutprv = JPAKE_PRV_new();
        if (joutmsg == NULL || joutprv == NULL) {
            retval = ENOMEM;
            goto egress;
        }
    }

    /* Handle step1. */
    if (jinmsg == NULL) {
        retval = ENOMEM;
        joutmsg->type = JPAKE_MESSAGE_TYPE_STEP1;
        joutmsg->value.step1 = JPAKE_STEP1_new();
        if (joutmsg->value.step1 == NULL)
            goto egress;
        joutmsg->value.step1->x1 = JPAKE_KEY_new();
        joutmsg->value.step1->x2 = JPAKE_KEY_new();
        if (joutmsg->value.step1->x1 == NULL
            || joutmsg->value.step1->x2 == NULL)
            goto egress;

        retval = step1(pctx, joutmsg->value.step1, joutprv);
    } else {
        switch (jinmsg->type) {
        /* Handle step2. */
        case JPAKE_MESSAGE_TYPE_STEP1:
            retval = ENOMEM;
            joutmsg->type = JPAKE_MESSAGE_TYPE_STEP2;
            joutmsg->value.step2 = JPAKE_KEY_new();
            if (joutmsg->value.step2 == NULL)
                goto egress;

            retval = step2(pctx, jinmsg->value.step1, jinprv,
                           joutmsg->value.step2, joutprv);
            break;

        /* Handle step3. */
        case JPAKE_MESSAGE_TYPE_STEP2:
            retval = ENOMEM;
            k = EC_POINT_new(pctx->grp);
            if (k == NULL)
                goto egress;

            retval = step3(pctx, jinmsg->value.step2, jinprv, k);
            if (retval != 0)
                EC_POINT_free(k);
            else
                *key = k;
            break;
        }
    }
    if (retval != 0)
        goto egress;

    if (joutmsg != NULL && joutprv != NULL) {
        *outmsg = item2os(joutmsg, JPAKE_MESSAGE);
        *outprv = item2os(joutprv, JPAKE_PRV);
        if (*outmsg == NULL || *outprv == NULL) {
            ASN1_OCTET_STRING_free(*outmsg);
            *outmsg = NULL;
            retval = ENOMEM;
        }
    }

egress:
    JPAKE_MESSAGE_free(joutmsg);
    JPAKE_MESSAGE_free(jinmsg);
    JPAKE_PRV_free(joutprv);
    JPAKE_PRV_free(jinprv);
    return retval;
}
