/*
 * Copyright 2015 Red Hat, Inc.  All rights reserved.
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

#include "global.h"
#include "pake/conv.h"

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/whrlpool.h>

#include <errno.h>
#include <stdbool.h>
#include <string.h>

/* The current ratio is 1.75, which allows (for instance):
 *     AES128 => P224 */
#define CURVE_KEY_RATIO 1.75

struct curve {
    EC_GROUP *curve;
    const ASN1_OBJECT *obj;
    size_t size;
};

struct hash {
    const EVP_MD *hash;
    const ASN1_OBJECT *obj;
    size_t size;
};

static int
curve_cmp(const void *a, const void *b)
{
    const curve *const *aa = a;
    const curve *const *bb = b;

    return (*aa)->size - (*bb)->size;
}

static STACK_OF(ASN1_INTEGER) *
ptypes(const global *g)
{
    static const krb5_int32 pakes[] = {
        PA_PAKE_SPAKE,
        PA_PAKE_JPAKE,
        0
    };

    STACK_OF(ASN1_INTEGER) *ptypes = NULL;
    ASN1_INTEGER *tmp = NULL;

    ptypes = sk_ASN1_INTEGER_new(NULL);
    if (ptypes == NULL)
        return NULL;

    for (size_t i = 0; pakes[i] != 0; i++) {
        tmp = int2integer(pakes[i]);
        if (tmp == NULL)
            goto error;

        if (!sk_ASN1_INTEGER_push(ptypes, tmp))
            goto error;
    }

    return ptypes;

error:
    sk_ASN1_INTEGER_free(ptypes);
    ASN1_INTEGER_free(tmp);
    return NULL;
}

static STACK_OF(ASN1_OBJECT) *
groups(const global *g, const krb5_keyblock *key)
{
    STACK_OF(ASN1_OBJECT) *sk;

    sk = sk_ASN1_OBJECT_new(NULL);
    if (sk == NULL)
        return NULL;

    for (size_t j = 0; g->curves[j] != NULL; j++) {
        if (g->curves[j]->size < key->length * CURVE_KEY_RATIO)
            continue;

        if (!sk_ASN1_OBJECT_push(sk, g->curves[j]->obj)) {
            sk_ASN1_OBJECT_free(sk);
            return NULL;
        }
    }

    return sk;
}

static STACK_OF(ASN1_OBJECT) *
hashes(const global *g, const krb5_keyblock *key)
{
    STACK_OF(ASN1_OBJECT) *sk;

    sk = sk_ASN1_OBJECT_new(NULL);
    if (sk == NULL)
        return NULL;

    for (size_t j = 0; g->hashes[j] != NULL; j++) {
        if (g->hashes[j]->size != key->length)
            continue;

        if (!sk_ASN1_OBJECT_push(sk, g->hashes[j]->obj)) {
            sk_ASN1_OBJECT_free(sk);
            return NULL;
        }
    }

    return sk;
}

static STACK_OF(PAKE_SUPPORT) *
supports(const global *g, const krb5_keyblock *keys)
{
    STACK_OF(PAKE_SUPPORT) *supports;

    supports = SKM_sk_new(PAKE_SUPPORT, NULL);
    if (supports == NULL)
        return NULL;

    for (size_t i = 0; keys[i].enctype != ENCTYPE_NULL; i++) {
        PAKE_SUPPORT *support;

        support = PAKE_SUPPORT_new();
        if (support == NULL)
            goto error;

        support->etype = int2integer(keys[i].enctype);
        support->groups = groups(g, &keys[i]);
        support->hashes = hashes(g, &keys[i]);
        if (support->etype == NULL
            || support->groups == NULL
            || support->hashes == NULL) {
            PAKE_SUPPORT_free(support);
            goto error;
        }

        /* Skip keys with empty lists. */
        if (sk_ASN1_OBJECT_num(support->groups) == 0
            || sk_ASN1_OBJECT_num(support->hashes) == 0) {
            PAKE_SUPPORT_free(support);
            continue;
        }

        if (!SKM_sk_push(PAKE_SUPPORT, supports, support)) {
            PAKE_SUPPORT_free(support);
            goto error;
        }
    }

    return supports;

error:
    SKM_sk_free(PAKE_SUPPORT, supports);
    return NULL;
}

static const EC_GROUP *
group_load(const global *g, const krb5_keyblock *key, const ASN1_OBJECT *obj)
{
    if (g == NULL || key == NULL || obj == NULL)
        return NULL;

    for (size_t i = 0; g->curves[i] != NULL; i++) {
        if (OBJ_cmp(g->curves[i]->obj, obj) != 0)
            continue;

        if (g->curves[i]->size >= key->length * CURVE_KEY_RATIO)
            return g->curves[i]->curve;
    }

    return NULL;
}

static const EC_GROUP *
group_choose(const global *g, const krb5_keyblock *key,
             const STACK_OF(ASN1_OBJECT) *options)
{
    if (g == NULL || key == NULL || options == NULL)
        return NULL;

    for (int i = 0; i < sk_ASN1_OBJECT_num(options); i++) {
        ASN1_OBJECT *obj = sk_ASN1_OBJECT_value(options, i);
        const EC_GROUP *grp = group_load(g, key, obj);
        if (grp != NULL)
            return grp;
    }

    return NULL;
}

static const EVP_MD *
hash_load(const global *g, const krb5_keyblock *key, const ASN1_OBJECT *obj)
{
    if (g == NULL || key == NULL || obj == NULL)
        return NULL;

    for (size_t j = 0; g->hashes[j] != NULL; j++) {
        if (OBJ_cmp(g->hashes[j]->obj, obj) != 0)
            continue;

        if (g->hashes[j]->size == key->length)
            return g->hashes[j]->hash;
    }

    return NULL;
}

static const EVP_MD *
hash_choose(const global *g, const krb5_keyblock *key,
            const STACK_OF(ASN1_OBJECT) *options)
{
    if (g == NULL || key == NULL || options == NULL)
        return NULL;

    for (int i = 0; i < sk_ASN1_OBJECT_num(options); i++) {
        ASN1_OBJECT *obj = sk_ASN1_OBJECT_value(options, i);
        const EVP_MD *md = hash_load(g, key, obj);
        if (md != NULL)
            return md;
    }

    return NULL;
}

static krb5_int32
ptype_load(const global *g, const ASN1_INTEGER *ptype)
{
    switch (ASN1_INTEGER_get(ptype)) {
    case PA_PAKE_SPAKE:
    case PA_PAKE_JPAKE:
        return ASN1_INTEGER_get(ptype);
    }

    return 0;
}

static krb5_int32
ptype_choose(const global *g, const STACK_OF(ASN1_INTEGER) *options)
{
    krb5_int32 ptype;

    for (int i = 0; i < sk_ASN1_INTEGER_num(options); i++) {
        ptype = ptype_load(g, sk_ASN1_INTEGER_value(options, i));
        if (ptype != 0)
            return ptype;
    }

    return 0;
}

void
global_free(global *g)
{
    if (g == NULL)
        return;

    for (size_t i = 0; g->curves[i] != NULL; i++) {
        EC_GROUP_clear_free(g->curves[i]->curve);
        free(g->curves[i]);
    }
    free(g->curves);

    for (size_t i = 0; g->hashes[i] != NULL; i++)
        free(g->hashes[i]);
    free(g->hashes);

    BN_CTX_free(g->ctx);
    memset(g, 0, sizeof(*g));
}

krb5_error_code
global_init(global *g)
{
    size_t ncurves;

    ncurves = EC_get_builtin_curves(NULL, 0);
    if (ncurves == 0)
        return EINVAL;

    EC_builtin_curve curves[ncurves];
    const hash HASHES[] = {
#ifndef OPENSSL_NO_MD5
        { EVP_md5(), OBJ_nid2obj(NID_md5), MD5_DIGEST_LENGTH },
#endif
#ifndef OPENSSL_NO_SHA
        { EVP_sha1(), OBJ_nid2obj(NID_sha1), SHA_DIGEST_LENGTH },
#endif
#ifndef OPENSSL_NO_SHA256
        { EVP_sha224(), OBJ_nid2obj(NID_sha224), SHA224_DIGEST_LENGTH },
        { EVP_sha256(), OBJ_nid2obj(NID_sha256), SHA256_DIGEST_LENGTH },
#endif
#ifndef OPENSSL_NO_SHA512
        { EVP_sha384(), OBJ_nid2obj(NID_sha384), SHA384_DIGEST_LENGTH },
        { EVP_sha512(), OBJ_nid2obj(NID_sha512), SHA512_DIGEST_LENGTH },
#endif
#ifndef OPENSSL_NO_WHIRLPOOL
        { EVP_whirlpool(), OBJ_nid2obj(NID_whirlpool), WHIRLPOOL_DIGEST_LENGTH },
#endif
        {}
    };

    g->ctx =  BN_CTX_new();
    g->curves = calloc(ncurves + 1, sizeof(curve *));
    g->hashes = calloc(sizeof(HASHES) / sizeof(*HASHES), sizeof(hash *));
    if (g->ctx == NULL || g->curves == NULL || g->hashes == NULL)
        goto error;

    EC_get_builtin_curves(curves, ncurves);
    for (size_t i = 0, j = 0; i < ncurves; i++) {
        const EC_POINT *gen;
        ASN1_OBJECT *obj;

        obj = OBJ_nid2obj(curves[i].nid);
        if (obj == NULL)
            continue; /* Skip curves without OIDs. */

        g->curves[j] = malloc(sizeof(curve));
        if (g->curves[j] == NULL)
            goto error;

        g->curves[j]->curve = EC_GROUP_new_by_curve_name(curves[i].nid);
        if (g->curves[j]->curve == NULL)
            goto error;

        gen = EC_GROUP_get0_generator(g->curves[j]->curve);
        g->curves[j]->size = EC_POINT_point2oct(g->curves[j]->curve, gen,
                                                POINT_CONVERSION_UNCOMPRESSED,
                                                NULL, 0, g->ctx) / 2;
        g->curves[j]->obj = obj;
        j++;
    }

    /* Sort curves in size order to reduce unnecessary network traffic. */
    for (ncurves = 0; g->curves[ncurves] != NULL; ncurves++)
        continue;
    qsort(g->curves, ncurves, sizeof(curve *), curve_cmp);

    for (size_t i = 0, j = 0; HASHES[i].size != 0; i++) {
        if (HASHES[i].hash == NULL)
            continue;

        g->hashes[j] = malloc(sizeof(hash));
        if (g->hashes[j] == NULL)
            goto error;

        *g->hashes[j++] = HASHES[i];
    }

    return 0;

error:
    global_free(g);
    return ENOMEM;
}

PAKE_INFO *
global_info(const global *g, const krb5_keyblock *keys)
{
    PAKE_INFO *pinfo;

    pinfo = PAKE_INFO_new();
    if (pinfo == NULL)
        return NULL;

    pinfo->ptypes = ptypes(g);
    pinfo->supports = supports(g, keys);
    if (pinfo->ptypes == NULL || pinfo->supports == NULL) {
        PAKE_INFO_free(pinfo);
        return NULL;
    }

    return pinfo;
}

krb5_error_code
global_profile(const global *g, const krb5_keyblock *key_or_keys,
               const PAKE_MESSAGE *in, krb5_int32 *ptype,
               const krb5_keyblock **ask, const EC_GROUP **grp,
               const EVP_MD **md)
{
    const krb5_keyblock *key = NULL;
    size_t nkeys = 1;
    int n;

    if (ask != NULL) {
        for (nkeys = 0; key_or_keys[nkeys].enctype != ENCTYPE_NULL; nkeys++)
            continue;
    }
    if (nkeys == 0)
        return EINVAL;

    /* Setup crypto. */
    switch (in->type) {
    case PAKE_MESSAGE_TYPE_INFO:
        *ptype = ptype_choose(g, in->value.info->ptypes);
        if (*ptype == 0)
            return ENOTSUP;

        n = SKM_sk_num(PAKE_SUPPORT, in->value.info->supports);
        for (int i = 0; i < n; i++) {
            const PAKE_SUPPORT *s;

            s = SKM_sk_value(PAKE_SUPPORT, in->value.info->supports, i);
            for (size_t i = 0; i < nkeys; i++) {
                if (key_or_keys[i].enctype == ASN1_INTEGER_get(s->etype)) {
                    key = &key_or_keys[i];
                    break;
                }
            }

            if (key == NULL)
                continue;

            *grp = group_choose(g, key, s->groups);
            *md = hash_choose(g, key, s->hashes);
            goto egress;
        }

        return KRB5KDC_ERR_ETYPE_NOSUPP;

    case PAKE_MESSAGE_TYPE_EXCHANGE:
    case PAKE_MESSAGE_TYPE_VERIFIER:
        *ptype = ptype_load(g, in->value.data->ptype);
        if (*ptype == 0)
            return ENOTSUP;

        for (size_t i = 0; i < nkeys; i++) {
            krb5_int32 etype = ASN1_INTEGER_get(in->value.data->etype);
            if (key_or_keys[i].enctype == etype) {
                key = &key_or_keys[i];
                break;
            }
        }

        *grp = group_load(g, key, in->value.data->group);
        *md = hash_load(g, key, in->value.data->hash);
        goto egress;
    }

    return EINVAL;

egress:
    if (*grp == NULL)
       return ENOTSUP;
    if (*md == NULL)
        return KRB5KDC_ERR_SUMTYPE_NOSUPP;
    if (ask != NULL)
        *ask = key;
    return 0;
}
