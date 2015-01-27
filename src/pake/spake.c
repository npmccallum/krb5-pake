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
#include "spake_constants.h"

#include "conv.h"

#include <errno.h>

static EC_POINT *
make_mask(const pake_ctx *pctx, bool m)
{
    const char *hex = NULL;

    for (size_t i = 0; SPAKE_CONSTANTS[i].curve != 0; i++) {
        if (SPAKE_CONSTANTS[i].curve != EC_GROUP_get_curve_name(pctx->grp))
            continue;

        hex = m ? SPAKE_CONSTANTS[i].m : SPAKE_CONSTANTS[i].n;
        return EC_POINT_hex2point(pctx->grp, hex, NULL, pctx->ctx);
    }

    return NULL;
}

static EC_POINT *
step1(const pake_ctx *pctx, const BIGNUM *prv)
{
    EC_POINT *mask = NULL;
    EC_POINT *pub = NULL;

    mask = make_mask(pctx, pctx->kdc);
    if (mask == NULL)
        return NULL;

    pub = EC_POINT_new(pctx->grp);
    if (pub == NULL) {
        EC_POINT_free(mask);
        return NULL;
    }

    /* Generate the client public key: g * prv + mask * sec. */
    if (!EC_POINT_mul(pctx->grp, pub, prv, mask, pctx->sec, pctx->ctx)) {
        EC_POINT_free(mask);
        EC_POINT_free(pub);
        return NULL;
    }

    EC_POINT_free(mask);
    return pub;
}

static EC_POINT *
step2(const pake_ctx *pctx, const BIGNUM *prv, const EC_POINT *pub)
{
    EC_POINT *mask = NULL;
    EC_POINT *key = NULL;

    /* Make our temporary variables. */
    mask = make_mask(pctx, !pctx->kdc);
    key = EC_POINT_new(pctx->grp);
    if (mask == NULL || key == NULL)
        goto error;

    /* Multiply the remote's mask by the secret.
     *     tmp = mask * sec */
    if (!EC_POINT_mul(pctx->grp, key, NULL, mask, pctx->sec, pctx->ctx))
        goto error;

    /* Subtract the above product from the remote public key.
     *     tmp = pub - tmp */
    if (!EC_POINT_invert(pctx->grp, key, pctx->ctx)
        || !EC_POINT_add(pctx->grp, key, pub, key, pctx->ctx))
        goto error;

    /* Multiply the above with the private key to obtain the session key.
     *     k = tmp * prv */
    if (!EC_POINT_mul(pctx->grp, key, NULL, key, prv, pctx->ctx))
        goto error;

    EC_POINT_free(mask);
    return key;

error:
    EC_POINT_free(mask);
    EC_POINT_free(key);
    return NULL;
}

int
SPAKE(const pake_ctx *pctx, const ASN1_OCTET_STRING *inmsg,
      const ASN1_OCTET_STRING *inprv, ASN1_OCTET_STRING **outmsg,
      ASN1_OCTET_STRING **outprv, EC_POINT **key)
{
    EC_POINT *pub = NULL;
    int retval = ENOMEM;
    BIGNUM *prv = NULL;

    *outmsg = NULL;
    *outprv = NULL;
    *key = NULL;

    if (inprv == NULL) {
        /* Make a random prv. */
        prv = BN_new();
        if (prv == NULL)
            goto error;
        if (!BN_rand_range(prv, pctx->ord))
            goto error;

        /* Make the public key. */
        pub = step1(pctx, prv);
        if (pub == NULL)
            goto error;

        /* Save the private value for later. */
        *outprv = bn2os(prv, pctx->ctx);
        if (*outprv == NULL)
            goto error;

        /* Send the public key. */
        *outmsg = point2os(pctx->grp, pub, pctx->ctx);
        EC_POINT_free(pub);
        if (*outmsg == NULL) {
            ASN1_OCTET_STRING_free(*outprv);
            *outprv = NULL;
            goto error;
        }
    } else {
        /* Load the private key. */
        prv = os2bn(inprv, pctx->ctx);
        if (prv == NULL)
            return EINVAL;

        /* Get the remote public key. */
        pub = os2point(pctx->grp, inmsg, pctx->ctx);
        if (pub == NULL) {
            retval = EINVAL;
            goto error;
        }

        /* Calculate the shared key. */
        *key = step2(pctx, prv, pub);
        EC_POINT_free(pub);
        if (*key == NULL)
            goto error;
    }

    retval = 0;

error:
    BN_free(prv);
    return retval;
}
