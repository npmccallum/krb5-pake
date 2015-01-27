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

#include "common.h"
#include "kconv.h"
#include "pake/conv.h"
#include "pake/hash.h"
#include "pake/pake.h"

#include <openssl/evp.h>

#include <errno.h>
#include <string.h>

static BIGNUM *
make_order(const EC_GROUP *grp, BN_CTX *ctx)
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

krb5_error_code
common_derive(krb5_context context, const krb5_kdc_req *request,
              const krb5_keyblock *ask, const EC_GROUP *grp,
              const EVP_MD *md, krb5_octet *phash, const EC_POINT *kek,
              krb5_keyblock **dsk, BN_CTX *ctx)
{
    char cname[princ2str(request->client, NULL, 0) + 1];
    char sname[princ2str(request->server, NULL, 0) + 1];
    krb5_error_code retval = 0;
    bool err = false;
    EVP_MD_CTX mdctx;

    princ2str(request->client, cname, sizeof(cname));
    princ2str(request->server, sname, sizeof(sname));

    retval = krb5_init_keyblock(context, ask->enctype,
                                EVP_MD_size(md), dsk);
    if (retval != 0)
        return retval;

    /* Add all the required items to the buffer for hashing. */
    if (!EVP_DigestInit(&mdctx, md))
        goto error;

    err |= !hash_append_data(&mdctx, (krb5_octet *) cname, strlen(cname));
    err |= !hash_append_data(&mdctx, (krb5_octet *) sname, strlen(sname));
    err |= !hash_append_data(&mdctx, phash, EVP_MD_size(md));
    err |= !hash_append_data(&mdctx, ask->contents, ask->length);
    err |= !hash_append_point(&mdctx, grp, kek, ctx);
    err |= !EVP_DigestFinal(&mdctx, (*dsk)->contents, NULL);
    if (err)
        goto error;

    return 0;

error:
    krb5_free_keyblock(context, *dsk);
    *dsk = NULL;
    return ENOMEM;
}

ASN1_OCTET_STRING *
common_verifier(const EVP_MD *md, const krb5_keyblock *dsk)
{
    krb5_octet buffer[EVP_MD_size(md)];

    if (!EVP_Digest(dsk->contents, dsk->length,
                    buffer, NULL, md, NULL))
        return NULL;

    return str2os(buffer, sizeof(buffer));
}

krb5_error_code
common_hash_padata(const EVP_MD *md, const krb5_octet *prev,
                   const krb5_pa_data *padata, krb5_octet *output)
{
    EVP_MD_CTX ctx;

    if (!EVP_DigestInit(&ctx, md))
        return ENOMEM;

    if (prev != NULL) {
        if (!hash_append_data(&ctx, prev, EVP_MD_size(md)))
            return ENOMEM;
    }

    if (!hash_append_data(&ctx, padata->contents, padata->length))
        return ENOMEM;

    if (!EVP_DigestFinal(&ctx, output, NULL))
        return ENOMEM;

    return 0;
}

krb5_error_code
common_padata(krb5_int32 ptype, krb5_int32 etype, const EC_GROUP *grp,
              const EVP_MD *md, PAKE_MESSAGE_TYPE mtype,
              const ASN1_OCTET_STRING *outmsg, krb5_pa_data **pa)
{
    krb5_error_code retval = 0;
    PAKE_DATA data = {};
    PAKE_MESSAGE msg = {
        .type = mtype,
        .value.data = &data
    };

    /* Create the output message. */
    data.ptype = int2integer(ptype);
    data.etype = int2integer(etype);
    data.group = OBJ_nid2obj(EC_GROUP_get_curve_name(grp));
    data.hash = OBJ_nid2obj(EVP_MD_type(md));
    data.data = (ASN1_OCTET_STRING *) outmsg;
    if (data.ptype == NULL
        || data.etype == NULL
        || data.group == NULL
        || data.hash == NULL) {
        retval = ENOMEM;
        goto error;
    }

    *pa = item2padata(&msg, PAKE_MESSAGE, PA_PAKE);
    if (*pa == NULL) {
        retval = ENOMEM;
        goto error;
    }


error:
    ASN1_INTEGER_free(data.ptype);
    ASN1_INTEGER_free(data.etype);
    ASN1_OBJECT_free(data.group);
    ASN1_OBJECT_free(data.hash);
    return retval;
}

krb5_error_code
common_pake(krb5_int32 ptype, const krb5_kdc_req *request,
            const krb5_keyblock *ask, krb5_boolean kdc, const EC_GROUP *grp,
            const EVP_MD *md, const ASN1_OCTET_STRING *inmsg,
            const ASN1_OCTET_STRING *inprv, ASN1_OCTET_STRING **outmsg,
            ASN1_OCTET_STRING **outprv, EC_POINT **kek, BN_CTX *ctx)
{
    char cname[princ2str(request->client, NULL, 0) + 1];
    char sname[princ2str(request->server, NULL, 0) + 1];
    krb5_error_code retval = 0;
    pake_ctx pctx = {
        .cname = cname,
        .sname = sname,
        .kdc = kdc,
        .ctx = ctx,
        .sec = BN_bin2bn(ask->contents, ask->length, NULL),
        .grp = grp,
        .ord = make_order(grp, ctx),
        .md = md
    };

    princ2str(request->client, cname, sizeof(cname));
    princ2str(request->server, sname, sizeof(sname));

    if (pctx.sec == NULL || pctx.ord == NULL) {
        retval = ENOMEM;
        goto error;
    }

    retval = pake(ptype, &pctx, inmsg, inprv, outmsg, outprv, kek);

error:
    BN_free(pctx.sec);
    BN_free(pctx.ord);
    return retval;
}

void
common_free_padata(krb5_pa_data ***pa)
{
    if (pa == NULL)
        return;

    for (size_t i = 0; (*pa)[i] != NULL; i++) {
        free((*pa)[i]->contents);
        free((*pa)[i]);
    }

    free(*pa);
    *pa = NULL;
}
