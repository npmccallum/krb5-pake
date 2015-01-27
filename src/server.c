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

#include <krb5/kdcpreauth_plugin.h>

#include "global.h"
#include "common.h"
#include "cookie.h"
#include "kconv.h"
#include "pake/conv.h"
#include "pake/pake.h"

#include <errno.h>
#include <string.h>

struct krb5_kdcpreauth_moddata_st {
    global global;
};

typedef struct {
    ASN1_OCTET_STRING *hash;
    ASN1_OCTET_STRING *next;
    ASN1_OCTET_STRING *key;
    ASN1_OCTET_STRING *prv;
} COOKIE;

ASN1_SEQUENCE(COOKIE) = {
    ASN1_EXP_OPT(COOKIE, hash, ASN1_OCTET_STRING, 0),
    ASN1_EXP_OPT(COOKIE, next, ASN1_OCTET_STRING, 1),
    ASN1_EXP_OPT(COOKIE, key, ASN1_OCTET_STRING, 2),
    ASN1_EXP_OPT(COOKIE, prv, ASN1_OCTET_STRING, 3),
} ASN1_SEQUENCE_END(COOKIE)

IMPLEMENT_ASN1_FUNCTIONS(COOKIE)

static krb5_error_code
make_info_padata(const global *g, const krb5_keyblock *keys,
                 krb5_pa_data **pa)
{
    PAKE_MESSAGE msg = { .type = PAKE_MESSAGE_TYPE_INFO };

    /* Get the info based on the keys. */
    msg.value.info = global_info(g, keys);
    if (msg.value.info == NULL)
        return ENOTSUP;

    /* Encode the data. */
    *pa = item2padata(&msg, PAKE_MESSAGE, PA_PAKE);
    PAKE_INFO_free(msg.value.info);
    return *pa == NULL ? ENOMEM : 0;
}

static krb5_error_code
make_info_hash_cookie(const global *g, const krb5_keyblock *keys,
                      const EVP_MD *md, COOKIE **cookie)
{
    krb5_octet hbuf[EVP_MD_size(md)];
    krb5_error_code retval = 0;
    krb5_pa_data *tmp = NULL;

    retval = make_info_padata(g, keys, &tmp);
    if (retval != 0)
        return retval;

    retval = common_hash_padata(md, NULL, tmp, hbuf);
    free(tmp->contents);
    free(tmp);
    if (retval != 0)
        return retval;

    *cookie = COOKIE_new();
    if (cookie == NULL)
        return ENOMEM;

    (*cookie)->hash = str2os(hbuf, sizeof(hbuf));
    if ((*cookie)->hash == NULL) {
        COOKIE_free(*cookie);
        *cookie = NULL;
        return ENOMEM;
    }

    return 0;
}

static krb5_error_code
load_cookie(krb5_context context, const krb5_kdc_req *request,
            const krb5_keyblock *ask, COOKIE **cookie)
{
    krb5_error_code retval = 0;
    *cookie = NULL;

    for (size_t i = 0; request->padata[i] != NULL; i++) {
        const unsigned char *tmp = NULL;
        krb5_pa_data *c = NULL;

        if (request->padata[i]->pa_type != KRB5_PADATA_FX_COOKIE)
            continue;

        retval = cookie_decrypt(context, request->server, ask,
                                request->padata[i], &c);
        if (retval != 0)
            continue;

        tmp = c->contents;
        *cookie = d2i_COOKIE(NULL, &tmp, c->length);
        free(c->contents);
        free(c);
        if (*cookie == NULL)
            retval = EINVAL;
        else
            break;
    }

    return retval;
}

static krb5_error_code
verify_exchange(krb5_context context, const krb5_kdc_req *request,
                const krb5_keyblock *ask, krb5_int32 ptype,
                const EC_GROUP *grp, const EVP_MD *md, COOKIE *cookie,
                const krb5_pa_data *pa, PAKE_MESSAGE *in, krb5_pa_data ***out,
                BN_CTX *ctx)
{
    krb5_octet hbuf[EVP_MD_size(md)];
    krb5_error_code retval = 0;
    krb5_keyblock *dsk = NULL;
    krb5_pa_data *tmp = NULL;
    EC_POINT *kek = NULL;
    COOKIE c = {};

    if (cookie == NULL || cookie->hash == NULL
        || cookie->hash->length != EVP_MD_size(md))
        return EINVAL;

    /* Create the PA data array. */
    *out = calloc(3, sizeof(**out));
    if (*out == NULL) {
        retval = ENOMEM;
        goto error;
    }

    /* Hash the incoming packet. */
    retval = common_hash_padata(md, cookie->hash->data, pa, hbuf);
    if (retval != 0)
        goto error;

    /* On the first pass... */
    if (cookie->prv == NULL && cookie->next == NULL) {
        /* Perform PAKE iteration. */
        retval = common_pake(ptype, request, ask, true, grp, md, NULL, NULL,
                             &cookie->next, &cookie->prv, &kek, ctx);
        if (retval != 0)
            goto error;
    }

    /* Create the output PA data. */
    retval = common_padata(ptype, ask->enctype, grp, md,
                           PAKE_MESSAGE_TYPE_EXCHANGE,
                           cookie->next, &(*out)[0]);
    if (retval != 0)
        goto error;

    /* Hash the outgoing message. */
    retval = common_hash_padata(md, hbuf, (*out)[0], hbuf);
    if (retval != 0)
        goto error;

    /* Store the hash state in the cookie. */
    c.hash = str2os(hbuf, sizeof(hbuf));
    if (c.hash == NULL) {
        retval = ENOMEM;
        goto error;
    }

    /* Perform next PAKE iteration. */
    retval = common_pake(ptype, request, ask, true, grp, md,
                         in->value.data->data, cookie->prv,
                         &c.next, &c.prv, &kek, ctx);
    if (retval != 0)
        goto error;

    /* If the key is generated, save it for next time. */
    if (kek != NULL) {
        retval = common_derive(context, request, ask, grp, md,
                               hbuf, kek, &dsk, ctx);
        if (retval != 0)
            goto error;

        c.key = str2os(dsk->contents, dsk->length);
        if (c.key == NULL) {
            retval = ENOMEM;
            goto error;
        }
    }

    tmp = item2padata(&c, COOKIE, KRB5_PADATA_FX_COOKIE);
    if (tmp == NULL) {
        retval = ENOMEM;
        goto error;
    }

    retval = cookie_encrypt(context, request->server, ask, tmp, &(*out)[1]);
    free(tmp->contents);
    free(tmp);
    if (retval != 0)
        goto error;

    retval = KRB5KDC_ERR_MORE_PREAUTH_DATA_REQUIRED;

error:
    if (retval != KRB5KDC_ERR_MORE_PREAUTH_DATA_REQUIRED)
        common_free_padata(out);
    krb5_free_keyblock(context, dsk);
    ASN1_OCTET_STRING_free(c.hash);
    ASN1_OCTET_STRING_free(c.next);
    ASN1_OCTET_STRING_free(c.key);
    ASN1_OCTET_STRING_free(c.prv);
    EC_POINT_free(kek);
    return retval;
}

static krb5_error_code
verify_verifier(krb5_context context, const krb5_keyblock *ask,
                const EVP_MD *md, const PAKE_MESSAGE *in,
                const COOKIE *cookie, krb5_keyblock **dsk)
{
    ASN1_OCTET_STRING *verifier = NULL;
    krb5_error_code retval = 0;

    if (cookie == NULL || cookie->key == NULL
        || (size_t) cookie->key->length != ask->length)
        return EINVAL;

    /* Load the key back from the cookie. */
    retval = krb5_init_keyblock(context, ask->enctype, ask->length, dsk);
    if (retval != 0)
        return retval;
    memcpy((*dsk)->contents, cookie->key->data, cookie->key->length);

    /* Create the verifier. */
    verifier = common_verifier(md, *dsk);
    if (verifier == NULL) {
        retval = ENOMEM;
        goto error;
    }

    /* Validate the password. */
    if (ASN1_OCTET_STRING_cmp(verifier, in->value.data->data) != 0) {
        retval = KRB5KDC_ERR_PREAUTH_FAILED;
        goto error;
    }

error:
    if (retval != 0) {
        krb5_free_keyblock(context, *dsk);
        *dsk = NULL;
    }

    ASN1_OCTET_STRING_free(verifier);
    return retval;
}

static void
pake_edata(krb5_context context, krb5_kdc_req *request,
           krb5_kdcpreauth_callbacks cb, krb5_kdcpreauth_rock rock,
           krb5_kdcpreauth_moddata moddata, krb5_preauthtype pa_type,
           krb5_kdcpreauth_edata_respond_fn respond, void *arg)
{

    const global *g = &moddata->global;
    krb5_error_code retval = ENOMEM;
    krb5_pa_data *padata = NULL;
    krb5_keyblock *keys = NULL;

    /* If we have received a message, padata will be sent by pake_verify(). */
    for (size_t i = 0; request->padata[i] != NULL; i++) {
        if (request->padata[i]->pa_type == PA_PAKE) {
            (*respond)(arg, EINVAL, NULL);
            return;
        }
    }

    /* Get the key for the client. */
    retval = cb->client_keys(context, rock, &keys);
    if (retval != 0)
        goto error;

    retval = make_info_padata(g, keys, &padata);

error:
    cb->free_keys(context, rock, keys);
    (*respond)(arg, retval, padata);
}

static void
pake_verify(krb5_context context, krb5_data *req_pkt, krb5_kdc_req *request,
            krb5_enc_tkt_part *enc_tkt_reply, krb5_pa_data *pa,
            krb5_kdcpreauth_callbacks cb, krb5_kdcpreauth_rock rock,
            krb5_kdcpreauth_moddata moddata,
            krb5_kdcpreauth_verify_respond_fn respond, void *arg)
{
    const global *g = &moddata->global;
    const krb5_keyblock *ask = NULL;
    const EC_GROUP *grp = NULL;
    const EVP_MD *md = NULL;

    krb5_error_code retval = ENOMEM;
    krb5_pa_data **padata = NULL;
    krb5_keyblock *keys = NULL;
    krb5_keyblock *dsk = NULL;
    PAKE_MESSAGE *in = NULL;
    COOKIE *cookie = NULL;
    krb5_int32 ptype;

    /* Get the key. */
    retval = cb->client_keys(context, rock, &keys);
    if (retval)
        goto error;

    /* Decode the PA data. */
    in = padata2item(pa, PAKE_MESSAGE);
    switch (in == NULL ? PAKE_MESSAGE_TYPE_INFO : in->type) {
    case PAKE_MESSAGE_TYPE_EXCHANGE:
    case PAKE_MESSAGE_TYPE_VERIFIER:
        break;
    default:
        retval = EINVAL; /* Bad input. */
        goto error;
    }

    /* Setup crypto. */
    retval = global_profile(g, keys, in, &ptype, &ask, &grp, &md);
    if (retval != 0)
        goto error;

    /* Load the cookie. */
    retval = load_cookie(context, request, ask, &cookie);
    if (retval != 0) {
        /* If no cookie was found, synthesize one containing
         * the hash of the (theoretically) sent PAKE_INFO. */
        retval = make_info_hash_cookie(g, keys, md, &cookie);
        if (retval != 0)
            goto error;
    }

    switch (in->type) {
    case PAKE_MESSAGE_TYPE_EXCHANGE:
        retval = verify_exchange(context, request, ask, ptype, grp, md,
                                 cookie, pa, in, &padata, g->ctx);
        break;

    case PAKE_MESSAGE_TYPE_VERIFIER:
        retval = verify_verifier(context, ask, md, in, cookie, &dsk);
        if (retval == 0)
            enc_tkt_reply->flags |= TKT_FLG_PRE_AUTH;
        break;

    default:
        retval = EINVAL;
        break;
    }

error:
    cb->free_keys(context, rock, keys);
    COOKIE_free(cookie);
    PAKE_MESSAGE_free(in);
    (*respond)(arg, retval, (krb5_kdcpreauth_modreq) dsk, padata, NULL);
}

static krb5_error_code
pake_return_padata(krb5_context context, krb5_pa_data *padata,
                   krb5_data *req_pkt, krb5_kdc_req *request,
                   krb5_kdc_rep *reply, krb5_keyblock *encrypting_key,
                   krb5_pa_data **send_pa_out, krb5_kdcpreauth_callbacks cb,
                   krb5_kdcpreauth_rock rock, krb5_kdcpreauth_moddata moddata,
                   krb5_kdcpreauth_modreq modreq)
{
    krb5_keyblock *kb = (krb5_keyblock *) modreq;
    krb5_error_code retval;

    krb5_free_keyblock_contents(context, encrypting_key);
    retval = krb5_copy_keyblock_contents(context, kb, encrypting_key);
    krb5_free_keyblock(context, kb);
    return retval;
}


static krb5_error_code
pake_init(krb5_context context, krb5_kdcpreauth_moddata *moddata_out,
          const char **realmnames)
{
    krb5_kdcpreauth_moddata md;
    krb5_error_code retval;

    *moddata_out = calloc(1, sizeof(*md));
    if (*moddata_out == NULL)
        return ENOMEM;

    retval = global_init(&(*moddata_out)->global);
    if (retval != 0) {
        free(*moddata_out);
        return retval;
    }

    OpenSSL_add_all_digests();
    return 0;
}

static void
pake_fini(krb5_context context, krb5_kdcpreauth_moddata moddata)
{
    global_free(&moddata->global);
    free(moddata);
    EVP_cleanup();
}


static int
pake_flags(krb5_context context, krb5_preauthtype pa_type)
{
    return PA_REPLACES_KEY;
}

krb5_error_code
kdcpreauth_pake_initvt(krb5_context context, int maj_ver, int min_ver,
                       krb5_plugin_vtable vtable)
{
    static krb5_preauthtype types[] = {
        PA_PAKE,
        0
    };

    krb5_kdcpreauth_vtable vt;

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;

    vt = (krb5_kdcpreauth_vtable)vtable;
    vt->name = "pake";
    vt->pa_type_list = types;
    vt->init = pake_init;
    vt->fini = pake_fini;
    vt->flags = pake_flags;
    vt->edata = pake_edata;
    vt->verify = pake_verify;
    vt->return_padata = pake_return_padata;

    return 0;
}
