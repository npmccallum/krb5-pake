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

#include <krb5/clpreauth_plugin.h>

#include "global.h"
#include "common.h"
#include "kconv.h"
#include "pake/pake.h"

#include <errno.h>
#include <string.h>

struct krb5_clpreauth_moddata_st {
    krb5_octet buffer[EVP_MAX_MD_SIZE];
    ASN1_OCTET_STRING *prv;
    global global;
};

static krb5_error_code
pake_client_prep_questions(krb5_context context,
                           krb5_clpreauth_moddata moddata,
                           krb5_clpreauth_modreq modreq,
                           krb5_get_init_creds_opt *opt,
                           krb5_clpreauth_callbacks cb,
                           krb5_clpreauth_rock rock, krb5_kdc_req *request,
                           krb5_data *encoded_request_body,
                           krb5_data *encoded_previous_request,
                           krb5_pa_data *pa_data)
{
    cb->need_as_key(context, rock);
    return 0;
}

static krb5_error_code
pake_client_process(krb5_context context, krb5_clpreauth_moddata moddata,
                    krb5_clpreauth_modreq modreq, krb5_get_init_creds_opt *opt,
                    krb5_clpreauth_callbacks cb, krb5_clpreauth_rock rock,
                    krb5_kdc_req *request, krb5_data *encoded_request_body,
                    krb5_data *encoded_previous_request, krb5_pa_data *pa_data,
                    krb5_prompter_fct prompter, void *prompter_data,
                    krb5_pa_data ***pa_data_out)
{
    const ASN1_OCTET_STRING *inmsg = NULL;
    const global *g = &moddata->global;
    const krb5_octet *hbuf = NULL;
    const EC_GROUP *grp = NULL;
    const EVP_MD *md = NULL;

    ASN1_OCTET_STRING *outmsg = NULL;
    ASN1_OCTET_STRING *outprv = NULL;
    krb5_error_code retval = 0;
    krb5_keyblock *ask = NULL; /* Alias; don't free. */
    krb5_keyblock *dsk = NULL;
    PAKE_MESSAGE *in = NULL;
    EC_POINT *kek = NULL;
    krb5_int32 ptype;

    /* Create the PA data array. */
    *pa_data_out = calloc(2, sizeof(**pa_data_out));
    if (*pa_data_out == NULL) {
        goto error;
    }

    /* Get the key. */
    retval = cb->get_as_key(context, rock, &ask);
    if (retval)
        goto error;

    /* Decode the PA data. */
    in = padata2item(pa_data, PAKE_MESSAGE);
    if (in == NULL) {
        retval = EINVAL; /* Bad input. */
        goto error;
    }
    if (in->type == PAKE_MESSAGE_TYPE_EXCHANGE)
        inmsg = in->value.data->data;

    /* Setup crypto. */
    retval = global_profile(g, ask, in, &ptype, NULL, &grp, &md);
    if (retval != 0)
        goto error;

    /* Hash the incoming packet. */
    if (in->type != PAKE_MESSAGE_TYPE_INFO)
        hbuf = moddata->buffer;
    retval = common_hash_padata(md, hbuf, pa_data, moddata->buffer);
    if (retval != 0)
        goto error;

    /* Perform PAKE iteration. */
    retval = common_pake(ptype, request, ask, FALSE, grp, md, inmsg, moddata->prv,
                         &outmsg, &outprv, &kek, g->ctx);
    ASN1_OCTET_STRING_free(moddata->prv);
    moddata->prv = outprv;
    if (retval != 0)
        goto error;

    if (outmsg != NULL) {
        /* Make the output PA data. */
        retval = common_padata(ptype, ask->enctype, grp, md,
                               PAKE_MESSAGE_TYPE_EXCHANGE,
                               outmsg, &(*pa_data_out)[0]);
        if (retval != 0)
            goto error;

        /* Hash the outgoing packet. */
        retval = common_hash_padata(md, moddata->buffer,
                                    (*pa_data_out)[0],
                                    moddata->buffer);
        if (retval != 0)
            goto error;
    } else {
        if (kek == NULL) {
            retval = EINVAL;
            goto error;
        }

        /* Derive the key. */
        retval = common_derive(context, request, ask, grp, md,
                               moddata->buffer, kek, &dsk, g->ctx);
        if (retval != 0)
            goto error;

        /* Make the verifier. */
        outmsg = common_verifier(md, dsk);
        if (outmsg == NULL) {
            retval = ENOMEM;
            goto error;
        }

        /* Make the output PA data. */
        retval = common_padata(ptype, ask->enctype, grp, md,
                               PAKE_MESSAGE_TYPE_VERIFIER,
                               outmsg, &(*pa_data_out)[0]);
        if (retval != 0)
            goto error;

        retval = cb->set_as_key(context, rock, dsk);
        if (retval != 0)
            goto error;
    }

error:
    if (retval != 0)
        common_free_padata(pa_data_out);

    krb5_free_keyblock(context, dsk);
    ASN1_OCTET_STRING_free(outmsg);
    PAKE_MESSAGE_free(in);
    EC_POINT_free(kek);
    return retval;
}

static krb5_error_code
pake_init(krb5_context context, krb5_clpreauth_moddata *moddata_out)
{
    krb5_clpreauth_moddata md;
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
pake_fini(krb5_context context, krb5_clpreauth_moddata moddata)
{
    ASN1_OCTET_STRING_free(moddata->prv);
    global_free(&moddata->global);
    free(moddata);
    EVP_cleanup();
}

krb5_error_code
clpreauth_pake_initvt(krb5_context context, int maj_ver, int min_ver,
                      krb5_plugin_vtable vtable)
{
    static krb5_preauthtype types[] = {
        PA_PAKE,
        0
    };
    krb5_clpreauth_vtable vt;

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;

    vt = (krb5_clpreauth_vtable)vtable;
    vt->name = "pake";
    vt->pa_type_list = types;
    vt->init = pake_init;
    vt->fini = pake_fini;
    vt->prep_questions = pake_client_prep_questions;
    vt->process = pake_client_process;

    return 0;
}
