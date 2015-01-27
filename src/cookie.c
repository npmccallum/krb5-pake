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

#include "cookie.h"
#include "pake/asn1.h"
#include "pake/conv.h"
#include "kconv.h"

#include <kdb.h>

#include <errno.h>
#include <string.h>

static krb5_error_code
make_cookie_key(krb5_context context, krb5_const_principal tgs,
                const krb5_keyblock *key, krb5_keyblock **ekey)
{
    krb5_db_entry *entry = NULL;
    krb5_key_data *kdata = NULL;
    krb5_error_code retval = 0;
    krb5_keyblock kblock = {};
    krb5_int32 start = 0;

    /* Look up the TGS principal. */
    retval = krb5_db_get_principal(context, tgs,
                                   KRB5_KDB_FLAG_ALIAS_OK, &entry);
    if (retval != 0)
        goto error;

    /* Find the key with the same enctype as the client key. */
    retval = krb5_dbe_search_enctype(context, entry, &start,
                                     key->enctype, -1, 0, &kdata);
    if (retval != 0)
        goto error;

    /* Decrypt the TGS key. */
    retval = krb5_dbe_decrypt_key_data(context, NULL, kdata, &kblock, NULL);
    if (retval != 0)
        goto error;

    /* Calculate the new key used for encrypting the cookie. */
    retval = krb5_c_fx_cf2_simple(context, &kblock,
                                  "PAKE TGS", (krb5_keyblock *) key,
                                  "PAKE Client", ekey);
    krb5_free_keyblock_contents(context, &kblock);

error:
    return retval;
}

krb5_error_code
cookie_encrypt(krb5_context context, krb5_const_principal tgs,
               const krb5_keyblock *key, const krb5_pa_data *in,
               krb5_pa_data **out)
{
    KRB5_ENCRYPTED_DATA ed = {};
    krb5_error_code retval = 0;
    krb5_keyblock *ekey = NULL;
    krb5_enc_data ct = {};
    krb5_data pt = {
        .data = (char *) in->contents,
        .length = in->length
    };
    size_t ctlen;

    if (in->pa_type != KRB5_PADATA_FX_COOKIE)
        return EINVAL;

    /* Get the key used to encrypt the cookie. */
    retval = make_cookie_key(context, tgs, key, &ekey);
    if (retval != 0)
        return retval;

    /* Find out how much buffer to allocate. */
    retval = krb5_c_encrypt_length(context, ekey->enctype,
                                   in->length, &ctlen);
    if (retval != 0) {
        krb5_free_keyblock(context, ekey);
        return retval;
    }

    /* Allocate the output buffer. */
    char buffer[ctlen];
    ct.ciphertext.length = ctlen;
    ct.ciphertext.data = buffer;

    /* Perform the encryption. */
    retval = krb5_c_encrypt(context, ekey, KRB5_KEYUSAGE_PA_FX_COOKIE,
                            NULL, &pt, &ct);
    if (retval != 0)
        return retval;

    ed.cipher = str2os((krb5_octet *) ct.ciphertext.data,
                       ct.ciphertext.length);
    ed.etype = int2integer(ct.enctype);
    ed.kvno = int2integer(0);
    if (ed.cipher == NULL || ed.etype == NULL || ed.kvno == NULL) {
        retval = ENOMEM;
        goto error;
    }

    /* Create the PA data. */
    *out = item2padata(&ed, KRB5_ENCRYPTED_DATA, KRB5_PADATA_FX_COOKIE);
    if (*out == NULL)
        goto error;

error:
    krb5_free_keyblock(context, ekey);
    ASN1_OCTET_STRING_free(ed.cipher);
    ASN1_INTEGER_free(ed.etype);
    ASN1_INTEGER_free(ed.kvno);
    return retval;

}

krb5_error_code
cookie_decrypt(krb5_context context, krb5_const_principal tgs,
               const krb5_keyblock *key, const krb5_pa_data *in,
               krb5_pa_data **out)
{
    KRB5_ENCRYPTED_DATA *ed = NULL;
    krb5_error_code retval = 0;
    krb5_keyblock *dkey = NULL;
    krb5_enc_data ct = {};
    krb5_data pt = {};

    if (in->pa_type != KRB5_PADATA_FX_COOKIE)
        return EINVAL;

    /* Parse the incoming data. */
    ed = padata2item(in, KRB5_ENCRYPTED_DATA);
    if (ed == NULL) {
        retval = EINVAL;
        goto error;
    }

    /* Get the key used to encrypt the cookie. */
    retval = make_cookie_key(context, tgs, key, &dkey);
    if (retval != 0)
        goto error;

    /* Make sure that the encrypted data has the same enctype as our key. */
    if (ASN1_INTEGER_get(ed->etype) != dkey->enctype) {
        retval = EINVAL;
        goto error;
    }

    /* Prepare input for decryption. */
    ct.enctype = ASN1_INTEGER_get(ed->etype);
    ct.ciphertext.length = ed->cipher->length;
    ct.ciphertext.data = (char *) ed->cipher->data;
    pt.length = ct.ciphertext.length;
    pt.data = malloc(pt.length);
    if (pt.data == NULL) {
        retval = ENOMEM;
        goto error;
    }

    /* Perform decryption. */
    retval = krb5_c_decrypt(context, dkey, KRB5_KEYUSAGE_PA_FX_COOKIE,
                            NULL, &ct, &pt);
    if (retval != 0)
        goto error;

    *out = calloc(1, sizeof(krb5_pa_data));
    if (*out == NULL)
        goto error;

    (*out)->contents = (krb5_octet *) pt.data;
    (*out)->length = pt.length;
    (*out)->pa_type = KRB5_PADATA_FX_COOKIE;
    pt.data = NULL;

error:
    krb5_free_keyblock(context, dkey);
    KRB5_ENCRYPTED_DATA_free(ed);
    free(pt.data);
    return retval;
}
