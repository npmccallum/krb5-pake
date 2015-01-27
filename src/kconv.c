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

#include "kconv.h"
#undef padata2item
#undef item2padata

#include <string.h>

int
princ2str(krb5_const_principal princ, char *buf, size_t len)
{
    int plen = 0;
    size_t c = 0;

    /* Calculate the length of the principal string. */
    for (krb5_int32 i = 0; i < princ->length; i++)
        plen += princ->data[i].length + 1;
    plen += princ->realm.length;

    /* If there is no buffer, return. */
    if (buf == NULL || len == 0)
        return plen;

    for (int i = 0; i < princ->length && c < len; i++) {
        if (i > 0)
            buf[c++] = '/';

        for (size_t j = 0; j < princ->data[i].length && c < len; j++)
            buf[c++] = princ->data[i].data[j];
    }

    if (c < len)
        buf[c++] = '@';

    for (size_t j = 0; j < princ->realm.length && c < len; j++)
        buf[c++] = princ->realm.data[j];

    if (c < len)
        buf[c] = '\0';

    return plen;
}


void *
padata2item(const krb5_pa_data *padata, const ASN1_ITEM *type)
{
    const krb5_octet *tmp = NULL;

    if (padata == NULL)
        return NULL;

    tmp = padata->contents;
    return ASN1_item_d2i(NULL, &tmp, padata->length, type);
}

krb5_pa_data *
item2padata(void *msg, const ASN1_ITEM *type, krb5_preauthtype patype)
{
    krb5_pa_data *pa = NULL;
    krb5_octet *tmp = NULL;
    int enclen = 0;

    enclen = ASN1_item_i2d(msg, &tmp, type);
    if (enclen < 1)
        return NULL;

    pa = calloc(1, sizeof(krb5_pa_data));
    if (pa == NULL) {
        OPENSSL_free(tmp);
        return NULL;
    }

    pa->contents = calloc(enclen, 1);
    if (pa->contents == NULL) {
        OPENSSL_free(tmp);
        free(pa);
        return NULL;
    }

    memcpy(pa->contents, tmp, enclen);
    pa->pa_type = patype;
    pa->length = enclen;

    OPENSSL_free(tmp);
    return pa;
}
