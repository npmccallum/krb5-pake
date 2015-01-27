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

#pragma once

#include "global.h"
#include "pake/pake.h"

krb5_error_code
common_derive(krb5_context context, const krb5_kdc_req *request,
              const krb5_keyblock *ask, const EC_GROUP *grp,
              const EVP_MD *md, krb5_octet *phash, const EC_POINT *kek,
              krb5_keyblock **dsk, BN_CTX *ctx);

ASN1_OCTET_STRING *
common_verifier(const EVP_MD *md, const krb5_keyblock *dsk);

krb5_error_code
common_hash_padata(const EVP_MD *md, const krb5_octet *prev,
                   const krb5_pa_data *padata, krb5_octet *output);

krb5_error_code
common_padata(krb5_int32 ptype, krb5_int32 etype, const EC_GROUP *grp,
              const EVP_MD *md, PAKE_MESSAGE_TYPE mtype,
              const ASN1_OCTET_STRING *outmsg, krb5_pa_data **pa);

krb5_error_code
common_pake(krb5_int32 ptype, const krb5_kdc_req *request,
            const krb5_keyblock *ask, krb5_boolean kdc, const EC_GROUP *grp,
            const EVP_MD *md, const ASN1_OCTET_STRING *inmsg,
            const ASN1_OCTET_STRING *inprv, ASN1_OCTET_STRING **outmsg,
            ASN1_OCTET_STRING **outprv, EC_POINT **kek, BN_CTX *ctx);

void
common_free_padata(krb5_pa_data ***pa);
