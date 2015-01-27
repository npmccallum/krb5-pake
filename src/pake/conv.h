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

#include "asn1.h"

#include <openssl/bn.h>
#include <openssl/ec.h>

ASN1_OCTET_STRING *
point2os(const EC_GROUP *grp, const EC_POINT *point, BN_CTX *ctx);

EC_POINT *
os2point(const EC_GROUP *grp, const ASN1_OCTET_STRING *os, BN_CTX *ctx);

ASN1_OCTET_STRING *
bn2os(const BIGNUM *n, BN_CTX *ctx);

BIGNUM *
os2bn(const ASN1_OCTET_STRING *os, BN_CTX *ctx);

ASN1_OCTET_STRING *
item2os(void *item, const ASN1_ITEM *type);
#define item2os(item, type) item2os(item, ASN1_ITEM_rptr(type))

void *
os2item(const ASN1_OCTET_STRING *os, const ASN1_ITEM *type);
#define os2item(os, type) (type*) os2item(os, ASN1_ITEM_rptr(type))

ASN1_INTEGER *
int2integer(int i);

ASN1_OCTET_STRING *
str2os(const unsigned char *str, size_t len);
