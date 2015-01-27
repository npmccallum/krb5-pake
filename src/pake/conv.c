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

#include "conv.h"
#undef item2os
#undef os2item

#include <stdio.h>
#include <string.h>

ASN1_OCTET_STRING *
point2os(const EC_GROUP *grp, const EC_POINT *point, BN_CTX *ctx)
{
    ASN1_OCTET_STRING *os;
    size_t size;

    size = EC_POINT_point2oct(grp, point, POINT_CONVERSION_COMPRESSED,
                              NULL, 0, ctx);
    if (size == 0)
        return NULL;

    unsigned char buffer[size];
    if (EC_POINT_point2oct(grp, point, POINT_CONVERSION_COMPRESSED,
                           buffer, size, ctx) != size)
        return NULL;

    os = ASN1_OCTET_STRING_new();
    if (os == NULL)
        return NULL;

    if (!ASN1_OCTET_STRING_set(os, buffer, size)) {
        ASN1_OCTET_STRING_free(os);
        return NULL;
    }

    return os;
}

EC_POINT *
os2point(const EC_GROUP *grp, const ASN1_OCTET_STRING *os, BN_CTX *ctx)
{
    EC_POINT *point;

    point = EC_POINT_new(grp);
    if (point == NULL)
        return NULL;

    if (!EC_POINT_oct2point(grp, point, os->data, os->length, ctx))
        goto error;

    if (!EC_POINT_is_on_curve(grp, point, ctx))
        goto error;

    return point;

error:
    EC_POINT_free(point);
    return NULL;
}

ASN1_OCTET_STRING *
bn2os(const BIGNUM *n, BN_CTX *ctx)
{
    ASN1_OCTET_STRING *os;

    unsigned char buffer[BN_num_bytes(n)];
    BN_bn2bin(n, buffer);

    os = ASN1_OCTET_STRING_new();
    if (os == NULL)
        return NULL;

    if (!ASN1_OCTET_STRING_set(os, buffer, sizeof(buffer))) {
        ASN1_OCTET_STRING_free(os);
        return NULL;
    }

    return os;
}

BIGNUM *
os2bn(const ASN1_OCTET_STRING *os, BN_CTX *ctx)
{
    return BN_bin2bn(os->data, os->length, NULL);
}

ASN1_OCTET_STRING *
item2os(void *item, const ASN1_ITEM *type)
{
    ASN1_OCTET_STRING *os;

    os = ASN1_OCTET_STRING_new();
    if (os == NULL)
        return NULL;

    os->length = ASN1_item_i2d(item, &os->data, type);
    if (os->length < 1) {
        ASN1_OCTET_STRING_free(os);
        return NULL;
    }

    return os;
}

void *
os2item(const ASN1_OCTET_STRING *os, const ASN1_ITEM *type)
{
    const unsigned char *data = os->data;
    return ASN1_item_d2i(NULL, &data, os->length, type);
}

ASN1_INTEGER *
int2integer(int i)
{
    ASN1_INTEGER *ai;

    ai = ASN1_INTEGER_new();
    if (ai == NULL)
        return NULL;

    if (!ASN1_INTEGER_set(ai, i)) {
        ASN1_INTEGER_free(ai);
        return NULL;
    }

    return ai;
}

ASN1_OCTET_STRING *
str2os(const unsigned char *str, size_t len)
{
    ASN1_OCTET_STRING *os;

    if (len == 0)
        len = strlen((char *) str);

    os = ASN1_OCTET_STRING_new();
    if (os == NULL)
        return NULL;

    if (!ASN1_OCTET_STRING_set(os, str, len)) {
        ASN1_OCTET_STRING_free(os);
        return NULL;
    }

    return os;
}

