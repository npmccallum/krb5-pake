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

#include "hash.h"
#include "conv.h"

#include <stdint.h>

bool
hash_append_data(EVP_MD_CTX *md_ctx, const unsigned char *data, size_t dlen)
{
    uint64_t len;

    if (md_ctx == NULL || data == NULL)
        return false;

    len = htobe64(dlen);
    if (!EVP_DigestUpdate(md_ctx, &len, sizeof(len)))
        return false;

    return EVP_DigestUpdate(md_ctx, data, dlen);
}

bool
hash_append_point(EVP_MD_CTX *md_ctx, const EC_GROUP *grp,
                  const EC_POINT *point, BN_CTX *ctx)
{
    size_t len;

    if (grp == NULL || point == NULL)
        return false;

    len = EC_POINT_point2oct(grp, point, POINT_CONVERSION_UNCOMPRESSED,
                             NULL, 0, ctx);
    if (len == 0)
        return false;

    unsigned char buf[len];
    if (EC_POINT_point2oct(grp, point, POINT_CONVERSION_UNCOMPRESSED,
                           buf, len, ctx) != len)
        return false;

    return hash_append_data(md_ctx, buf, len);
}
