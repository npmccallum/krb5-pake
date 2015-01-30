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

#define _GNU_SOURCE
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sha.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define SEED_TEMPLATE "%s point generation seed (%c)"

/* Make the OID for the given group. */
static char *
make_oid(const EC_GROUP *grp)
{
    ASN1_OBJECT *obj = NULL;
    char *oid = NULL;
    int size;

    obj = OBJ_nid2obj(EC_GROUP_get_curve_name(grp));
    if (obj == NULL)
        return NULL;

    size = OBJ_obj2txt(NULL, 0, obj, 1);
    if (size != 0) {
        oid = OPENSSL_malloc(size + 1);
        if (oid != NULL) {
            if (OBJ_obj2txt(oid, size + 1, obj, 1) != size) {
                OPENSSL_free(oid);
                oid = NULL;
            }
        }
    }

    ASN1_OBJECT_free(obj);
    return oid;
}

/* Find the smallest digest that is >= the point size.
 * If the point size is larger than all digests, use the largest digest. */
static const EVP_MD *
find_digest(const EC_GROUP *grp, BN_CTX *ctx)
{
    static struct {
        size_t size;
        int nid;
    } hashes[] = {
        { SHA_DIGEST_LENGTH, NID_sha1 },
        { SHA224_DIGEST_LENGTH, NID_sha224 },
        { SHA256_DIGEST_LENGTH, NID_sha256 },
        { SHA384_DIGEST_LENGTH, NID_sha384 },
        { SHA512_DIGEST_LENGTH, NID_sha512 },
        {}
    };

    size_t size;
    int hnid;

    size = EC_POINT_point2oct(grp, EC_GROUP_get0_generator(grp),
                              POINT_CONVERSION_COMPRESSED,
                              NULL, 0, ctx);
    if (size-- == 0)
        return NULL;

    for (size_t i = 0; hashes[i].size != 0; i++) {
        hnid = hashes[i].nid;
        if (size <= hashes[i].size)
            break;
    }

    return EVP_get_digestbynid(hnid);
}

/* Try to make a point on the curve given the digest. */
static EC_POINT *
attempt(const EC_GROUP *grp, const uint8_t *digest, size_t dlen, BN_CTX *ctx)
{
    EC_POINT *p = NULL;
    BIGNUM *x = NULL;
    size_t glen;
    int y;

    if (grp == NULL || digest == NULL)
        return NULL;

    glen = EC_POINT_point2oct(grp, EC_GROUP_get0_generator(grp),
                              POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    if (glen-- == 0)
        return NULL;

    y = digest[dlen - 1] & 1; /* Last bit. */
    x = BN_bin2bn(digest, glen < dlen ? glen : dlen, NULL);
    if (x == NULL)
        return NULL;

    p = EC_POINT_new(grp);
    if (p == NULL)
        goto error;

    if (!EC_POINT_set_compressed_coordinates_GFp(grp, p, x, y, ctx)) {
        EC_POINT_free(p);
        p = NULL;
    }

error:
    BN_free(x);
    return p;
}

/* Hash the seed onto the curve. Fails after 1,000 attempts. */
static EC_POINT *
make_constant(const EC_GROUP *grp, const EVP_MD *md, const char *oid, char var,
              BN_CTX *ctx)
{
    EC_POINT *p = NULL;
    int len;

    if (grp == NULL || md == NULL || oid == NULL)
        return NULL;

    len = snprintf(NULL, 0, SEED_TEMPLATE, oid, var);
    if (len < 1)
        return NULL;

    char seed[len + 1];
    if (snprintf(seed, sizeof(seed), SEED_TEMPLATE, oid, var) != len)
        return NULL;

    uint8_t digest[EVP_MD_size(md)];
    if (!EVP_Digest(seed, strlen(seed), digest, NULL, md, NULL))
        return NULL;

    for (size_t i = 0; i < 1000 && p == NULL; i++) {
        p = attempt(grp, digest, sizeof(digest), ctx);
        EVP_Digest(digest, sizeof(digest), digest, NULL, md, NULL);
    }

    return p;
}

static bool
print_curve(void *misc, EC_builtin_curve *curve, int digest,
            const char *oid, const char *m, const char *n)
{
    if (printf("%s (%s) / %s\n",
               OBJ_nid2sn(curve->nid), oid,
               OBJ_nid2sn(digest)) < 0)
        return false;

    if (printf("\tM: %s\n", m) < 0)
        return false;

    if (printf("\tN: %s\n\n", n) < 0)
        return false;

    return true;
}

static bool
write_curve(void *misc, EC_builtin_curve *curve, int digest,
            const char *oid, const char *m, const char *n)
{
    FILE *file = misc;

    if (fprintf(file, "    { %d, /* %s (%s): %s */\n",
            curve->nid, OBJ_nid2sn(curve->nid), oid, curve->comment) < 0)
        return false;

    if (fprintf(file, "      \"%s\",\n", m) < 0)
        return false;

    if (fprintf(file, "      \"%s\" },\n\n", n) < 0)
        return false;

    return true;
}

static bool
output_curve(EC_builtin_curve *curve, BN_CTX *ctx, void *misc,
        bool (*writer)(void *misc, EC_builtin_curve *curve, int digest,
                       const char *oid, const char *m, const char *n))
{
    const EVP_MD *md = NULL;
    EC_GROUP *grp = NULL;
    EC_POINT *m = NULL;
    EC_POINT *n = NULL;
    char *hexm = NULL;
    char *hexn = NULL;
    char *oid = NULL;
    int ret = false;

    grp = EC_GROUP_new_by_curve_name(curve->nid);
    if (grp == NULL)
        goto error;

    oid = make_oid(grp);
    if (oid == NULL) {
        ret = true; /* Skip OIDless curves. */
        goto error;
    }

    md = find_digest(grp, ctx);
    if (md == NULL)
        goto error;

    m = make_constant(grp, md, oid, 'M', ctx);
    n = make_constant(grp, md, oid, 'N', ctx);
    if (m == NULL || n == NULL)
        goto error;

    hexm = EC_POINT_point2hex(grp, m, POINT_CONVERSION_COMPRESSED, ctx);
    hexn = EC_POINT_point2hex(grp, n, POINT_CONVERSION_COMPRESSED, ctx);
    if (hexm == NULL || hexn == NULL)
        goto error;

    ret = writer(misc, curve, EVP_MD_type(md), oid, hexm, hexn);

error:
    OPENSSL_free(hexn);
    OPENSSL_free(hexm);
    EC_POINT_free(n);
    EC_POINT_free(m);
    OPENSSL_free(oid);
    EC_GROUP_free(grp);
    return ret;
}

static void
write_header(FILE *file)
{
    fprintf(file, "/* This file is autogenerated: DO NOT EDIT. */\n\n");
    fprintf(file, "static const struct {\n");
    fprintf(file, "    int curve;\n");
    fprintf(file, "    const char *m;\n");
    fprintf(file, "    const char *n;\n");
    fprintf(file, "} SPAKE_CONSTANTS[] = {\n");
}

static void
write_footer(FILE *file)
{
    fprintf(file, "    {}\n");
    fprintf(file, "};\n");
}

int
main(int argc, const char **argv)
{
    BN_CTX *ctx = NULL;
    FILE *file = NULL;
    int ret = 1;

    if (argc > 2) {
        fprintf(stderr, "Usage: %s [<filename>]", argv[0]);
        return 1;
    }

    OpenSSL_add_all_algorithms();

    EC_builtin_curve curves[EC_get_builtin_curves(NULL, 0)];
    if (!EC_get_builtin_curves(curves, sizeof(curves) / sizeof(*curves)))
        return 1;

    if (argc == 2) {
        file = fopen(argv[1], "w");
        if (file == NULL) {
            fprintf(stderr, "Error opening file (%s)!", argv[1]);
            return 1;
        }

        write_header(file);
    }

    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto error;

    for (size_t i = 0; i < sizeof(curves) / sizeof(*curves); i++) {
        bool success;

        if (file == NULL)
            success = output_curve(&curves[i], ctx, NULL, print_curve);
        else
            success = output_curve(&curves[i], ctx, file, write_curve);

        if (!success) {
            fprintf(stderr, "Error writing curve (%s)!\n",
                    OBJ_nid2sn(curves[i].nid));
            goto error;
        }
    }

    if (file != NULL)
        write_footer(file);

    ret = 0;

error:
    BN_CTX_free(ctx);
    if (file != NULL)
        fclose(file);
    EVP_cleanup();
    return ret;
}
