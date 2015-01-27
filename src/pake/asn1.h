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

#include <openssl/asn1t.h>

#define PA_PAKE 150      /* FIXME */
#define PA_PAKE_SPAKE 1  /* FIXME */
#define PA_PAKE_JPAKE 2  /* FIXME */


/*
 * Kerberos
 */
typedef struct {
    ASN1_INTEGER *etype;
    ASN1_INTEGER *kvno;
    ASN1_OCTET_STRING *cipher;
} KRB5_ENCRYPTED_DATA;

DECLARE_ASN1_FUNCTIONS(KRB5_ENCRYPTED_DATA)


/*
 * PAKE
 */
typedef struct {
    ASN1_INTEGER *etype;
    STACK_OF(ASN1_OBJECT) *groups;
    STACK_OF(ASN1_OBJECT) *hashes;
} PAKE_SUPPORT;

typedef struct {
    STACK_OF(ASN1_INTEGER) *ptypes;
    STACK_OF(PAKE_SUPPORT) *supports;
} PAKE_INFO;

typedef struct {
    ASN1_INTEGER *ptype;
    ASN1_INTEGER *etype;
    ASN1_OBJECT *group;
    ASN1_OBJECT *hash;
    ASN1_OCTET_STRING *data;
} PAKE_DATA;

typedef enum {
    PAKE_MESSAGE_TYPE_INFO = 0,
    PAKE_MESSAGE_TYPE_EXCHANGE = 1,
    PAKE_MESSAGE_TYPE_VERIFIER = 2,
} PAKE_MESSAGE_TYPE;

typedef struct {
    PAKE_MESSAGE_TYPE type;
    union {
        PAKE_INFO *info;
        PAKE_DATA *data;
    } value;
} PAKE_MESSAGE;

DECLARE_ASN1_FUNCTIONS(PAKE_SUPPORT)
DECLARE_ASN1_FUNCTIONS(PAKE_INFO)
DECLARE_ASN1_FUNCTIONS(PAKE_DATA)
DECLARE_ASN1_FUNCTIONS(PAKE_MESSAGE)

/*
 * JPAKE
 */
typedef struct {
    ASN1_OCTET_STRING *gv;
    ASN1_OCTET_STRING *r;
    ASN1_OCTET_STRING *x;
} JPAKE_KEY;

typedef struct {
    JPAKE_KEY *x1;
    JPAKE_KEY *x2;
} JPAKE_STEP1;

typedef enum {
    JPAKE_MESSAGE_TYPE_STEP1 = 0,
    JPAKE_MESSAGE_TYPE_STEP2 = 1,
} JPAKE_MESSAGE_TYPE;

typedef struct {
    JPAKE_MESSAGE_TYPE type;
    union {
        JPAKE_STEP1 *step1;
        JPAKE_KEY *step2;
    } value;
} JPAKE_MESSAGE;

DECLARE_ASN1_FUNCTIONS(JPAKE_KEY)
DECLARE_ASN1_FUNCTIONS(JPAKE_STEP1)
DECLARE_ASN1_FUNCTIONS(JPAKE_MESSAGE)
