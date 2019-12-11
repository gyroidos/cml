/* Copyright (C) 2016 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Note: The ASN.1 defines constitute an interface specification for
 * the openssl key format which may be copied by other implementations
 * as fair use regardless of licence
 */
#ifndef _TPM2_ASN_H
#define _TPM2_ASN_H

#include <openssl/asn1t.h>

/*
 * Define the format of policy commands required for TPM enhanced authorization.
 *
 * TPMPolicy ::= SEQUENCE {
 *	CommandCode		[0] EXPLICIT INTEGER
 *	CommandPolicy		[1] EXPLICIT OCTET STRING
 * }
 */
typedef struct {
	ASN1_INTEGER *CommandCode;
	ASN1_OCTET_STRING *CommandPolicy;
} TSSOPTPOLICY;

ASN1_SEQUENCE(TSSOPTPOLICY) = { ASN1_EXP(TSSOPTPOLICY, CommandCode, ASN1_INTEGER, 0),
				ASN1_EXP(TSSOPTPOLICY, CommandPolicy, ASN1_OCTET_STRING,
					 1) } ASN1_SEQUENCE_END(TSSOPTPOLICY)

	//IMPLEMENT_ASN1_FUNCTIONS(TSSOPTPOLICY);
	//IMPLEMENT_STATIC_ASN1_ALLOC_FUNCTIONS(TSSOPTPOLICY);
	IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(TSSOPTPOLICY);

#if OPENSSL_VERSION_NUMBER < 0x10100000
#define sk_TSSOPTPOLICY_new_null() SKM_sk_new_null(TSSOPTPOLICY)
#define sk_TSSOPTPOLICY_push(sk, policy) SKM_sk_push(TSSOPTPOLICY, sk, policy)
#define sk_TSSOPTPOLICY_pop(sk) SKM_sk_pop(TSSOPTPOLICY, sk)
#define sk_TSSOPTPOLICY_free(sk) SKM_sk_free(TSSOPTPOLICY, sk)
#define sk_TSSOPTPOLICY_num(policy) SKM_sk_num(TSSOPTPOLICY, policy)
#define sk_TSSOPTPOLICY_value(policy, i) SKM_sk_value(TSSOPTPOLICY, policy, i)
#else
DEFINE_STACK_OF(TSSOPTPOLICY);
#endif

/*
 * Define the format of a TPM key file.  The current format covers
 * both TPM1.2 keys as well as symmetrically encrypted private keys
 * produced by TSS2_Import and the TPM2 format public key which
 * contains things like the policy but which is cryptographically tied
 * to the private key.
 *
 * OldTPMKey ::= SEQUENCE {
 *	type		OBJECT IDENTIFIER
 *	emptyAuth	[0] EXPLICIT BOOLEAN OPTIONAL
 *	parent		[1] EXPLICIT INTEGER OPTIONAL
 *	pubkey		[2] EXPLICIT OCTET STRING OPTIONAL
 *	policy		[3] EXPLICIT SEQUENCE OF TPMPolicy OPTIONAL
 *	privkey		OCTET STRING
 * }
 *
 * This is the newer form of the key file.  It no-longer covers TPM
 * 1.2 keys and thus the parent and pubkey are no-longer optional
 *
 * TPMKey ::= SEQUENCE {
 *	type		OBJECT IDENTIFIER
 *	emptyAuth	[0] EXPLICIT BOOLEAN OPTIONAL
 *	policy		[1] EXPLICIT SEQUENCE OF TPMPolicy OPTIONAL
 *	secret		[2] EXPLICIT OCTET STRING OPTIONAL
 *	parent		INTEGER
 *	pubkey		OCTET STRING
 *	privkey		OCTET STRING
 * }
 */

typedef struct {
	ASN1_OBJECT *type;
	ASN1_BOOLEAN emptyAuth;
	ASN1_INTEGER *parent;
	ASN1_OCTET_STRING *pubkey;
	STACK_OF(TSSOPTPOLICY) * policy;
	ASN1_OCTET_STRING *privkey;
} TSSLOADABLE;

typedef struct {
	ASN1_OBJECT *type;
	ASN1_BOOLEAN emptyAuth;
	STACK_OF(TSSOPTPOLICY) * policy;
	ASN1_OCTET_STRING *secret;
	ASN1_INTEGER *parent;
	ASN1_OCTET_STRING *pubkey;
	ASN1_OCTET_STRING *privkey;
} TSSPRIVKEY;

/* the two type oids are in the TCG namespace 2.23.133; we choose an
 *  unoccupied child (10) for keytype file and two values:
 *    1 : Key that is directly loadable
 *    2 : Key that must first be imported then loaded
 *
 * the TCG actually gave us some OIDs which turn out to be different
 * from the ones we chose, so keep OID_Oldloadablekey for backwards
 * compatibility, but add the new loadable and importable key types on
 * the new OIDs
 */
#define OID_OldloadableKey "2.23.133.10.2"

#define OID_loadableKey "2.23.133.10.1.3"
#define OID_importableKey "2.23.133.10.1.4"

ASN1_SEQUENCE(TSSLOADABLE) = { ASN1_SIMPLE(TSSLOADABLE, type, ASN1_OBJECT),
			       ASN1_EXP_OPT(TSSLOADABLE, emptyAuth, ASN1_BOOLEAN, 0),
			       ASN1_EXP_OPT(TSSLOADABLE, parent, ASN1_INTEGER, 1),
			       ASN1_EXP_OPT(TSSLOADABLE, pubkey, ASN1_OCTET_STRING, 2),
			       ASN1_EXP_SEQUENCE_OF_OPT(TSSLOADABLE, policy, TSSOPTPOLICY, 3),
			       ASN1_SIMPLE(TSSLOADABLE, privkey,
					   ASN1_OCTET_STRING) } ASN1_SEQUENCE_END(TSSLOADABLE)

	//IMPLEMENT_ASN1_FUNCTIONS(TSSLOADABLE);
	//IMPLEMENT_STATIC_ASN1_ALLOC_FUNCTIONS(TSSLOADABLE);
	IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(TSSLOADABLE);

ASN1_SEQUENCE(TSSPRIVKEY) = { ASN1_SIMPLE(TSSPRIVKEY, type, ASN1_OBJECT),
			      ASN1_EXP_OPT(TSSPRIVKEY, emptyAuth, ASN1_BOOLEAN, 0),
			      ASN1_EXP_SEQUENCE_OF_OPT(TSSPRIVKEY, policy, TSSOPTPOLICY, 1),
			      ASN1_EXP_OPT(TSSPRIVKEY, secret, ASN1_OCTET_STRING, 2),
			      ASN1_SIMPLE(TSSPRIVKEY, parent, ASN1_INTEGER),
			      ASN1_SIMPLE(TSSPRIVKEY, pubkey, ASN1_OCTET_STRING),
			      ASN1_SIMPLE(TSSPRIVKEY, privkey,
					  ASN1_OCTET_STRING) } ASN1_SEQUENCE_END(TSSPRIVKEY)

	//IMPLEMENT_ASN1_FUNCTIONS(TSSPRIVKEY);
	//IMPLEMENT_STATIC_ASN1_ALLOC_FUNCTIONS(TSSPRIVKEY);
	IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(TSSPRIVKEY);

/* This is the PEM guard tag */
#define TSSLOADABLE_PEM_STRING "TSS2 KEY BLOB"
#define TSSPRIVKEY_PEM_STRING "TSS2 PRIVATE KEY"

static IMPLEMENT_PEM_write_bio(TSSLOADABLE, TSSLOADABLE, TSSLOADABLE_PEM_STRING, TSSLOADABLE) static IMPLEMENT_PEM_read_bio(
	TSSLOADABLE, TSSLOADABLE, TSSLOADABLE_PEM_STRING,
	TSSLOADABLE) static IMPLEMENT_PEM_write_bio(TSSPRIVKEY, TSSPRIVKEY, TSSPRIVKEY_PEM_STRING,
						    TSSPRIVKEY) static IMPLEMENT_PEM_read_bio(TSSPRIVKEY,
											      TSSPRIVKEY,
											      TSSPRIVKEY_PEM_STRING,
											      TSSPRIVKEY)

#endif
