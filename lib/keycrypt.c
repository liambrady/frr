/*
 * Copyright 2020, LabN Consulting, L.L.C.
 * Copyright (C) 2008 Free Software Foundation, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "memory.h"
#include "log.h"
#include "keycrypt.h"
#include "command.h"
#include "keychain.h"
#include "libfrr.h"

DEFINE_MTYPE(LIB, KEYCRYPT_CIPHER_B64, "keycrypt base64 encoded")
DEFINE_MTYPE(LIB, KEYCRYPT_PLAIN_TEXT, "keycrypt plain text")

#if KEYCRYPT_ENABLED

/*
 * normalize backend flag names
 */
#if defined(HAVE_GNUTLS)
#define KEYCRYPT_HAVE_GNUTLS 1
#endif
#if defined(CRYPTO_OPENSSL)
#define KEYCRYPT_HAVE_OPENSSL 1
#endif

#if !defined(KEYCRYPT_HAVE_GNUTLS) && !defined(KEYCRYPT_HAVE_OPENSSL)
#error "KEYCRYPT_ENABLED set but no backend defined"
#endif

#endif /* KEYCRYPT_ENABLED */

#ifdef KEYCRYPT_HAVE_GNUTLS
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>
#endif

#ifdef KEYCRYPT_HAVE_OPENSSL
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#endif

/***********************************************************************
 *		KEYCRYPT internal definitions
 ***********************************************************************/

#define KEYFILE_NAME_PRIVATE ".ssh/frr"
#define PWENT_BUFSIZE 512

DEFINE_MTYPE_STATIC(LIB, KEYCRYPT_KEYFILE_PATH, "keycrypt keyfile path")
DEFINE_MTYPE_STATIC(LIB, KEYCRYPT_CIPHER_TEXT, "keycrypt cipher text")
DEFINE_MTYPE_STATIC(LIB, KEYCRYPT_B64DEC, "keycrypt base64 decoded")

/* don't hit disk more often than this interval: */
#define KEYCRYPT_CHECK_PKEY_SECONDS 10

/*
 * Compute path to keyfile
 *
 * Caller must free returned buffer XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, path)
 *
 * Return value is NULL on failure.
 */
static char *keycrypt_keyfile_path(void)
{
	/*
	 * get homedir
	 */
	uid_t uid = geteuid();
	struct passwd pwd;
	struct passwd *pwd_result;
	char *pbuf = XMALLOC(MTYPE_TMP, PWENT_BUFSIZE);
	int rc;
	char *path = NULL;
	size_t len_pw_dir;
	size_t len;
	const char *sep = "/";

	rc = getpwuid_r(uid, &pwd, pbuf, PWENT_BUFSIZE, &pwd_result);
	if (rc) {
		zlog_warn("%s: getpwuid_r(uid=%u): %s", __func__, uid,
			  safe_strerror(errno));
		XFREE(MTYPE_TMP, pbuf);
		return NULL;
	}

	len_pw_dir = strlen(pwd.pw_dir);
	len = len_pw_dir + 1 + strlen(KEYFILE_NAME_PRIVATE) + 1;
	path = XMALLOC(MTYPE_KEYCRYPT_KEYFILE_PATH, len);

	/* clean up one trailing slash if needed */
	if (pwd.pw_dir[len_pw_dir - 1] == '/')
		sep = "";
	snprintf(path, len, "%s%s%s", pwd.pw_dir, sep, KEYFILE_NAME_PRIVATE);
	XFREE(MTYPE_TMP, pbuf);

	return path;
}

/* clang-format off */
typedef int be_encrypt_t(
	const char	*pPlainText,
	size_t		PlainTextLen,
	char		**ppCipherTextB64,
	size_t		*pCipherTextB64Len);

typedef int be_decrypt_t(
	struct memtype	*mt,
	const char	*pCipherTextB64,
	size_t		CipherTextB64Len,
	char		**ppPlainText,
	size_t		*pPlainTextLen);

typedef int be_test_cmd_t(
	struct vty	*vty,
	const char	*cleartext);

typedef keycrypt_err_t be_keyfile_read_status_t(
	const char	*keyfile_path,
	const char	**detail);

typedef struct {
	const char			*name;
	be_encrypt_t			*f_encrypt;
	be_decrypt_t			*f_decrypt;
	be_test_cmd_t			*f_test_cmd;
	be_keyfile_read_status_t	*f_keyfile_read_status;
} keycrypt_backend_t;
/* clang-format on */

/***********************************************************************
 *		openssl-specific functions
 ***********************************************************************/

#ifdef KEYCRYPT_HAVE_OPENSSL

typedef enum {
	KEYCRYPT_FORMAT_ASN1,
	KEYCRYPT_FORMAT_PEM,
	KEYCRYPT_FORMAT_PVK,
} keycrypt_openssl_key_format_t;

/* RSA_PKCS1_OAEP_PADDING seems not to be supported by gnutls */
#define KC_OPENSSL_PADDING RSA_PKCS1_PADDING

/*
 * To generate a suitable private key, use:
 *
 *      chmod 0700 .ssh
 *      openssl genpkey -algorithm RSA -out .ssh/frr
 *      chmod 0400 .ssh/frr
 *
 * returns pointer to EVP_PKEY, or NULL. Caller must free EVP_PKEY
 * when done, via EVP_PKEY_free(pkey).
 *
 * We read only the private keyfile because:
 *  1. It contains both the private and public keys
 *  2. We need to be able to decrypt and encrypt
 */
/* clang-format off */
static keycrypt_err_t keycrypt_read_keyfile_openssl(
	const char *path,
	EVP_PKEY **ppKey)
/* clang-format on */
{
	FILE *fp;
	BIO *fb;
	EVP_PKEY *pkey = NULL;
	const char *formatstr = "";
	keycrypt_openssl_key_format_t format = KEYCRYPT_FORMAT_PEM;

	*ppKey = NULL;

	/*
	 * Use fopen() instead of BIO_new_file() so we can get meaningful
	 * error messages to the log for not-found or permission issues.
	 */
	fp = fopen(path, "r");
	if (!fp) {
		zlog_err("%s: fopen(\"%s\") failed: %s", __func__, path,
			 safe_strerror(errno));
		return KC_ERR_KEYFILE_READ;
	}

	fb = BIO_new_fp(fp, BIO_CLOSE);
	if (!fb) {
		fclose(fp);
		zlog_err("%s: BIO_new_fp() failed", __func__);
		return KC_ERR_KEYFILE_READ;
	}

	switch (format) {
	case KEYCRYPT_FORMAT_ASN1:
		pkey = d2i_PrivateKey_bio(fb, NULL);
		formatstr = "ASN1";
		break;
	case KEYCRYPT_FORMAT_PEM:
		pkey = PEM_read_bio_PrivateKey(fb, NULL, NULL, NULL);
		formatstr = "PEM";
		break;
	case KEYCRYPT_FORMAT_PVK:
		pkey = b2i_PVK_bio(fb, NULL, NULL);
		formatstr = "PVK";
		break;
	default:
		zlog_err("%s: unknown format %u: not supported", __func__,
			 format);
	}

	BIO_free(fb);

	if (!pkey)
		zlog_err(
			"%s: unable to load format \"%s\" key from file \"%s\"",
			__func__, formatstr, path);

	*ppKey = pkey;
	return 0;
}

/*
 * Caller must free result XFREE(MTYPE_KEYCRYPT_CIPHER_B64, *pOut)
 */
static void keycrypt_base64_encode_openssl(const char *pIn, size_t InLen,
					   char **ppOut, size_t *pOutLen)
{
	BIO *bio_b64;
	BIO *bio_mem;
	BUF_MEM *obufmem;

	bio_mem = BIO_new(BIO_s_mem());
	bio_b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_push(bio_b64, bio_mem);
	BIO_write(bio_b64, pIn, InLen);

	/* NetBSD 8 openssl BIO_flush() returns int */
	(void)BIO_flush(bio_b64);

	BIO_get_mem_ptr(bio_mem, &obufmem);
	*ppOut = XMALLOC(MTYPE_KEYCRYPT_CIPHER_B64, obufmem->length + 1);
	memcpy(*ppOut, obufmem->data, obufmem->length);
	*((*ppOut) + obufmem->length) = 0; /* NUL-terminate */
	*pOutLen = obufmem->length;

	BIO_free_all(bio_b64);
}

/*
 * Caller must free result XFREE(MTYPE_KEYCRYPT_B64DEC, *pOut)
 */
static void keycrypt_base64_decode_openssl(const char *pIn, size_t InLen,
					   char **ppOut, size_t *pOutLen)
{
	BIO *bio_b64;
	BIO *bio_mem;
	BIO *bio_omem;
	BUF_MEM *obufmem;
	char inbuf[512];
	int inlen;

	/*
	 * Debian 8, Ubuntu 14.04 openssl
	 * BIO_new_mem_buf() discards const from 1st arg
	 */
	bio_mem = BIO_new_mem_buf((void *)pIn, InLen);
	bio_b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_push(bio_b64, bio_mem);

	bio_omem = BIO_new(BIO_s_mem());

	while ((inlen = BIO_read(bio_b64, inbuf, sizeof(inbuf))) > 0)
		BIO_write(bio_omem, inbuf, inlen);

	/* NetBSD 8 openssl BIO_flush() returns int */
	(void)BIO_flush(bio_omem);
	BIO_free_all(bio_b64);

	BIO_get_mem_ptr(bio_omem, &obufmem);
	*ppOut = XMALLOC(MTYPE_KEYCRYPT_B64DEC, obufmem->length + 1);
	memcpy(*ppOut, obufmem->data, obufmem->length);
	*((*ppOut) + obufmem->length) = 0; /* NUL-terminate */
	*pOutLen = obufmem->length;

	BIO_free_all(bio_omem);
}

/*
 * Encrypt provided plain text.
 *
 * Returns dynamically-allocated cipher text, which caller must
 * free via XFREE(KEYCRYPT_CIPHER_TEXT, pCipherText)
 *
 * Return value is 0 if successful, non-0 for error
 *
 * NOTE: RSA encryption has a cleartext size limit slightly less
 * (11 bits => 2 bytes?) than the key size.
 */
/* clang-format off */
static int keycrypt_encrypt_internal_openssl(
	EVP_PKEY	*pKey,				/* IN */
	struct memtype	*mt,	/* of CipherText */	/* IN */
	const char	*pPlainText,			/* IN */
	size_t		PlainTextLen,			/* IN */
	char		**ppCipherText,			/* OUT */
	size_t		*pCipherTextLen)		/* OUT */
/* clang-format on */
{
	EVP_PKEY_CTX *ctx;
	ENGINE *eng = NULL; /* default RSA impl */
	int rc;

	ctx = EVP_PKEY_CTX_new(pKey, eng);
	if (!ctx) {
		zlog_warn("%s: unable to alloc context", __func__);
		return -1;
	}

	rc = EVP_PKEY_encrypt_init(ctx);
	if (rc <= 0) {
		EVP_PKEY_CTX_free(ctx);
		zlog_warn("%s: Error: EVP_PKEY_encrypt_init%s", __func__,
			  ((rc == -2) ? ": not supported by public key alg"
				      : ""));
		return -1;
	}

	rc = EVP_PKEY_CTX_set_rsa_padding(ctx, KC_OPENSSL_PADDING);
	if (rc <= 0) {
		EVP_PKEY_CTX_free(ctx);
		zlog_warn("%s: Error: EVP_PKEY_CTX_set_rsa_padding%s", __func__,
			  ((rc == -2) ? ": not supported by public key alg"
				      : ""));
		return -1;
	}

	/* Determine buffer length */
	rc = EVP_PKEY_encrypt(ctx, NULL, pCipherTextLen,
			      (const u_char *)pPlainText, PlainTextLen);
	if (rc <= 0) {
		EVP_PKEY_CTX_free(ctx);
		zlog_warn("%s: Error: EVP_PKEY_encrypt (1)%s", __func__,
			  ((rc == -2) ? ": not supported by public key alg"
				      : ""));
		return -1;
	}

	*ppCipherText = XMALLOC(mt, *pCipherTextLen);

	rc = EVP_PKEY_encrypt(ctx, (u_char *)*ppCipherText, pCipherTextLen,
			      (const u_char *)pPlainText, PlainTextLen);
	if (rc <= 0) {
		EVP_PKEY_CTX_free(ctx);
		XFREE(mt, *ppCipherText);
		zlog_warn("%s: Error: EVP_PKEY_encrypt (2)%s", __func__,
			  ((rc == -2) ? ": not supported by public key alg"
				      : ""));
		return -1;
	}

	EVP_PKEY_CTX_free(ctx);

	return 0;
}


/*
 * Decrypt provided cipher text.
 *
 * Returns dynamically-allocated plain text, which caller must
 * free via XFREE(KEYCRYPT_PLAIN_TEXT, pPlainText)
 *
 * Return value is 0 if successful, non-0 for error
 */
/* clang-format off */
static int keycrypt_decrypt_internal_openssl(
	EVP_PKEY	*pKey,				/* IN */
	struct memtype	*mt,	/* of PlainText */	/* IN */
	const char	*pCipherText,			/* IN */
	size_t		CipherTextLen,			/* IN */
	char		**ppPlainText,			/* OUT */
	size_t		*pPlainTextLen)			/* OUT */
/* clang-format on */
{
	EVP_PKEY_CTX *ctx;
	ENGINE *eng = NULL; /* default RSA impl */
	int rc;

	ctx = EVP_PKEY_CTX_new(pKey, eng);
	if (!ctx) {
		zlog_warn("%s: unable to alloc context", __func__);
		return -1;
	}

	rc = EVP_PKEY_decrypt_init(ctx);
	if (rc <= 0) {
		EVP_PKEY_CTX_free(ctx);
		zlog_warn("%s: Error: EVP_PKEY_decrypt_init%s", __func__,
			  ((rc == -2) ? ": not supported by public key alg"
				      : ""));
		return -1;
	}

	rc = EVP_PKEY_CTX_set_rsa_padding(ctx, KC_OPENSSL_PADDING);
	if (rc <= 0) {
		EVP_PKEY_CTX_free(ctx);
		zlog_warn("%s: Error: EVP_PKEY_CTX_set_rsa_padding%s", __func__,
			  ((rc == -2) ? ": not supported by public key alg"
				      : ""));
		return -1;
	}

	/* Determine buffer length */
	rc = EVP_PKEY_decrypt(ctx, NULL, pPlainTextLen,
			      (const u_char *)pCipherText, CipherTextLen);
	if (rc <= 0) {
		EVP_PKEY_CTX_free(ctx);
		zlog_warn("%s: Error: EVP_PKEY_decrypt (1)%s", __func__,
			  ((rc == -2) ? ": not supported by public key alg"
				      : ""));
		return -1;
	}

	*ppPlainText = XMALLOC(mt, *pPlainTextLen + 1);

	rc = EVP_PKEY_decrypt(ctx, (u_char *)*ppPlainText, pPlainTextLen,
			      (const u_char *)pCipherText, CipherTextLen);
	if (rc <= 0) {
		EVP_PKEY_CTX_free(ctx);
		if (*ppPlainText)
			XFREE(mt, *ppPlainText);
		zlog_warn(
			"%s: EVP_PKEY_decrypt (2) CipherTextLen %zu, PlainTextLen %zu",
			__func__, CipherTextLen, *pPlainTextLen);
		zlog_warn("%s: Error: EVP_PKEY_decrypt (2)%s", __func__,
			  ((rc == -2) ? ": not supported by public key alg"
				      : ""));
		return -1;
	}
	(*ppPlainText)[*pPlainTextLen] = '\0';

	EVP_PKEY_CTX_free(ctx);

	return 0;
}

/*
 * Allocates an EVP_PKEY which should later be freed via EVP_PKEY_free()
 */
static keycrypt_err_t keycrypt_read_default_keyfile_openssl(EVP_PKEY **ppKey)
{
	char *keyfile_path;
	keycrypt_err_t	krc;

	*ppKey = NULL;

	keyfile_path = keycrypt_keyfile_path();
	if (!keyfile_path) {
		zlog_err("%s: Error: can't compute keyfile path\n", __func__);
		return KC_ERR_KEYFILE_PATH;
	}

	krc = keycrypt_read_keyfile_openssl(keyfile_path, ppKey);
	if (krc) {
		zlog_err("%s: Error: %s can't read \"%s\"\n",
			 __func__, "keycrypt_read_keyfile_openssl",
			 keyfile_path);
		XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);
		return KC_ERR_KEYFILE_READ;
	}
	XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);
	return KC_OK;
}

/*
 * Caller should not free returned key
 */
static EVP_PKEY *keycrypt_get_pkey_openssl()
{
	static time_t keycrypt_pkey_check_time;
	static EVP_PKEY *keycrypt_cached_pkey;

	time_t now;

	now = monotime(NULL);
	if (now - keycrypt_pkey_check_time > KEYCRYPT_CHECK_PKEY_SECONDS) {
		EVP_PKEY *pKey;
		keycrypt_err_t rc;

		keycrypt_pkey_check_time = now;

		rc = keycrypt_read_default_keyfile_openssl(&pKey);
		if (rc != KC_OK)
			goto end;

		if (keycrypt_cached_pkey)
			EVP_PKEY_free(keycrypt_cached_pkey);

		keycrypt_cached_pkey = pKey;
	}
end:
	return keycrypt_cached_pkey;
}

/*
 * After successful return (0), caller MUST free base-64 encoded
 * cipher text via XFREE(MTYPE_KEYCRYPT_CIPHER_B64, ptr)
 */
/* clang-format off */
static int keycrypt_encrypt_openssl(
	const char	*pPlainText,		/* IN */
	size_t		PlainTextLen,		/* IN */
	char		**ppCipherTextB64,	/* OUT */
	size_t		*pCipherTextB64Len)	/* OUT */
/* clang-format on */
{
	EVP_PKEY *pKey;
	int rc;
	char *pCipherTextRaw;
	size_t CipherTextRawLen;
	size_t B64len;

	pKey = keycrypt_get_pkey_openssl();
	if (!pKey)
		return -1;

	rc = keycrypt_encrypt_internal_openssl(
		pKey, MTYPE_KEYCRYPT_CIPHER_TEXT, pPlainText, PlainTextLen,
		&pCipherTextRaw, &CipherTextRawLen);
	if (rc)
		return -1;

	keycrypt_base64_encode_openssl(pCipherTextRaw, CipherTextRawLen,
				       ppCipherTextB64, &B64len);

	if (pCipherTextB64Len)
		*pCipherTextB64Len = B64len;

	XFREE(MTYPE_KEYCRYPT_CIPHER_TEXT, pCipherTextRaw);

	return 0;
}

/* clang-format off */
static int keycrypt_decrypt_openssl(
	struct memtype	*mt,	/* of PlainText */	/* IN */
	const char	*pCipherTextB64,		/* IN */
	size_t		CipherTextB64Len,		/* IN */
	char		**ppPlainText,			/* OUT */
	size_t		*pPlainTextLen)			/* OUT */
/* clang-format on */
{
	EVP_PKEY *pKey;
	int rc;
	char *pCipherTextRaw;
	size_t CipherTextRawLen;
	size_t PlainTextLen;

	pKey = keycrypt_get_pkey_openssl();
	if (!pKey)
		return -1;

	keycrypt_base64_decode_openssl(pCipherTextB64, CipherTextB64Len,
				       &pCipherTextRaw, &CipherTextRawLen);

	rc = keycrypt_decrypt_internal_openssl(pKey, mt, pCipherTextRaw,
					       CipherTextRawLen, ppPlainText,
					       &PlainTextLen);

	XFREE(MTYPE_KEYCRYPT_B64DEC, pCipherTextRaw);

	if (rc)
		return -1;

	if (pPlainTextLen)
		*pPlainTextLen = PlainTextLen;

	return 0;
}

static int debug_keycrypt_test_cmd_openssl(struct vty *vty,
					   const char *cleartext)
{
	char *keyfile_path = NULL;
	EVP_PKEY *pKey;
	int rc;
	char *pCipherText = NULL;
	size_t CipherTextLen;
	char *pClearText = NULL;
	size_t ClearTextLen;
	char *pB64Text;
	size_t B64TextLen;
	keycrypt_err_t krc;

	keyfile_path = keycrypt_keyfile_path();
	if (!keyfile_path) {
		vty_out(vty, "%s: Error: can't compute keyfile path\n",
			__func__);
		return CMD_SUCCESS;
	}

	krc = keycrypt_read_keyfile_openssl(keyfile_path, &pKey);
	if (krc) {
		vty_out(vty, "%s: Error: %s\n", __func__,
			"keycrypt_read_keyfile_openssl");
		XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);
		return CMD_SUCCESS;
	}
	XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);

	rc = keycrypt_encrypt_internal_openssl(pKey, MTYPE_KEYCRYPT_CIPHER_TEXT,
					       cleartext, strlen(cleartext),
					       &pCipherText, &CipherTextLen);
	if (rc) {
		EVP_PKEY_free(pKey);
		vty_out(vty, "%s: Error: keycrypt_encrypt_internal_openssl\n",
			__func__);
		return CMD_SUCCESS;
	}

	if (!pCipherText) {
		vty_out(vty, "%s: missing cipher text\n", __func__);
		return CMD_SUCCESS;
	}

	/*
	 * Encode for printing
	 */

	keycrypt_base64_encode_openssl(pCipherText, CipherTextLen, &pB64Text,
				       &B64TextLen);

	XFREE(MTYPE_KEYCRYPT_CIPHER_TEXT, pCipherText);

	vty_out(vty,
		"INFO: clear text len: %zu, CipherTextLen: %zu, B64TextLen %zu\n",
		strlen(cleartext), CipherTextLen, B64TextLen);

	vty_out(vty, "INFO: base64 cipher text:\n%s\n", pB64Text);


	/*
	 * Decode back to binary
	 */
	keycrypt_base64_decode_openssl(pB64Text, B64TextLen, &pCipherText,
				       &CipherTextLen);

	XFREE(MTYPE_KEYCRYPT_CIPHER_B64, pB64Text);

	vty_out(vty, "INFO: After B64 decode, CipherTextLen: %zu\n",
		CipherTextLen);


	rc = keycrypt_decrypt_internal_openssl(pKey, MTYPE_KEYCRYPT_PLAIN_TEXT,
					       pCipherText, CipherTextLen,
					       &pClearText, &ClearTextLen);

	EVP_PKEY_free(pKey);

	if (pCipherText) {
		if (!strncmp(cleartext, pCipherText, strlen(cleartext))) {
			vty_out(vty,
				"%s: cipher text and cleartext same for %zu chars\n",
				__func__, strlen(cleartext));
			XFREE(MTYPE_KEYCRYPT_B64DEC, pCipherText);
			if (pClearText)
				XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, pClearText);
			return CMD_SUCCESS;
		}
		XFREE(MTYPE_KEYCRYPT_B64DEC, pCipherText);
	}

	if (rc) {
		vty_out(vty, "%s: Error: keycrypt_decrypt_internal_openssl\n",
			__func__);
		if (pClearText)
			XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, pClearText);
		return CMD_SUCCESS;
	}

	if (!pClearText) {
		vty_out(vty,
			"%s: keycrypt_decrypt_internal_openssl didn't return clear text pointer\n",
			__func__);
		return CMD_SUCCESS;
	}
	if (strlen(cleartext) != ClearTextLen) {
		vty_out(vty,
			"%s: decrypted ciphertext length (%zu) != original length (%lu)\n",
			__func__, ClearTextLen, strlen(cleartext));
		XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, pClearText);
		return CMD_SUCCESS;
	}

	if (strncmp(cleartext, pClearText, ClearTextLen)) {
		vty_out(vty,
			"%s: decrypted ciphertext differs from original text\n",
			__func__);
		XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, pClearText);
		return CMD_SUCCESS;
	}

	vty_out(vty, "OK: decrypted ciphertext matches original text\n");
	return CMD_SUCCESS;
}

static keycrypt_err_t keyfile_read_status_openssl(const char *keyfile_path,
						  const char **detail)
{
	keycrypt_err_t krc;
	EVP_PKEY *pKey;

	*detail = NULL;

	krc = keycrypt_read_keyfile_openssl(keyfile_path, &pKey);
	if (krc)
		*detail = keycrypt_strerror(krc);
	else
		EVP_PKEY_free(pKey);

	return krc;
}

/* clang-format off */
keycrypt_backend_t kbe_openssl = {
	.name			= "openssl",
	.f_encrypt		= keycrypt_encrypt_openssl,
	.f_decrypt		= keycrypt_decrypt_openssl,
	.f_test_cmd		= debug_keycrypt_test_cmd_openssl,
	.f_keyfile_read_status	= keyfile_read_status_openssl,
};
/* clang-format on */

#endif /* KEYCRYPT_HAVE_OPENSSL */


/***********************************************************************
 *		gnutls-specific functions
 ***********************************************************************/

#if defined KEYCRYPT_HAVE_GNUTLS

/*
 * If successful (return value is 0), allocates and fills in
 * private key structure. Caller is responsible for calling
 * gnutls_x509_privkey_deinit() to free private key structure
 */
/* clang-format off */
static keycrypt_err_t keycrypt_read_keyfile_gnutls(
	const char		*filename,
	/* gnutls_x509_privkey_t is a pointer to key struct */
	gnutls_x509_privkey_t	*ppPrivKey)	/* ptr to caller's ptr */
/* clang-format on */
{
	int rc;
	gnutls_datum_t data;

	rc = gnutls_load_file(filename, &data);
	if (rc) {
		zlog_err("%s: error: gnutls_load_file(\"%s\") returned %d: %s ",
			 __func__, filename, rc, gnutls_strerror(rc));
		return KC_ERR_KEYFILE_READ;
	}

	/*
	 * Allocates structure and saves ptr in *ppPrivKey
	 */
	rc = gnutls_x509_privkey_init(ppPrivKey);
	if (rc < 0) {
		zlog_err("%s: %s returned error %d: %s\n", __func__,
			 "gnutls_x509_privkey_init", rc, gnutls_strerror(rc));
		return KC_ERR_MEMORY;
	}
	rc = gnutls_x509_privkey_import2(*ppPrivKey, &data, GNUTLS_X509_FMT_PEM,
					 NULL /* password */,
					 GNUTLS_PKCS_PLAIN);
	free(data.data);
	if (rc < 0) {
		zlog_err("%s: %s returned error %d: %s\n", __func__,
			 "gnutls_x509_privkey_import2", rc,
			 gnutls_strerror(rc));
		gnutls_x509_privkey_deinit(*ppPrivKey); /* frees structure */
		return KC_ERR_KEYFILE_PARSE;
	}
	return KC_OK;
}

/*
 * Allocates a *gnutls_x509_privkey_t  which should later be
 * freed via gnutls_x509_privkey_deinit()
 */
static keycrypt_err_t
keycrypt_read_default_keyfile_gnutls(gnutls_x509_privkey_t *ppPrivKey)
{
	keycrypt_err_t rc;
	char *keyfile_path;

	*ppPrivKey = NULL;

	keyfile_path = keycrypt_keyfile_path();
	if (!keyfile_path) {
		zlog_err("%s: Error: can't compute keyfile path\n", __func__);
		return KC_ERR_KEYFILE_PATH;
	}

	rc = keycrypt_read_keyfile_gnutls(keyfile_path, ppPrivKey);
	if (rc) {
		zlog_err("%s: Error: %s can't read \"%s\"\n", __func__,
			 "keycrypt_read_keyfile_gnutls", keyfile_path);
		XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);
		return rc;
	}

	XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);
	return KC_OK;
}

/*
 * Caller should not free returned key
 */
static gnutls_x509_privkey_t keycrypt_get_pkey_gnutls()
{
	static time_t keycrypt_pkey_check_time;
	static gnutls_x509_privkey_t
		keycrypt_cached_pkey_gnutls; /* type is ptr */
	time_t now;

	now = monotime(NULL);
	if (now - keycrypt_pkey_check_time > KEYCRYPT_CHECK_PKEY_SECONDS) {
		gnutls_x509_privkey_t pKey;
		keycrypt_err_t rc;

		keycrypt_pkey_check_time = now;

		rc = keycrypt_read_default_keyfile_gnutls(&pKey);
		if (rc != KC_OK)
			goto end;

		if (keycrypt_cached_pkey_gnutls)
			gnutls_x509_privkey_deinit(keycrypt_cached_pkey_gnutls);

		keycrypt_cached_pkey_gnutls = pKey;
	}
end:
	return keycrypt_cached_pkey_gnutls;
}

/* clang-format off */
typedef enum {
	GT_DATUM_M = 0,
	GT_DATUM_E,
	GT_DATUM_D,
	GT_DATUM_P,
	GT_DATUM_Q,
	GT_DATUM_U,
	GT_DATUM_E1,
	GT_DATUM_E2,
	N_GT_DATA
} kc_gt_privdata_params_t;

static int keycrypt_encrypt_internal_gnutls(
	gnutls_x509_privkey_t	pPrivKey,			/* IN */
	struct memtype		*mt,	/* of CipherText */	/* IN */
	const char		*pPlainText,			/* IN */
	size_t			PlainTextLen,			/* IN */
	char			**ppCipherText,			/* OUT */
	size_t			*pCipherTextLen)		/* OUT */
{
	int			rc;
	gnutls_datum_t		d[N_GT_DATA];
	gnutls_pubkey_t		pPubKey;
	kc_gt_privdata_params_t	i;
	/* clang-format on */

	for (i = GT_DATUM_M; i < N_GT_DATA; ++i)
		d[i].data = NULL;

	/*
	 * Derive public key from private key
	 */
	/* clang-format off */
	rc = gnutls_x509_privkey_export_rsa_raw(pPrivKey,
		d+GT_DATUM_M,
		d+GT_DATUM_E,
		d+GT_DATUM_D,
		d+GT_DATUM_P,
		d+GT_DATUM_Q,
		d+GT_DATUM_U);
	/* clang-format on */
	if (rc) {
		zlog_err("%s: error: %s returned %d: %s", __func__,
			 "gnutls_privkey_export_rsa_raw", rc,
			 gnutls_strerror(rc));
		return KC_ERR_ENCRYPT;
	}

	gnutls_pubkey_init(&pPubKey);

	rc = gnutls_pubkey_import_rsa_raw(pPubKey, d + GT_DATUM_M,
					  d + GT_DATUM_E);

	/*
	 * gnutls documentation is not clear on need to keep data components
	 * allocated during lifetime of public key
	 */
	for (i = GT_DATUM_M; i < N_GT_DATA; ++i) {
		if (d[i].data)
			gnutls_free(d[i].data);
	}

	if (rc) {
		zlog_err("%s: error: %s returned %d: %s", __func__,
			 "gnutls_pubkey_import_rsa_raw", rc,
			 gnutls_strerror(rc));
		gnutls_pubkey_deinit(pPubKey);
		return KC_ERR_ENCRYPT;
	}

	gnutls_datum_t datum_plaintext;
	gnutls_datum_t datum_ciphertext;

	datum_plaintext.data = (unsigned char *)pPlainText;
	datum_plaintext.size = PlainTextLen;

	rc = gnutls_pubkey_encrypt_data(pPubKey, 0, &datum_plaintext,
					&datum_ciphertext);
	gnutls_pubkey_deinit(pPubKey);
	if (rc) {
		zlog_err("%s: error: %s returned %d: %s", __func__,
			 "gnutls_pubkey_encrypt_data", rc, gnutls_strerror(rc));
		return KC_ERR_ENCRYPT;
	}
	*pCipherTextLen = datum_ciphertext.size;
	*ppCipherText = XMALLOC(mt, datum_ciphertext.size);
	memcpy(*ppCipherText, datum_ciphertext.data, datum_ciphertext.size);

	gnutls_free(datum_ciphertext.data);

	return 0;
}

/*
 * Decrypt provided cipher text.
 *
 * Returns dynamically-allocated plain text, which caller must
 * free via XFREE(KEYCRYPT_PLAIN_TEXT, pPlainText)
 *
 * Return value is 0 if successful, non-0 for error
 */
/* clang-format off */
static int keycrypt_decrypt_internal_gnutls(
	gnutls_x509_privkey_t	pX509PrivKey,			/* IN */
	struct memtype		*mt,	/* of PlainText */	/* IN */
	const char		*pCipherText,			/* IN */
	size_t			CipherTextLen,			/* IN */
	char			**ppPlainText,			/* OUT */
	size_t			*pPlainTextLen)			/* OUT */
{
	gnutls_datum_t		datum_ciphertext;
	gnutls_datum_t		datum_plaintext;
	gnutls_privkey_t	pPrivKey;
	int		rc;
	/* clang-format on */

	/*
	 * make a generic private key
	 */
	rc = gnutls_privkey_init(&pPrivKey);
	if (rc) {
		zlog_err("%s: error: %s returned %d: %s", __func__,
			 "gnutls_privkey_init", rc, gnutls_strerror(rc));
		return KC_ERR_DECRYPT;
	}
	rc = gnutls_privkey_import_x509(pPrivKey, pX509PrivKey, 0);
	if (rc) {
		zlog_err("%s: error: %s returned %d: %s", __func__,
			 "gnutls_privkey_import_x509", rc, gnutls_strerror(rc));
		return KC_ERR_DECRYPT;
	}

	datum_ciphertext.data = (unsigned char *)pCipherText;
	datum_ciphertext.size = CipherTextLen;

	rc = gnutls_privkey_decrypt_data(pPrivKey, 0, &datum_ciphertext,
					 &datum_plaintext);
	gnutls_privkey_deinit(pPrivKey);
	if (rc) {
		zlog_err("%s: error: %s returned %d: %s", __func__,
			 "gnutls_privkey_decrypt_data", rc,
			 gnutls_strerror(rc));
		zlog_err(
			"%s: datum_ciphertext.data %p, datum_ciphertext.size %u",
			__func__, datum_ciphertext.data, datum_ciphertext.size);
		return KC_ERR_DECRYPT;
	}
	*pPlainTextLen = datum_plaintext.size;
	*ppPlainText = XMALLOC(mt, datum_plaintext.size + 1);
	memcpy(*ppPlainText, datum_plaintext.data, datum_plaintext.size);
	(*ppPlainText)[*pPlainTextLen] = '\0';

	gnutls_free(datum_plaintext.data);

	return 0;
}


/*
 * Caller must free result XFREE(MTYPE_KEYCRYPT_CIPHER_B64, *pOut)
 */
/* clang-format off */
static keycrypt_err_t keycrypt_base64_encode_gnutls(
	const char	*pIn,
	size_t		InLen,
	char		**ppOut,
	size_t		*pOutLen)
{
	gnutls_datum_t	d_raw;
	gnutls_datum_t	d_b64;
	int		rc;
	/* clang-format on */

	d_raw.data = (unsigned char *)pIn;
	d_raw.size = InLen;

	rc = gnutls_base64_encode2(&d_raw, &d_b64);
	if (rc) {
		zlog_err("%s: error: %s returned %d: %s", __func__,
			 "gnutls_base64_encode2", rc, gnutls_strerror(rc));
		return KC_ERR_BASE64;
	}

	*ppOut = XMALLOC(MTYPE_KEYCRYPT_CIPHER_B64, d_b64.size + 1);
	memcpy(*ppOut, d_b64.data, d_b64.size);
	*(*ppOut + d_b64.size) = '\0';
	*pOutLen = d_b64.size;
	gnutls_free(d_b64.data);
	return 0;
}

/*
 * Caller must free result XFREE(MTYPE_KEYCRYPT_B64DEC, *pOut)
 */
/* clang-format off */
static keycrypt_err_t keycrypt_base64_decode_gnutls(
	const char	*pIn,
	size_t		InLen,
	char		**ppOut,
	size_t		*pOutLen)
{
	gnutls_datum_t	d_raw;
	gnutls_datum_t	d_b64;
	int		rc;
	/* clang-format on */

	d_b64.data = (unsigned char *)pIn;
	d_b64.size = InLen;

	rc = gnutls_base64_decode2(&d_b64, &d_raw);
	if (rc) {
		zlog_err("%s: error: %s returned %d: %s", __func__,
			 "gnutls_base64_decode2", rc, gnutls_strerror(rc));
		zlog_err("%s: d_b64.data %p, d_b64.size %u", __func__,
			 d_b64.data, d_b64.size);
		return KC_ERR_BASE64;
	}

	*ppOut = XMALLOC(MTYPE_KEYCRYPT_B64DEC, d_raw.size + 1);
	memcpy(*ppOut, d_raw.data, d_raw.size);
	*(*ppOut + d_raw.size) = '\0';
	*pOutLen = d_raw.size;
	gnutls_free(d_raw.data);
	return 0;
}

/*
 * After successful return (0), caller MUST free base-64 encoded
 * cipher text via XFREE(MTYPE_KEYCRYPT_CIPHER_B64, ptr)
 */
/* clang-format off */
static int keycrypt_encrypt_gnutls(
	const char	*pPlainText,		/* IN */
	size_t		PlainTextLen,		/* IN */
	char		**ppCipherTextB64,	/* OUT */
	size_t		*pCipherTextB64Len)	/* OUT */
{
	gnutls_x509_privkey_t	pKey;
	int			rc;
	keycrypt_err_t		krc;
	char			*pCipherTextRaw;
	size_t			CipherTextRawLen = 0;
	size_t			B64len = 0;
	/* clang-format on */

	pKey = keycrypt_get_pkey_gnutls();
	if (!pKey)
		return -1;

	rc = keycrypt_encrypt_internal_gnutls(
		pKey, MTYPE_KEYCRYPT_CIPHER_TEXT, pPlainText, PlainTextLen,
		&pCipherTextRaw, &CipherTextRawLen);
	if (rc)
		return -1;

	krc = keycrypt_base64_encode_gnutls(pCipherTextRaw, CipherTextRawLen,
					    ppCipherTextB64, &B64len);

	if (krc) {
		zlog_err("%s: %s returned %d: %s", __func__,
			 "keycrypt_base64_encode_gnutls", krc,
			 keycrypt_strerror(krc));
		XFREE(MTYPE_KEYCRYPT_CIPHER_TEXT, pCipherTextRaw);
		return krc;
	}

	if (pCipherTextB64Len)
		*pCipherTextB64Len = B64len;

	XFREE(MTYPE_KEYCRYPT_CIPHER_TEXT, pCipherTextRaw);

	return 0;
}

/* clang-format off */
static int keycrypt_decrypt_gnutls(
	struct memtype	*mt,	/* of PlainText */	/* IN */
	const char	*pCipherTextB64,		/* IN */
	size_t		CipherTextB64Len,		/* IN */
	char		**ppPlainText,			/* OUT */
	size_t		*pPlainTextLen)			/* OUT */
{
	gnutls_x509_privkey_t	pKey;
	int			rc;
	char			*pCipherTextRaw;
	size_t			CipherTextRawLen = 0;
	size_t			PlainTextLen = 0;
	/* clang-format on */

	pKey = keycrypt_get_pkey_gnutls();
	if (!pKey)
		return -1;

	keycrypt_base64_decode_gnutls(pCipherTextB64, CipherTextB64Len,
				      &pCipherTextRaw, &CipherTextRawLen);

	rc = keycrypt_decrypt_internal_gnutls(pKey, mt, pCipherTextRaw,
					      CipherTextRawLen, ppPlainText,
					      &PlainTextLen);

	XFREE(MTYPE_KEYCRYPT_B64DEC, pCipherTextRaw);

	if (rc)
		return -1;

	if (pPlainTextLen)
		*pPlainTextLen = PlainTextLen;

	return 0;
}

/* clang-format off */
static int debug_keycrypt_test_cmd_gnutls(
	struct vty	*vty,
	const char	*cleartext)
{
	char			*keyfile_path = NULL;
	gnutls_x509_privkey_t	pPrivKey;

	int			rc;
	keycrypt_err_t		krc;
	char			*pCipherText = NULL;
	size_t			CipherTextLen;
	char			*pClearText = NULL;
	size_t			ClearTextLen;
	char			*pB64Text;
	size_t			B64TextLen = 0;
	/* clang-format on */

	keyfile_path = keycrypt_keyfile_path();
	if (!keyfile_path) {
		vty_out(vty, "%s: Error: can't compute keyfile path\n",
			__func__);
		return CMD_SUCCESS;
	}

	zlog_debug("%s: Computed keyfile_path: %s", __func__, keyfile_path);

	krc = keycrypt_read_keyfile_gnutls(keyfile_path, &pPrivKey);
	if (krc) {
		vty_out(vty, "%s: Error: %s returned %d: %s\n", __func__,
			"keycrypt_read_keyfile_gnutls", krc,
			keycrypt_strerror(krc));
		XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);
		return CMD_SUCCESS;
	}

	zlog_debug("%s: Read keyfile", __func__);

	krc = keycrypt_encrypt_internal_gnutls(
		pPrivKey, MTYPE_KEYCRYPT_CIPHER_TEXT, cleartext,
		strlen(cleartext), &pCipherText, &CipherTextLen);
	if (krc) {
		vty_out(vty, "%s: Error: %s returned %d: %s\n", __func__,
			"keycrypt_encrypt_internal_gnutls", krc,
			keycrypt_strerror(krc));
		return CMD_SUCCESS;
	}

	zlog_debug("%s: encrypted successfully", __func__);

	if (!pCipherText) {
		vty_out(vty, "%s: missing cipher text\n", __func__);
		return CMD_SUCCESS;
	}

	/*
	 * Encode for printing
	 */

	krc = keycrypt_base64_encode_gnutls(pCipherText, CipherTextLen,
					    &pB64Text, &B64TextLen);

	XFREE(MTYPE_KEYCRYPT_CIPHER_TEXT, pCipherText);

	if (krc) {
		vty_out(vty, "%s: Error: %s returned %d: %s\n", __func__,
			"keycrypt_base64_encode_gnutls", krc,
			keycrypt_strerror(krc));
		/* TBD does anything else need to be freed her? */
		return CMD_SUCCESS;
	}

	zlog_debug("%s: base64-encoded successfully", __func__);

	vty_out(vty,
		"INFO: clear text len: %zu, CipherTextLen: %zu, B64TextLen %zu\n",
		strlen(cleartext), CipherTextLen, B64TextLen);

	vty_out(vty, "INFO: base64 cipher text:\n%s\n", pB64Text);


	/*
	 * Decode back to binary
	 */
	keycrypt_base64_decode_gnutls(pB64Text, B64TextLen, &pCipherText,
				      &CipherTextLen);

	vty_out(vty, "INFO: After B64 decode, CipherTextLen: %zu\n",
		CipherTextLen);


	rc = keycrypt_decrypt_internal_gnutls(
		pPrivKey, MTYPE_KEYCRYPT_PLAIN_TEXT, pCipherText, CipherTextLen,
		&pClearText, &ClearTextLen);

	XFREE(MTYPE_KEYCRYPT_CIPHER_B64, pB64Text);

	if (pCipherText) {
		if (!strncmp(cleartext, pCipherText, strlen(cleartext))) {
			vty_out(vty,
				"%s: cipher text and cleartext same for %zu chars\n",
				__func__, strlen(cleartext));
			XFREE(MTYPE_KEYCRYPT_B64DEC, pCipherText);
			if (pClearText)
				XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, pClearText);
			return CMD_SUCCESS;
		}
		XFREE(MTYPE_KEYCRYPT_B64DEC, pCipherText);
	}

	if (rc) {
		vty_out(vty, "%s: Error: keycrypt_decrypt_internal_openssl\n",
			__func__);
		if (pClearText)
			XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, pClearText);
		return CMD_SUCCESS;
	}

	if (!pClearText) {
		vty_out(vty,
			"%s: keycrypt_decrypt_internal_openssl didn't return clear text pointer\n",
			__func__);
		return CMD_SUCCESS;
	}
	if (strlen(cleartext) != ClearTextLen) {
		vty_out(vty,
			"%s: decrypted ciphertext length (%zu) != original length (%lu)\n",
			__func__, ClearTextLen, strlen(cleartext));
		XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, pClearText);
		return CMD_SUCCESS;
	}

	if (strncmp(cleartext, pClearText, ClearTextLen)) {
		vty_out(vty,
			"%s: decrypted ciphertext differs from original text\n",
			__func__);
		XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, pClearText);
		return CMD_SUCCESS;
	}

	vty_out(vty, "OK: decrypted ciphertext matches original text\n");
	return CMD_SUCCESS;
}

static keycrypt_err_t keyfile_read_status_gnutls(const char *keyfile_path,
						 const char **detail)
{
	keycrypt_err_t krc;
	gnutls_x509_privkey_t pPrivKey;

	*detail = NULL;

	krc = keycrypt_read_keyfile_gnutls(keyfile_path, &pPrivKey);
	if (krc)
		*detail = keycrypt_strerror(krc);
	else
		gnutls_x509_privkey_deinit(pPrivKey);

	return krc;
}

/* clang-format off */
keycrypt_backend_t kbe_gnutls = {
	.name			= "gnutls",
	.f_encrypt		= keycrypt_encrypt_gnutls,
	.f_decrypt		= keycrypt_decrypt_gnutls,
	.f_test_cmd		= debug_keycrypt_test_cmd_gnutls,
	.f_keyfile_read_status	= keyfile_read_status_gnutls,
};
/* clang-format on */

#endif /* KEYCRYPT_HAVE_GNUTLS */

/***********************************************************************
 *		null backend simplifies error handling below
 ***********************************************************************/

/* clang-format off */
static int keycrypt_encrypt_null(
	const char	*pPlainText,		/* IN */
	size_t		PlainTextLen,		/* IN */
	char		**ppCipherTextB64,	/* OUT */
	size_t		*pCipherTextB64Len)	/* OUT */
{
	zlog_err("%s: KEYCRYPT_ENABLED not set: keycrypt not available",
		 __func__);
	return -1;
}
static int keycrypt_decrypt_null(
	struct memtype	*mt,	/* of PlainText */	/* IN */
	const char	*pCipherTextB64,		/* IN */
	size_t		CipherTextB64Len,		/* IN */
	char		**ppPlainText,			/* OUT */
	size_t		*pPlainTextLen)			/* OUT */
{
	zlog_err("%s: KEYCRYPT_ENABLED not set: keycrypt not available",
		 __func__);
	return -1;
}

static int debug_keycrypt_test_cmd_null(
	struct vty	*vty,
	const char	*cleartext)
{
	vty_out(vty, "Error: keycrypt not enabled in this build\n");
	return CMD_SUCCESS;
}

keycrypt_backend_t kbe_null = {
	.name			= NULL,
	.f_encrypt		= keycrypt_encrypt_null,
	.f_decrypt		= keycrypt_decrypt_null,
	.f_test_cmd		= debug_keycrypt_test_cmd_null,
	.f_keyfile_read_status	= keyfile_read_status_gnutls,
};
/* clang-format on */

/***********************************************************************
 *		externally-visible functions
 ***********************************************************************/


/*
 * first backend present is the one we use
 */
static keycrypt_backend_t *keycrypt_backends[] = {
#if KEYCRYPT_HAVE_GNUTLS
	&kbe_gnutls,
#endif
#if KEYCRYPT_HAVE_OPENSSL
	&kbe_openssl,
#endif
	&kbe_null,
	NULL};

#define KC_BACKEND (keycrypt_backends[0])

const char *keycrypt_strerror(keycrypt_err_t kc_err)
{
	switch (kc_err) {
	case KC_OK:
		return "No error";
	case KC_ERR_MEMORY:
		return "Can't allocate memory";
	case KC_ERR_BASE64:
		return "base64 encode/decode error";
	case KC_ERR_DECRYPT:
		return "Can't decrypt";
	case KC_ERR_ENCRYPT:
		return "Can't encrypt";
	case KC_ERR_BUILD_NOT_ENABLED:
		return "keycrypt not enabled in this build";
	case KC_ERR_KEYFILE_PATH:
		return "Can't compute private key file path";
	case KC_ERR_KEYFILE_READ:
		return "Can't read private key file";
	case KC_ERR_KEYFILE_PARSE:
		return "Can't parse private key file";
	}
	return "Unknown error";
}

/*
 * After successful return (0), caller MUST free base-64 encoded
 * cipher text via XFREE(MTYPE_KEYCRYPT_CIPHER_B64, ptr)
 */
int keycrypt_encrypt(const char *pPlainText,    /* IN */
		     size_t PlainTextLen,       /* IN */
		     char **ppCipherTextB64,    /* OUT */
		     size_t *pCipherTextB64Len) /* OUT */
{
	return (*KC_BACKEND->f_encrypt)(pPlainText, PlainTextLen,
					ppCipherTextB64, pCipherTextB64Len);
}

int keycrypt_decrypt(struct memtype *mt, /* of PlainText */ /* IN */
		     const char *pCipherTextB64,	    /* IN */
		     size_t CipherTextB64Len,		    /* IN */
		     char **ppPlainText,		    /* OUT */
		     size_t *pPlainTextLen)		    /* OUT */
{
	return (*KC_BACKEND->f_decrypt)(mt, pCipherTextB64, CipherTextB64Len,
					ppPlainText, pPlainTextLen);
}

/*
 * keycrypt_build_passwords
 *
 * Takes a single encrypted or plaintext password as input.
 *
 * Attempts to encrypt or decrypt as needed, and returns either
 * one or two dynamically-allocated strings containing the
 * plaintext and encrypted passwords.
 *
 * Caller MUST take ownership of any returned allocated strings.
 * These strings are indicated by non-NULL pointer values returned
 * via the ppPlainText and ppCryptText parameters.
 *
 * NOTE! By design, this function allocates strings even if it
 * returns an error value.
 *
 * Return codes:
 *
 *	0: KC_OK	Successful encrypt or decrypt operation
 *	!0		encrypt or decrypt failed
 */
/* clang-format off */
keycrypt_err_t
keycrypt_build_passwords(
    const char		*password_in,	/* IN */
    bool		is_encrypted,	/* IN */
    struct memtype	*mt_plaintext,	/* IN */
    char		**ppPlainText,	/* OUT type mt_plaintext */
    char		**ppCryptText)	/* OUT MTYPE_KEYCRYPT_CIPHER_B64 */
{
    *ppPlainText = NULL;
    *ppCryptText = NULL;

    if (is_encrypted) {
	/* don't lose encrypted password */
	*ppCryptText = XSTRDUP(MTYPE_KEYCRYPT_CIPHER_B64, password_in);

#ifdef KEYCRYPT_ENABLED
	if (keycrypt_decrypt(mt_plaintext, password_in,
			     strlen(password_in), ppPlainText, NULL)) {

	    zlog_err("%s: keycrypt_decrypt failed", __func__);
	    return KC_ERR_DECRYPT;
	}
#else
	zlog_err("%s: can't decrypt: keycrypt not supported in this build",
	    __func__);
	return KC_ERR_BUILD_NOT_ENABLED;
#endif

    } else {

	*ppPlainText = XSTRDUP(mt_plaintext, password_in);

	if (keycrypt_is_now_encrypting()) {

#ifdef KEYCRYPT_ENABLED
	    if (keycrypt_encrypt(password_in, strlen(password_in),
				 ppCryptText, NULL)) {
		zlog_err("%s: keycrypt_encrypt failed", __func__);
		return KC_ERR_ENCRYPT;
	    }
#else
	    zlog_err("%s: can't encrypt: keycrypt not supported in this build",
		__func__);
	    return KC_ERR_BUILD_NOT_ENABLED;
#endif

	}
    }

    return KC_OK;
}
/* clang-format on */

/* clang-format off */
DEFUN_HIDDEN (debug_keycrypt_test,
	      debug_keycrypt_test_cmd,
	      "debug keycrypt-test STRING",
	      "Debug command\n"
	      "Test keycrypt encryption and decryption\n"
	      "plain text to encrypt and decrypt\n")
/* clang-format on */
{
	int idx_string = 2;
	const char *cleartext = argv[idx_string]->arg;

	return (*KC_BACKEND->f_test_cmd)(vty, cleartext);
}

/* clang-format off */
static void inter_backend_test(
	struct vty		*vty,
	const char		*cleartext,
	keycrypt_backend_t	*b1,
	keycrypt_backend_t	*b2)
{
	size_t	cleartext_len;
	char	*pPlainText;
	char	*pCipherTextB64;
	size_t	PlainTextLen;
	size_t	CipherTextB64Len;
	int	rc;
	/* clang-format on */

	cleartext_len = strlen(cleartext);

	vty_out(vty, "cross-backend test %s->%s\n", b1->name, b2->name);
	vty_out(vty, "  cleartext \"%s\", cleartext_len %zu\n", cleartext,
		cleartext_len);

	/*
	 * encrypt with b1
	 * allocates pCipherTextB64 MTYPE_KEYCRYPT_CIPHER_B64
	 */
	rc = (*b1->f_encrypt)(cleartext, cleartext_len, &pCipherTextB64,
			      &CipherTextB64Len);
	if (rc) {
		vty_out(vty, "Error: %s encryption failed, rc=%d\n", b1->name,
			rc);
		return;
	}

	vty_out(vty, "OK: %s encryption result len %zu: \"%s\"\n", b1->name,
		CipherTextB64Len, pCipherTextB64);

	/*
	 * Decrypt with b1 (same as encrypt) first
	 */
	rc = (*b1->f_decrypt)(MTYPE_TMP, pCipherTextB64, CipherTextB64Len,
			      &pPlainText, &PlainTextLen);
	if (rc) {
		vty_out(vty, "Error: %s decryption failed, rc=%d\n", b1->name,
			rc);
		XFREE(MTYPE_KEYCRYPT_CIPHER_B64, pCipherTextB64);
		return;
	}

	/*
	 * compare plaintext
	 */
	if (PlainTextLen != cleartext_len) {
		vty_out(vty,
			"Error: orig cleartext len %zu, decrypted len %zu\n",
			cleartext_len, PlainTextLen);
		XFREE(MTYPE_KEYCRYPT_CIPHER_B64, pCipherTextB64);
		XFREE(MTYPE_TMP, pPlainText);
		return;
	}
	if (strncmp(pPlainText, cleartext, cleartext_len)) {
		vty_out(vty, "Error: orig cleartext differs from decrypted\n");
		XFREE(MTYPE_KEYCRYPT_CIPHER_B64, pCipherTextB64);
		XFREE(MTYPE_TMP, pPlainText);
		return;
	}

	vty_out(vty, "OK %s->%s \"%s\" == \"%s\"\n", b1->name, b1->name,
		cleartext, pPlainText);

	XFREE(MTYPE_TMP, pPlainText);


	/*
	 * decrypt with b2
	 * allocates pPlainText MTYPE_TMP
	 */
	rc = (*b2->f_decrypt)(MTYPE_TMP, pCipherTextB64, CipherTextB64Len,
			      &pPlainText, &PlainTextLen);
	if (rc) {
		vty_out(vty, "Error: %s decryption failed, rc=%d\n", b2->name,
			rc);
		XFREE(MTYPE_KEYCRYPT_CIPHER_B64, pCipherTextB64);
		return;
	}

	/*
	 * compare plaintext
	 */
	if (PlainTextLen != cleartext_len) {
		vty_out(vty,
			"Error: orig cleartext len %zu, decrypted len %zu\n",
			cleartext_len, PlainTextLen);
		XFREE(MTYPE_KEYCRYPT_CIPHER_B64, pCipherTextB64);
		XFREE(MTYPE_TMP, pPlainText);
		return;
	}
	if (strncmp(pPlainText, cleartext, cleartext_len)) {
		vty_out(vty, "Error: orig cleartext differs from decrypted\n");
		XFREE(MTYPE_KEYCRYPT_CIPHER_B64, pCipherTextB64);
		XFREE(MTYPE_TMP, pPlainText);
		return;
	}

	vty_out(vty, "OK %s->%s \"%s\" == \"%s\"\n", b1->name, b2->name,
		cleartext, pPlainText);

	XFREE(MTYPE_KEYCRYPT_CIPHER_B64, pCipherTextB64);
	XFREE(MTYPE_TMP, pPlainText);
}

/* clang-format off */
DEFUN_HIDDEN (debug_keycrypt_test_inter_backend,
	      debug_keycrypt_test_inter_backend_cmd,
	      "debug keycrypt-test-inter-backend STRING",
	      "Debug command\n"
	      "Test keycrypt encryption and decryption\n"
	      "plain text to encrypt and decrypt\n")
/* clang-format on */
{
	int idx_string = 2;
	const char *cleartext = argv[idx_string]->arg;

	keycrypt_backend_t *b_gnutls = NULL;
	keycrypt_backend_t *b_openssl = NULL;
	keycrypt_backend_t **p;

	for (p = keycrypt_backends; *p; ++p) {
		if (!(*p)->name)
			continue;
		if (!strcmp((*p)->name, "gnutls"))
			b_gnutls = *p;
		if (!strcmp((*p)->name, "openssl"))
			b_openssl = *p;
	}

	/*
	 * Do we have both real backends?
	 */
	if (!b_gnutls) {
		vty_out(vty, "no gnutls\n");
		return CMD_SUCCESS;
	}
	if (!b_openssl) {
		vty_out(vty, "no openssl\n");
		return CMD_SUCCESS;
	}

	inter_backend_test(vty, cleartext, b_gnutls, b_openssl);
	inter_backend_test(vty, cleartext, b_openssl, b_gnutls);

	return CMD_SUCCESS;
}

static bool keycrypt_now_encrypting = false;
static keycrypt_callback_t *keycrypt_protocol_callback = NULL;
static keycrypt_show_callback_t *keycrypt_protocol_show_callback = NULL;

void keycrypt_register_protocol_callback(keycrypt_callback_t *kcb)
{
	keycrypt_protocol_callback = kcb;
}

bool keycrypt_is_now_encrypting(void)
{
	return keycrypt_now_encrypting;
}

void keycrypt_state_change(bool now_encrypting)
{
	if (now_encrypting == keycrypt_now_encrypting)
		return;

	keycrypt_now_encrypting = now_encrypting;

	if (keycrypt_protocol_callback)
		(*keycrypt_protocol_callback)(now_encrypting);

	keychain_encryption_state_change(now_encrypting);
}

static void keycrypt_show_status_internal(struct vty *vty)
{
	const char *status;

#ifdef KEYCRYPT_ENABLED
	status = keycrypt_now_encrypting ? "ON" : "off";
#else
	status = "not included in software build";
#endif
	vty_out(vty, "%s Keycrypt status: %s\n", frr_protoname, status);

#ifdef KEYCRYPT_ENABLED
	const char *indentstr = "  ";
	char *keyfile_path;
	keycrypt_err_t krc;

	vty_out(vty, "%s%s: Keycrypt backend: %s\n", indentstr, frr_protoname,
		KC_BACKEND->name);

	keyfile_path = keycrypt_keyfile_path();

	if (keyfile_path) {

		const char *details = NULL;

		vty_out(vty, "%s%s: Private key file name: \"%s\"\n", indentstr,
			frr_protoname, keyfile_path);

		krc = (*KC_BACKEND->f_keyfile_read_status)(keyfile_path,
							   &details);
		XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);
		if (krc) {
			vty_out(vty,
				"%s%s: Private key file status: NOT READABLE\n",
				indentstr, frr_protoname);
			if (details) {
				vty_out(vty,
					"%s%s: Private key file details: %s\n",
					indentstr, frr_protoname, details);
			}
		} else {
			vty_out(vty,
				"%s%s: Private key file status: readable\n",
				indentstr, frr_protoname);
		}

	} else {
		uid_t uid = geteuid();
		vty_out(vty,
			"%s%s: Private key file name: UNABLE TO COMPUTE (euid %u)\n",
			indentstr, frr_protoname, uid);
	}

	keychain_encryption_show_status(vty, indentstr);

	if (keycrypt_protocol_show_callback) {
		(*keycrypt_protocol_show_callback)(vty, indentstr);
	}
#endif
}

void keycrypt_register_protocol_show_callback(keycrypt_show_callback_t *kcb)
{
	keycrypt_protocol_show_callback = kcb;
}

DEFUN (keycrypt_show_status,
       keycrypt_show_status_cmd,
       "show keycrypt status",
       "Show command\n"
       "keycrypt protocol key encryption\n"
       "status\n")
{
	keycrypt_show_status_internal(vty);
	return CMD_SUCCESS;
}

void keycrypt_init(void)
{
	install_element(VIEW_NODE, &debug_keycrypt_test_cmd);
	install_element(VIEW_NODE, &debug_keycrypt_test_inter_backend_cmd);
	install_element(VIEW_NODE, &keycrypt_show_status_cmd);
}
