/*
 * Copyright 2020, LabN Consulting, L.L.C.
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

#ifdef CRYPTO_OPENSSL

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>

#define KEYFILE_NAME_PRIVATE	".ssh/frr"
#define PWENT_BUFSIZE	512

DEFINE_MTYPE_STATIC(LIB, KEYCRYPT_KEYFILE_PATH, "keycrypt keyfile path")
DEFINE_MTYPE_STATIC(LIB, KEYCRYPT_CIPHER_TEXT, "keycrypt cipher text")
DEFINE_MTYPE_STATIC(LIB, KEYCRYPT_PLAIN_TEXT, "keycrypt plain text")
DEFINE_MTYPE_STATIC(LIB, KEYCRYPT_B64ENC, "keycrypt base64 encoded")
DEFINE_MTYPE_STATIC(LIB, KEYCRYPT_B64DEC, "keycrypt base64 decoded")

/*
 * TBD: validate permissions on keyfile path
 */

/*
 * Compute path to keyfile
 *
 * Caller must free returned buffer XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, path)
 *
 * Return value is NULL on failure.
 */
char *
keycrypt_keyfile_path(void)
{
    /*
     * get homedir
     */
    uid_t		uid = geteuid();
    struct passwd	pwd;
    struct passwd	*pwd_result;
    char		*pbuf = XMALLOC(MTYPE_TMP, PWENT_BUFSIZE);
    int			rc;
    char		*path = NULL;
    size_t		len;

    rc = getpwuid_r(uid, &pwd, pbuf, PWENT_BUFSIZE, &pwd_result);
    if (rc) {
        zlog_warn("%s: getpwuid_r(uid=%u): %s",
            __func__, uid, safe_strerror(errno));
        XFREE(MTYPE_TMP, pbuf);
        return NULL;
    }

    len = strlen(pwd.pw_dir) + 1 + strlen(KEYFILE_NAME_PRIVATE) + 1;
    path = XMALLOC(MTYPE_KEYCRYPT_KEYFILE_PATH,  len);
    sprintf(path, "%s/%s", pwd.pw_dir, KEYFILE_NAME_PRIVATE);
    XFREE(MTYPE_TMP, pbuf);

    return path;
}

/*
 * To generate a suitable private key, use:
 *
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
EVP_PKEY *
keycrypt_read_keyfile(char *path, keycrypt_key_format_t format)
{
    EVP_PKEY	*pkey = NULL;
    BIO		*fb;

    fb = BIO_new_file(path, "r");
    if (!fb) {
        zlog_warn("%s: BIO_new_file(\"%s\") failed: %s",
            __func__, path, safe_strerror(errno));
        return NULL;
    }

    switch (format) {
    case KEYCRYPT_FORMAT_ASN1:
        pkey = d2i_PrivateKey_bio(fb, NULL);
        break;
    case KEYCRYPT_FORMAT_PEM:
        pkey = PEM_read_bio_PrivateKey(fb, NULL, NULL, NULL);
        break;
    case KEYCRYPT_FORMAT_PVK:
        pkey = b2i_PVK_bio(fb, NULL, NULL);
        break;
    default:
        zlog_warn("%s: unknown format %u: not supported",
            __func__, format);
    }

    BIO_free(fb);

    if (!pkey)
        zlog_warn("%s: unable to load key from file \"%s\"", __func__, path);

    return pkey;
}

/*
 * Caller must free result XFREE(MTYPE_KEYCRYPT_B64ENC, *pOut)
 */
void
keycrypt_base64_encode(char *pIn, size_t InLen, char **ppOut, size_t *pOutLen)
{
    BIO *bio_b64;
    BIO *bio_mem;
    BUF_MEM *obufmem;

    bio_mem = BIO_new(BIO_s_mem());
    bio_b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(bio_b64, bio_mem);
    BIO_write(bio_b64, pIn, InLen);
    BIO_flush(bio_b64);

    BIO_get_mem_ptr(bio_mem, &obufmem);
    *ppOut = XMALLOC(MTYPE_KEYCRYPT_B64ENC, obufmem->length + 1);
    memcpy(*ppOut, obufmem->data, obufmem->length);
    *((*ppOut) + obufmem->length) = 0;	/* NUL-terminate */
    *pOutLen = obufmem->length;

    BIO_free_all(bio_b64);
}

/*
 * Caller must free result XFREE(MTYPE_KEYCRYPT_B64DEC, *pOut)
 */
void
keycrypt_base64_decode(char *pIn, size_t InLen, char **ppOut, size_t *pOutLen)
{
    BIO *bio_b64;
    BIO *bio_mem;
    BIO	*bio_omem;
    BUF_MEM *obufmem;
    char inbuf[512];
    int	inlen;

    bio_mem = BIO_new_mem_buf(pIn, InLen);
    bio_b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(bio_b64, bio_mem);

    bio_omem = BIO_new(BIO_s_mem());

    while((inlen = BIO_read(bio_b64, inbuf, sizeof(inbuf))) > 0)
        BIO_write(bio_omem, inbuf, inlen);

    BIO_flush(bio_omem);
    BIO_free_all(bio_b64);

    BIO_get_mem_ptr(bio_omem, &obufmem);
    *ppOut = XMALLOC(MTYPE_KEYCRYPT_B64DEC, obufmem->length + 1);
    memcpy(*ppOut, obufmem->data, obufmem->length);
    *((*ppOut) + obufmem->length) = 0;	/* NUL-terminate */
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
int
keycrypt_encrypt(
    EVP_PKEY *pKey,		/* IN */
    const char *pPlainText,	/* IN */
    size_t PlainTextLen,	/* IN */
    char **ppCipherText,	/* OUT */
    size_t *pCipherTextLen)	/* OUT */
{
    EVP_PKEY_CTX	*ctx;
    ENGINE		*eng = NULL;	/* default RSA impl */
    int			rc;
    size_t		OutLen;
    char		*pOutBuf;

    ctx = EVP_PKEY_CTX_new(pKey, eng);
    if (!ctx) {
        zlog_warn("%s: unable to alloc context", __func__);
        return -1;
    }

    rc = EVP_PKEY_encrypt_init(ctx);
    if (rc <= 0) {
        EVP_PKEY_CTX_free(ctx);
        zlog_warn("%s: Error: EVP_PKEY_encrypt_init%s",
            __func__, ((rc == -2)? ": not supported by public key alg": "" ));
        return -1;
    }

    rc = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    if (rc <= 0) {
        EVP_PKEY_CTX_free(ctx);
        zlog_warn("%s: Error: EVP_PKEY_CTX_set_rsa_padding%s",
            __func__, ((rc == -2)? ": not supported by public key alg": "" ));
        return -1;
    }

    /* Determine buffer length */
    rc = EVP_PKEY_encrypt(ctx, NULL, &OutLen,
        (const u_char *)pPlainText, PlainTextLen);
    if (rc <= 0) {
        EVP_PKEY_CTX_free(ctx);
        zlog_warn("%s: Error: EVP_PKEY_encrypt (1)%s",
            __func__, ((rc == -2)? ": not supported by public key alg": "" ));
        return -1;
    }

    pOutBuf = XMALLOC(MTYPE_KEYCRYPT_CIPHER_TEXT, OutLen);

    rc = EVP_PKEY_encrypt(ctx, (u_char *)pOutBuf, &OutLen,
        (const u_char *)pPlainText, PlainTextLen);
    if (rc <= 0) {
        EVP_PKEY_CTX_free(ctx);
        XFREE(MTYPE_KEYCRYPT_CIPHER_TEXT, pOutBuf);
        zlog_warn("%s: Error: EVP_PKEY_encrypt (2)%s",
            __func__, ((rc == -2)? ": not supported by public key alg": "" ));
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);

    *ppCipherText = pOutBuf;
    *pCipherTextLen = OutLen;

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
int
keycrypt_decrypt(
    EVP_PKEY *pKey,		/* IN */
    const char *pCipherText,	/* IN */
    size_t CipherTextLen,	/* IN */
    char **ppPlainText,		/* OUT */
    size_t *pPlainTextLen)	/* OUT */
{
    EVP_PKEY_CTX	*ctx;
    ENGINE		*eng = NULL;	/* default RSA impl */
    int			rc;
    size_t		OutLen;

    ctx = EVP_PKEY_CTX_new(pKey, eng);
    if (!ctx) {
        zlog_warn("%s: unable to alloc context", __func__);
        return -1;
    }

    rc = EVP_PKEY_decrypt_init(ctx);
    if (rc <= 0) {
        EVP_PKEY_CTX_free(ctx);
        zlog_warn("%s: Error: EVP_PKEY_decrypt_init%s",
            __func__, ((rc == -2)? ": not supported by public key alg": "" ));
        return -1;
    }

    rc = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    if (rc <= 0) {
        EVP_PKEY_CTX_free(ctx);
        zlog_warn("%s: Error: EVP_PKEY_CTX_set_rsa_padding%s",
            __func__, ((rc == -2)? ": not supported by public key alg": "" ));
        return -1;
    }

    /* Determine buffer length */
    rc = EVP_PKEY_decrypt(ctx, NULL, &OutLen,
        (const u_char *)pCipherText, CipherTextLen);
    if (rc <= 0) {
        EVP_PKEY_CTX_free(ctx);
        zlog_warn("%s: Error: EVP_PKEY_encrypt (1)%s",
            __func__, ((rc == -2)? ": not supported by public key alg": "" ));
        return -1;
    }

    *ppPlainText = XMALLOC(MTYPE_KEYCRYPT_PLAIN_TEXT, OutLen);

    rc = EVP_PKEY_decrypt(ctx,
        (u_char *)*ppPlainText, pPlainTextLen,
        (const u_char *)pCipherText, CipherTextLen);
    if (rc <= 0) {
        EVP_PKEY_CTX_free(ctx);
        if (*ppPlainText)
            XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, *ppPlainText);
        zlog_warn("%s: Error: EVP_PKEY_decrypt (2)%s",
            __func__, ((rc == -2)? ": not supported by public key alg": "" ));
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);

    return 0;
}

DEFUN_HIDDEN (debug_keycrypt_test,
       debug_keycrypt_test_cmd,
       "debug keycrypt-test STRING",
       "Debug command\n"
       "Test keycrypt encryption and decryption\n"
       "plain text to encrypt and decrypt\n")
{
    char	*keyfile_path = NULL;
    EVP_PKEY    *pKey;
    int		rc;
    char	*pCipherText = NULL;
    size_t	CipherTextLen;
    char	*pClearText = NULL;
    size_t	ClearTextLen;
    int		idx_string = 2;
    char	*pB64Text;
    size_t	B64TextLen;

    const char	*cleartext = argv[idx_string]->arg;

    keyfile_path = keycrypt_keyfile_path();
    if (!keyfile_path) {
        vty_out(vty, "%s: Error: can't compute keyfile path\n", __func__);
        return CMD_SUCCESS;
    }

    pKey = keycrypt_read_keyfile(keyfile_path, KEYCRYPT_FORMAT_PEM );
    if (!pKey) {
        vty_out(vty, "%s: Error: keycrypt_read_keyfile\n", __func__);
        XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);
        return CMD_SUCCESS;
    }
    XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);

    rc = keycrypt_encrypt(pKey,
        cleartext, strlen(cleartext),
        &pCipherText, &CipherTextLen);
    if (rc) {
        EVP_PKEY_free(pKey);
        vty_out(vty, "%s: Error: keycrypt_encrypt\n", __func__);
        return CMD_SUCCESS;
    }

    if (!pCipherText) {
        vty_out(vty, "%s: missing cipher text\n", __func__);
        return CMD_SUCCESS;
    }

    /*
     * Encode for printing
     */

    keycrypt_base64_encode(pCipherText, CipherTextLen, &pB64Text, &B64TextLen);

    XFREE(MTYPE_KEYCRYPT_CIPHER_TEXT, pCipherText);

    vty_out(vty, "INFO: clear text len: %lu, CipherTextLen: %lu, B64TextLen %lu\n",
        strlen(cleartext), CipherTextLen, B64TextLen);

    vty_out(vty, "INFO: base64 cipher text:\n%s\n", pB64Text);


    /*
     * Decode back to binary
     */
    keycrypt_base64_decode(pB64Text, B64TextLen, &pCipherText, &CipherTextLen);

    XFREE(MTYPE_KEYCRYPT_B64ENC, pB64Text);

    vty_out(vty, "INFO: After B64 decode, CipherTextLen: %lu\n",
        CipherTextLen);


    rc = keycrypt_decrypt(pKey,
        pCipherText, CipherTextLen,
        &pClearText, &ClearTextLen);

    EVP_PKEY_free(pKey);

    if (pCipherText) {
        if (!strncmp(cleartext, pCipherText, strlen(cleartext))) {
            vty_out(vty, "%s: cipher text and cleartext same for %lu chars\n",
                __func__, strlen(cleartext));
            XFREE(MTYPE_KEYCRYPT_B64DEC, pCipherText);
            if (pClearText)
                XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, pClearText);
            return CMD_SUCCESS;
        }
        XFREE(MTYPE_KEYCRYPT_B64DEC, pCipherText);
    }

    if (rc) {
        vty_out(vty, "%s: Error: keycrypt_decrypt\n", __func__);
        if (pClearText)
            XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, pClearText);
        return CMD_SUCCESS;
    }

    if (!pClearText) {
        vty_out(vty,
            "%s: keycrypt_decrypt didn't return clear text pointer\n",
            __func__);
        return CMD_SUCCESS;
    }
    if (strlen(cleartext) != ClearTextLen) {
        vty_out(vty,
            "%s: decrypted ciphertext length (%lu) != original length (%lu)\n",
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

void
keycrypt_init(void)
{
    install_element(VIEW_NODE, &debug_keycrypt_test_cmd);
}

#endif /* CRYPTO_OPENSSL */
