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

#ifndef _FRR_KEYCRYPT_H
#define _FRR_KEYCRYPT_H

#ifdef CRYPTO_OPENSSL

#include <openssl/evp.h>
#include <zebra.h>

typedef enum {
    KEYCRYPT_FORMAT_ASN1,
    KEYCRYPT_FORMAT_PEM,
    KEYCRYPT_FORMAT_PVK,
} keycrypt_key_format_t;

extern char *
keycrypt_keyfile_path(void);

extern void
keycrypt_base64_encode(char *pIn, size_t InLen, char **ppOut, size_t *pOutLen);

extern void
keycrypt_base64_decode(char *pIn, size_t InLen, char **ppOut, size_t *pOutLen);

extern EVP_PKEY *
keycrypt_read_keyfile(char *path, keycrypt_key_format_t format);

extern int
keycrypt_encrypt(
    EVP_PKEY *pKey,		/* IN */
    const char *pPlainText,	/* IN */
    size_t PlainTextLen,	/* IN */
    char **ppCipherText,	/* OUT */
    size_t *pCipherTextLen);	/* OUT */

extern int
keycrypt_decrypt(
    EVP_PKEY *pKey,		/* IN */
    const char *pCipherText,	/* IN */
    size_t CipherTextLen,	/* IN */
    char **pPlainText,		/* OUT */
    size_t *pPlainTextLen);	/* OUT */

extern void keycrypt_init(void);

#endif /* CRYPTO_OPENSSL */

#endif /* _FRR_KEYCRYPT_H */
