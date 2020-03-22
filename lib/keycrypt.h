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

#include <zebra.h>
#include <memory.h>

DECLARE_MTYPE(KEYCRYPT_CIPHER_B64)
DECLARE_MTYPE(KEYCRYPT_PLAIN_TEXT)

#ifdef CRYPTO_OPENSSL

#define KEYCRYPT_ENABLED 1

extern void
keycrypt_base64_encode(const char *pIn, size_t InLen, char **ppOut, size_t *pOutLen);

extern void
keycrypt_base64_decode(const char *pIn, size_t InLen, char **ppOut, size_t *pOutLen);

extern int
keycrypt_encrypt(
    const char		*pPlainText,		/* IN */
    size_t		PlainTextLen,		/* IN */
    char		**ppCipherText,		/* OUT */
    size_t		*pCipherTextLen);	/* OUT */

extern int
keycrypt_decrypt(
    struct memtype	*mt, /* of PlainText */	/* IN */
    const char		*pCipherText,		/* IN */
    size_t		CipherTextLen,		/* IN */
    char		**pPlainText,		/* OUT */
    size_t		*pPlainTextLen);	/* OUT */

extern void keycrypt_init(void);

typedef void(keycrypt_callback_t)(bool);

void
keycrypt_register_protocol_callback(keycrypt_callback_t kcb);

bool
keycrypt_is_now_encrypting(void);

void
keycrypt_state_change(bool now_encrypting);

#endif /* CRYPTO_OPENSSL */


#endif /* _FRR_KEYCRYPT_H */
