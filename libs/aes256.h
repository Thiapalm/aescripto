/*
*   Byte-oriented AES-256 implementation.
*   All lookup tables replaced with 'on the fly' calculations.
*
*   Copyright (c) 2007-2009 Ilya O. Levin, http://www.literatecode.com
*   Other contributors: Hal Finney
*
*   Permission to use, copy, modify, and distribute this software for any
*   purpose with or without fee is hereby granted, provided that the above
*   copyright notice and this permission notice appear in all copies.
*
*   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
*   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
*   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
*   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
*   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
*   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
*   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
/****************************************************************************
 * Title                 :   AES 256
 * Filename              :   aes256.h
 * Author                :   Ilya O. Levin
 * Origin Date           :   29/12/2014
 * Version               :   1.0.0
 * Compiler              :   AVR8/GNU C Compiler : 4.8.1
 * Target                :   ATMEGA328p and ATMEGA2560p
 * Notes                 :   None
 *****************************************************************************/
/*************** INTERFACE CHANGE LIST **************************************
 *
 *    Date    Software Version    Initials   Description
 *  29/12/14        1.0.0         IOL       Created.
 *
 *****************************************************************************/
/** \file aes256.h
 *  \brief This module contains AES EBC encryption
 *
 *  This is the header file for AES 256 encryption
 *
 */

#ifndef _AES256_H_
#define _AES256_H_

/******************************************************************************
 * Includes
 *******************************************************************************/
#include <inttypes.h>
/******************************************************************************
 * Preprocessor Constants
 *******************************************************************************/
/*#ifndef uint8_t
#define uint8_t  unsigned char
#endif*/

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************
 * Configuration Constants
 *******************************************************************************/


/******************************************************************************
 * Macros
 *******************************************************************************/


/******************************************************************************
 * Typedefs
 *******************************************************************************/
/**
 * \struct aes256_context
 *
 * \brief It is used to store the encryption variables
 *
 */
typedef struct {
    uint8_t key[32]; //!< Key to be used for encryption/decryption
    uint8_t enckey[32]; //!< Key to be used for encryption
    uint8_t deckey[32]; //!< Key to be used for decryption
} aes256_context;

/******************************************************************************
* Variables
*******************************************************************************/


/******************************************************************************
* Function Prototypes
*******************************************************************************/

    void aes256_init(aes256_context *, uint8_t * /* key */);
    void aes256_done(aes256_context *);
    void aes256_encrypt_ecb(aes256_context *, uint8_t * /* plaintext */);
    void aes256_decrypt_ecb(aes256_context *, uint8_t * /* cipertext */);

#ifdef __cplusplus
}
#endif

#endif /* _AES256_H_ */
/*** End of File **************************************************************/
