/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

#include <string.h>
#include <sys/types.h>
#include <libubox/md5.h>

#include "mstp.h"

/*
** Function: hmac_md5 from RFC-2104
*/
void hmac_md5(text, text_len, key, key_len, digest)
unsigned char*  text;       /* pointer to data stream */
int             text_len;   /* length of data stream */
unsigned char*  key;        /* pointer to authentication key */
int             key_len;    /* length of authentication key */
caddr_t         digest;     /* caller digest to be filled in */
{
    md5_ctx_t context;
    unsigned char k_ipad[65];    /* inner padding -
                                  * key XORd with ipad
                                  */
    unsigned char k_opad[65];    /* outer padding -
                                  * key XORd with opad
                                  */
    unsigned char tk[16];
    int i;
    /* if key is longer than 64 bytes reset it to key=MD5(key) */
    if(key_len > 64)
    {
        md5_ctx_t tctx;

        md5_begin(&tctx);
        md5_hash(key, key_len, &tctx);
        md5_end(tk, &tctx);

        key = tk;
        key_len = 16;
    }

    /*
     * the HMAC_MD5 transform looks like:
     *
     * MD5(K XOR opad, MD5(K XOR ipad, text))
     *
     * where K is an n byte key
     * ipad is the byte 0x36 repeated 64 times
     * opad is the byte 0x5c repeated 64 times
     * and text is the data being protected
     */

    /* start out by storing key in pads */
    bzero(k_ipad, sizeof k_ipad);
    bzero(k_opad, sizeof k_opad);
    bcopy(key, k_ipad, key_len);
    bcopy( key, k_opad, key_len);

    /* XOR key with ipad and opad values */
    for(i = 0; i < 64; ++i)
    {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    /*
     * perform inner MD5
     */
    md5_begin(&context);                 /* init context for 1st
                                          * pass */
    md5_hash(k_ipad, 64, &context);      /* start with inner pad */
    md5_hash(text, text_len, &context);  /* then text of datagram */
    md5_end(digest, &context);           /* finish up 1st pass */
    /*
     * perform outer MD5
     */
    md5_begin(&context);                 /* init context for 2nd
                                          * pass */
    md5_hash(k_opad, 64, &context);      /* start with outer pad */
    md5_hash(digest, 16, &context);      /* then results of 1st
                                          * hash */
    md5_end(digest, &context);           /* finish up 2nd pass */
}
