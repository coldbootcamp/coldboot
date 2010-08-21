/**@file aes_core.h
 *
 */

#ifndef AES_CORE_H_
#define AES_CORE_H_

#include <stddef.h>

#define AES_ENCRYPT	1
#define AES_DECRYPT	0

/* Because array size can't be a const in C, the following two are macros.
   Both sizes are in bytes. */
#define AES_MAXNR 14
#define AES_BLOCK_SIZE 16

#ifdef  __cplusplus
extern "C" {
#endif

/* #if !defined (ALIGN16) */
/* # if defined (__GNUC__) */
/* # define ALIGN16 __attribute__ ( (aligned (16))) */
/* # else */
/* # define ALIGN16 __declspec (align (16)) */
/* # endif */
/* #endif */

/* This should be a hidden type, but EVP requires that the size be known */
struct aes_key_st {
#ifdef AES_LONG
    unsigned long rd_key[4 *(AES_MAXNR + 1)];
#else
    unsigned int rd_key[4 *(AES_MAXNR + 1)];
#endif
    int rounds;
};
typedef struct aes_key_st AES_KEY;

int AES_set_encrypt_key (const unsigned char *userKey,
                         const int bits,
                         key_schedule_t *key);
void AES_CBC_encrypt (const unsigned char *in,
		      unsigned char *out,
		      unsigned char ivec[16],
		      unsigned long length,
		      const unsigned char *KS,
		      int nr);

void AES_transform_key (unsigned char *key_sched, int key_nr);
#endif /* AES_CORE_H_ */
