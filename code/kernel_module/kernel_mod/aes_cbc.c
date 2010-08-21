/**@file aes_cbc.c
 *
 *
 */

/* Steps:
 * 1. Generate key schedules
 * 2. Transform secret key's key schedule
 * 3. Try encrypting buffer with transformed key
 */

#ifndef LENGTH
#define LENGTH 64
#endif
#include <stdint.h>
#include <stdio.h>
#include <wmmintrin.h>

#include "aes_core.h"

#define ERROR -1
#define SUCCESS 0

ALIGN16 uint8_t AES256_TEST_KEY[] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
                                      0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
                                      0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
                                      0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
ALIGN16 uint8_t AES_TEST_VECTOR[] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                                      0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
                                      0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
                                      0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
                                      0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
                                      0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
                                      0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
                                      0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
ALIGN16 uint8_t CBC_IV[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                             0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};

int main(void) {
  int i;
  int ret_val;
  uint8_t *output;

  /* Initialize the IV for each cbc key structure */
  for (i = 0; i < 16; i++) {
    trans_key_sched.IV[i] = CBC_IV[i];
    hash_key_sched.IV[i] = CBC_HASH_IV[i];
  }
  trans_key_sched.aeskey.nr = 14;
  hash_key_sched.aeskey.nr = 10;

  /* Generate key schedule for public hash key */
  ret_val = AES_set_encrypt_key((unsigned char *)(&AES128_HASH_KEY),
				 128,
				 (AES_KEY *)&(hash_key_sched.aeskey));
  if (ret_val < 0) {
    printf("ERROR: Unable to generate hash key schedule");
    return ERROR;
  }

  ret_val = AES_set_encrypt_key((unsigned char *)(&AES256_TEST_KEY),
				256,
				(AES_KEY *)&(trans_key_sched.aeskey));
  if (ret_val < 0) {
    printf("ERROR: Unable to generate transformed key schedule");
    return ERROR;
  }

  AES_transform_key(trans_key_sched.aeskey.KEY, trans_key_sched.aeskey.nr);

  printf("Managed to transform trans_key_sched.\n");

  /* Before exiting clear out the value of x from the register and
   * put it back into the debug register
   */
  output = (uint8_t *)(malloc(LENGTH));
  if (output == NULL) {
    return 0;
  }

  printf("Value of output: %p\n", output);

  AES_CBC_encrypt((unsigned char *)AES_TEST_VECTOR,
		  (unsigned char *)(output),
		  (unsigned char *)(trans_key_sched.IV),
		  LENGTH,
		  trans_key_sched.aeskey.KEY,
		  trans_key_sched.aeskey.nr);

  for (i = 0; i < 64; i++) {
    if (output[i] == AES_TEST_VECTOR[i]) {
      printf("Problem with output at %d.\n", i);
      return -1;
    }
  }


  AES_CBC_encrypt((unsigned char *)(output),
		  (unsigned char *)(output),
		  (unsigned char *)(trans_key_sched.IV),
		  LENGTH,
		  trans_key_sched.aeskey.KEY,
		  trans_key_sched.aeskey.nr);


  for (i = 0; i < 64; i++) {
    if (output[i] != AES_TEST_VECTOR[i]) {
      printf("Problem at %d.\n", i);
      //return -1;
    }
  }
  return 0;
}
