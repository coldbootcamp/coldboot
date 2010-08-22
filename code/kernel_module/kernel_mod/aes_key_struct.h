/**@file aes_key_struct.h
 *
 * This file contains the definition of the key structure used
 * for AES key schedule.
 *
 * @author Vanshidhar Konda (vkonda)
 * @author Shishir Kumar Yadav (skyadav)
 * @author Chetan Anand (canand)
 *
 */

#ifndef AES_KEY_STRUCT_H_
#define AES_KEY_STRUCT_H_

#if !defined (ALIGN16)
# if defined (__GNUC__)
# define ALIGN16 __attribute__ ( (aligned (16)))
# else
# define ALIGN16 __declspec (align (16))
# endif
#endif

typedef struct {
    ALIGN16 char key[16*15];
    unsigned int nr;
}key_schedule_t;

typedef struct {
  char *user_key;
  int user_key_size; //key size in bits
  key_schedule_t key_schedule;
}ioctl_set_key_t;

typedef struct {
  ALIGN16 unsigned char IV[16];
  ALIGN16 key_schedule_t aeskey;
}cbc_key_t;

typedef struct AESKEY {
  int key_size_bits;
  unsigned char key[32];
}AES_BITKEY;

void SAVE_X(void *, void *);

int AES_set_encrypt_key (const char *userKey,
                         const int bits,
                         key_schedule_t *key);

int AES_set_decrypt_key (const char *userKey,
                         const int bits,
                         key_schedule_t *key);

void AES_128_Key_Expansion (const char *userKey, key_schedule_t *key);

void AES_192_Key_Expansion (const char *userKey, key_schedule_t *key);

void AES_256_Key_Expansion (const char *userKey, key_schedule_t *key);

void AES_transform_key (unsigned char *key_sched, int key_nr);

#endif /* AES_KEY_STRUCT_H_ */
