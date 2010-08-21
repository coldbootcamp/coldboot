/**@file aeskey_struct.h
 *
 * This file contains the definition of structures that are
 * necessary for representing keys.
 *
 */

#ifndef AESKEY_STRUCT_H_
#define AESKEY_STRUCT_H_

#if !defined (ALIGN16)
# if defined (__GNUC__)
# define ALIGN16 __attribute__ ( (aligned (16)))
# else
# define ALIGN16 __declspec (align (16))
# endif
#endif

typedef struct KEY_SCHEDULE{
  unsigned char KEY[16*15];
  unsigned int nr;
}M_AES_KEY;

typedef struct CBC_KEY_SCHEDULE {
  ALIGN16 unsigned char IV[16];
  ALIGN16 M_AES_KEY aeskey;
}CBC_KEY;

typedef struct AESKEY {
  int key_size_bits;
  unsigned char key[32];
}AES_BITKEY;

#endif /* AESKEY_STRUCT_H_ */
