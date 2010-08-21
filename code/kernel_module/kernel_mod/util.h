#ifndef __UTIL_H__
#define __UTIL_H__


#define X_SIZE 16    // 128 bits
#define MAX_KEY_SIZE 32    // 256 bits - Max key size

/* We need better random generation for the key */
void generate_rand128(void *buf);

void set_X(char *buffer);
void get_X(char *buffer);


/* For set encrypt key, we need - 
 1. Original Encryption Key
 2. Key Size (128 or 192 or 256 bits)
 3. Pointer (buffer) for storing the AES_KEY struct (transformed key)
*/



#endif
