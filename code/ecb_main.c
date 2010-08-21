//#define AES128
//#define AES192
//#define AES256
#ifndef LENGTH
#define LENGTH 64
#endif
#include <stdint.h>
#include <stdio.h>
#include <wmmintrin.h>
#if !defined (ALIGN16)
# if defined (__GNUC__)
# define ALIGN16 __attribute__ ( (aligned (16)))
# else
# define ALIGN16 __declspec (align (16))
# endif
#endif

#define cpuid(func,ax,bx,cx,dx)\
	__asm__ __volatile__ ("cpuid":\
			"=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (func));
int Check_CPU_support_AES()
{
	unsigned int a,b,c,d;
	cpuid(1, a,b,c,d);
	return (c & 0x2000000);
}

typedef struct KEY_SCHEDULE{
    ALIGN16 unsigned char KEY[16*15];
    unsigned int nr;
    }AES_KEY;
/*test vectors were taken from http://csrc.nist.gov/publications/nistpubs/800-
38a/sp800-38a.pdf*/
ALIGN16 uint8_t AES128_TEST_KEY[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                                      0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
ALIGN16 uint8_t AES192_TEST_KEY[] = {0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
                                      0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
                                      0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b};
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
ALIGN16 uint8_t ECB128_EXPECTED[] = {0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,
                                      0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97,
                                      0xf5,0xd3,0xd5,0x85,0x03,0xb9,0x69,0x9d,
                                     0xe7,0x85,0x89,0x5a,0x96,0xfd,0xba,0xaf,
                                     0x43,0xb1,0xcd,0x7f,0x59,0x8e,0xce,0x23,
                                     0x88,0x1b,0x00,0xe3,0xed,0x03,0x06,0x88,
                                     0x7b,0x0c,0x78,0x5e,0x27,0xe8,0xad,0x3f,
                                     0x82,0x23,0x20,0x71,0x04,0x72,0x5d,0xd4};
ALIGN16 uint8_t ECB192_EXPECTED[] = {0xbd,0x33,0x4f,0x1d,0x6e,0x45,0xf2,0x5f,
                                     0xf7,0x12,0xa2,0x14,0x57,0x1f,0xa5,0xcc,
                                     0x97,0x41,0x04,0x84,0x6d,0x0a,0xd3,0xad,
                                     0x77,0x34,0xec,0xb3,0xec,0xee,0x4e,0xef,
                                     0xef,0x7a,0xfd,0x22,0x70,0xe2,0xe6,0x0a,
                                     0xdc,0xe0,0xba,0x2f,0xac,0xe6,0x44,0x4e,
                                     0x9a,0x4b,0x41,0xba,0x73,0x8d,0x6c,0x72,
                                     0xfb,0x16,0x69,0x16,0x03,0xc1,0x8e,0x0e};
ALIGN16 uint8_t ECB256_EXPECTED[] = {0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,
                                     0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8,
                                     0x59,0x1c,0xcb,0x10,0xd4,0x10,0xed,0x26,
                                     0xdc,0x5b,0xa7,0x4a,0x31,0x36,0x28,0x70,
                                     0xb6,0xed,0x21,0xb9,0x9c,0xa6,0xf4,0xf9,
                                     0xf1,0x53,0xe7,0xb1,0xbe,0xaf,0xed,0x1d,
                                     0x23,0x30,0x4b,0x7a,0x39,0xf9,0xf3,0xff,
                                     0x06,0x7d,0x8d,0x8f,0x9e,0x24,0xec,0xc7};
/*****************************************************************************/
void print_m128i_with_string(char* string,__m128i data)
    {
    unsigned char *pointer = (unsigned char*)&data;
    int i;
    printf("%-40s[0x",string);
    for (i=0; i<16; i++)
        printf("%02x",pointer[i]);
    printf("]\n");
    }
void print_m128i_with_string_short(char* string,__m128i data,int length)
    {
    unsigned char *pointer = (unsigned char*)&data;
    int i;
    printf("%-40s[0x",string);
    for (i=0; i<length; i++)
        printf("%02x",pointer[i]);
    printf("]\n");
    }
/*****************************************************************************/
int main(){
    AES_KEY key;
    AES_KEY decrypt_key;
    uint8_t *PLAINTEXT;
    uint8_t *CIPHERTEXT;
    uint8_t *DECRYPTEDTEXT;
    uint8_t *EXPECTED_CIPHERTEXT;
    uint8_t *CIPHER_KEY;
    int i,j;
    int key_length;
    if (!Check_CPU_support_AES()){
        printf("Cpu does not support AES instruction set. Bailing out.\n");
        return 1;
        }
    printf("CPU support AES instruction set.\n\n");
#ifdef AES128
#define STR "Performing AES128 ECB.\n"
    CIPHER_KEY = AES128_TEST_KEY;
    EXPECTED_CIPHERTEXT = ECB128_EXPECTED;
    key_length = 128;
#elif defined AES192
#define STR "Performing AES192 ECB.\n"
    CIPHER_KEY = AES192_TEST_KEY;
    EXPECTED_CIPHERTEXT = ECB192_EXPECTED;
    key_length = 192;
#elif defined AES256
#define STR "Performing AES256 ECB.\n"
    CIPHER_KEY = AES256_TEST_KEY;
    EXPECTED_CIPHERTEXT = ECB256_EXPECTED;
    key_length = 256;
#endif
    PLAINTEXT = (uint8_t*)malloc(LENGTH);
    CIPHERTEXT = (uint8_t*)malloc(LENGTH);
    DECRYPTEDTEXT = (uint8_t*)malloc(LENGTH);
    for(i=0 ;i<LENGTH/16/4; i++){
        for(j=0; j<4; j++){
            _mm_storeu_si128(&((__m128i*)PLAINTEXT)[i*4+j],
                              ((__m128i*)AES_TEST_VECTOR)[j]);
            }
        }
    for(j=i*4 ; j<LENGTH/16; j++){
        _mm_storeu_si128(&((__m128i*)PLAINTEXT)[j],
                         ((__m128i*)AES_TEST_VECTOR)[j%4]);
        }
    if (LENGTH%16){
        _mm_storeu_si128(&((__m128i*)PLAINTEXT)[j],
                          ((__m128i*)AES_TEST_VECTOR)[j%4]);
        }
    AES_set_encrypt_key(CIPHER_KEY, key_length, &key);
    AES_set_decrypt_key(CIPHER_KEY, key_length, &decrypt_key);
    AES_ECB_encrypt(PLAINTEXT,
                    CIPHERTEXT,
                    LENGTH,
                    key.KEY,
                    key.nr);
    AES_ECB_decrypt(CIPHERTEXT,
                    DECRYPTEDTEXT,
                    LENGTH,
                    decrypt_key.KEY,
                    decrypt_key.nr);
    printf("%s\n",STR);
    printf("The Cipher Key:\n");
    print_m128i_with_string("",((__m128i*)CIPHER_KEY)[0]);
    if (key_length > 128)
      print_m128i_with_string_short("",((__m128i*)CIPHER_KEY)[1],(key_length/8) -16);
    printf("The Key Schedule:\n");
    for (i=0; i< key.nr; i++)
        print_m128i_with_string("",((__m128i*)key.KEY)[i]);
printf("The PLAINTEXT:\n");
for (i=0; i< LENGTH/16; i++)
    print_m128i_with_string("",((__m128i*)PLAINTEXT)[i]);
if (LENGTH%16)
    print_m128i_with_string_short("",((__m128i*)PLAINTEXT)[i],LENGTH%16);
printf("\n\nThe CIPHERTEXT:\n");
for (i=0; i< LENGTH/16; i++)
    print_m128i_with_string("",((__m128i*)CIPHERTEXT)[i]);
if (LENGTH%16)
    print_m128i_with_string_short("",((__m128i*)CIPHERTEXT)[i],LENGTH%16);
for(i=0; i<LENGTH; i++){
    if (CIPHERTEXT[i] != EXPECTED_CIPHERTEXT[i%(16*4)]){
      printf("The CIPHERTEXT is not equal to the EXPECTED CIHERTEXT.\n\n");
      return 1;
      }
    }
printf("The CIPHERTEXT equals to the EXPECTED CIHERTEXT.\n\n");
for(i=0; i<LENGTH; i++){
    if (DECRYPTEDTEXT[i] != PLAINTEXT[i%(16*4)]){
        printf("The DECRYPTED TEXT isn't equal to the original PLAINTEXT!");
        printf("\n\n");
        return 1;
        }
    }
printf("The DECRYPTED TEXT equals to the original PLAINTEXT.\n\n");
}

