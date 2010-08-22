/*
 *  ioctl.c - the process to use ioctl's to control the kernel module
 *
 *  Until now we could have used cat for input and output.  But now
 *  we need to do ioctl's, which require writing our own process.
 */

/* 
 * device specifics, such as ioctl numbers and the
 * major device file. 
 */
#include "aes_chardev.h"
#include "aes_key_struct.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>		/* open */
#include <unistd.h>		/* exit */
#include <sys/ioctl.h>		/* ioctl */
//#include <wmmintrin.h>

// global variables
char AES128_TEST_KEY[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
			     0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};

// prototypes
void print_m128i_with_string(char* string, char *data);

/* 
 * Functions for the ioctl calls 
 */

void ioctl_set_key(int file_desc, ioctl_set_key_t *ioctl_key)
{
  int ret_val;
  ret_val = ioctl(file_desc, IOCTL_SET_ENCRYPT_KEY, ioctl_key);
  
  if (ret_val < 0) {
    printf("ioctl_set_msg failed:%d\n", ret_val);
    exit(-1);
  }
}

void ioctl_encrypt_data(int file_desc)
{
	int ret_val;
	char message[100];

	/* 
	 * Warning - this is dangerous because we don't tell
	 * the kernel how far it's allowed to write, so it
	 * might overflow the buffer. In a real production
	 * program, we would have used two ioctls - one to tell
	 * the kernel the buffer length and another to give
	 * it the buffer to fill
	 */
	ret_val = ioctl(file_desc, IOCTL_ENCRYPT_DATA, message);

	if (ret_val < 0) {
		printf("ioctl_get_msg failed:%d\n", ret_val);
		exit(-1);
	}

	printf("get_msg message:%s\n", message);
}

void ioctl_decrypt_data(int file_desc)
{
  	int ret_val;
	char message[100];

	/* 
	 * Warning - this is dangerous because we don't tell
	 * the kernel how far it's allowed to write, so it
	 * might overflow the buffer. In a real production
	 * program, we would have used two ioctls - one to tell
	 * the kernel the buffer length and another to give
	 * it the buffer to fill
	 */
	ret_val = ioctl(file_desc, IOCTL_DECRYPT_DATA, message);

	if (ret_val < 0) {
		printf("ioctl_get_msg failed:%d\n", ret_val);
		exit(-1);
	}

	printf("get_msg message:%s\n", message);
}


/* 
 * Main - Call the ioctl functions 
 */
int main()
{
	int file_desc, ret_val;
	char *key = "Message passed by ioctl\n";
	ioctl_set_key_t ioctl_arg;

	file_desc = open(DEVICE_PATH, 0);
	if (file_desc < 0) {
		printf("Can't open device file: %s\n", DEVICE_PATH);
		exit(-1);
	}

	ioctl_arg.user_key = (char *)AES128_TEST_KEY;
	ioctl_arg.user_key_size = 128;
	ioctl_set_key(file_desc, &ioctl_arg);
	
	printf("Transformed key is - ");
	//for (int i=0; i< (ioctl_arg.key_schedule).nr; i++)
	// print_m128i_with_string("", &((ioctl_arg.key_schedule).key[i]));

	ioctl_encrypt_data(file_desc);
	ioctl_decrypt_data(file_desc);

	close(file_desc);
}


void print_m240i_with_string(char* string, char *pointer)
{
  //unsigned char *pointer = (unsigned char*)&data;
  int i;
  printf("%-40s[0x",string);
  for (i=0; i<15; i++) {
      for (int j=0; j<16; j++)
	printf("%02x",pointer[i]);
      printf("\n");
  }
  printf("]\n");
}
