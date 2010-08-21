#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>		/* open */
#include <unistd.h>		/* exit */
#include <sys/ioctl.h>		/* ioctl */
#include <errno.h>
#include <string.h>
#include "aes_chardev.h"

void ioctl_set_key(int file_desc)
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
  strcpy(message, "Hello from user world.");
  ret_val = ioctl(file_desc, IOCTL_SET_KEY, message);

  if (ret_val < 0) {
    printf("ioctl_get_msg failed:%d\n", ret_val);
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

  printf("Msg from kernel: %s\n", message);
}

int main(void)
{
  int file_desc, ret_val;
  char *msg = "Message passed by ioctl\n";

  file_desc = open("/dev/aes_chardev", 0);
  if (file_desc < 0) {
    printf("Can't open device file: %s. Errno: %d\n", DEVICE_FILE_NAME,
	   errno);
    exit(-1);
  }

  ioctl_set_key(file_desc);
  ioctl_encrypt_data(file_desc);

  close(file_desc);
  return 0;
}
