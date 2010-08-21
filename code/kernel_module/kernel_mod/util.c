#include <linux/time.h>
#include <linux/string.h>
#include <linux/random.h>

#include "util.h"
#include "aes_key_struct.h"

/* We need better random generation for the key */
void generate_rand128(void *buf)
{
  //int temp_rand;
  //int ret_val;
  //int i = 0;
  /*struct timeval current_time;

  ret_val = gettimeofday(&current_time, NULL);

  if(ret_val != 0) {
    printk(KERN_INFO "AES_MOD: Error in generate_rand128 .");
    //perror("\nError in gettimeofday() ");
    //exit(-1);
  }

  srand(getppid() + getpid() + current_time.tv_usec);
  
  temp_rand = rand();
  memcpy(buf, &temp_rand, 4);

  temp_rand = rand();
  memcpy((void *)((char *)buf + 4), &temp_rand, 4);

  temp_rand = rand();
  memcpy((void *)((char *)buf + 8), &temp_rand, 4);

  temp_rand = rand();
  memcpy((void *)((char *)buf + 12), &temp_rand, 4);
  */
  get_random_bytes(buf, X_SIZE);

}

void set_X(char *buffer)
{
  char original_db0_value[X_SIZE];
  SAVE_X(buffer, original_db0_value);
  memset(buffer, 0, X_SIZE);  
}

// get the X value from debug 0
// using the same SAVE_X function
void get_X(char *buffer)
{
  char tmp_buffer[X_SIZE];
  // set some garbled value into X
  SAVE_X(tmp_buffer, buffer);
  // setback the correct value
  SAVE_X(buffer, tmp_buffer);
}

/*
// the functions sets the X value to fromBuffer
// and gets the exiting X value into toBuffer
static void swap_X( char *fromBuffer, char *toBuffer ) {
  
  SAVE_X(fromBuffer, toBuffer);
}
*/
