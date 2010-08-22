/*  
 *  aes_mod.c - A simple kernel module for aes encryption with
 *  cold boot protection.
 */
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/fs.h>
//#include <assert.h>
#include <asm/uaccess.h>	/* for get_user and put_user */
#include <wmmintrin.h>

#include "aes_key_struct.h"
#include "aes_chardev.h"
//#include "aes_core.h"
#include "util.h"

#define DEBUG 1

#define SUCCESS 0
#define DEVICE_NAME "aes_chardev"
#define BYTE 8

// constants 
ALIGN16 uint8_t X[] = {0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
		       0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11
};
char test_var[16];
ALIGN16 uint8_t AES128_HASH_KEY[] = {0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,
                                      0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d
};
ALIGN16 uint8_t CBC_HASH_IV[] = {0x71,0x16,0xe6,0x9e,0x22,0x22,0x95,0x16,
                                 0x3f,0xf1,0xca,0xa1,0x68,0x1f,0xac,0x09
};
cbc_key_t hash_key_sched;
cbc_key_t trans_key_sched;

key_schedule_t hash_key;  // need to be modified

static int Device_Open = 0;

/* For the time being we are putting X as global variable
 * just to test our integartion. Later value from debug 
 * register should be used.
 */
//ALIGN16 unsigned char X[16]; 

// prototypes
static void set_encrypt_key(ioctl_set_key_t *ioctl_key);
static void set_decrypt_key(ioctl_set_key_t *ioctl_key);
void print_m128i_with_string(char* string,__m128i data);
void print_m128i_with_string_short(char* string,__m128i data,int length);
void print_X(char *buf, char *comment);

//-----------------------------------------------------------------

/* 
 * This is called whenever a process attempts to open the device file 
 */
static int device_open(struct inode *inode, struct file *file)
{
#ifdef DEBUG
  printk(KERN_INFO "device_open(%p)\n", file);
#endif

  /* 
   * We don't want to talk to two processes at the same time 
   */
  if (Device_Open)
    return -EBUSY;

  Device_Open++;
  /*
   * Initialize the message
   */
  try_module_get(THIS_MODULE);
  return SUCCESS;
}

static int device_release(struct inode *inode, struct file *file)
{
#ifdef DEBUG
  printk(KERN_INFO "device_release(%p,%p)\n", inode, file);
#endif

  /* 
   * We're now ready for our next caller 
   */
  Device_Open--;

  module_put(THIS_MODULE);
  return SUCCESS;
}

int init_aes_module(void)
{
  char buffer[X_SIZE];  // X_SIZE = 16 bytes = 128 bits
  unsigned char hash_key_128[X_SIZE];

  /* Generate a random "x" that acts as the session key --
   * for now it has been statically generated.
   */
  /* X = {} */

  /* Generate Random X - It need  */
  generate_rand128(buffer);
  printk(KERN_INFO "AES_MOD: random x is %s.\n", buffer);

  /* For now we are moving the buffer to the global variable
     X, Later save it and use it from debug register (set_X)
   */

  memcpy(X, buffer, X_SIZE);

  /* Put X in the debug registers */

  /* Generate a random 128 bit key for the hash function --
   * for now this key has also been statically chosen.
   */

    /* Generate a hash key */
  generate_rand128(hash_key_128);
  AES_set_encrypt_key(hash_key_128, 128, &hash_key);


  /* Generate the key schedule for the hash key. The hash key
   * schedule is a global variable.
   */
  return 0;
}

/* This function encrypts the buffer with the identifier passed by the
 * application
 */
int encrypt_buffer(int key_identifier, void *buffer)
{
#ifdef DEBUG
  printk(KERN_INFO "AES_MOD: encrypt_buffer called.");
#endif

  return 0;
}

int device_ioctl(struct inode *inode,	/* see include/linux/fs.h */
		 struct file *file,	/* ditto */
		 unsigned int ioctl_num,	/* number and param for ioctl */
		 unsigned long ioctl_param)
{
  unsigned long ret_val;
  //AES_BITKEY user_key;
  char buffer[MAX_KEY_SIZE];
  char *kernel_msg = "This is a message from the kernel.";
  /* 
   * Switch according to the ioctl called 
   */

  memset(buffer, 0, MAX_KEY_SIZE);

  switch (ioctl_num) {
    
  case IOCTL_SET_ENCRYPT_KEY:

    /* This is the case when an application requests to get the transformed
     * key schedule from an encryption key 
     * 
     * e.g. encryption_key(128 bit) -> transformed key schedule (240 Bytes)    
     */
    printk(KERN_INFO "AES_MOD: Inside set encrypt key \n");
    set_encrypt_key((ioctl_set_key_t *)ioctl_param);    
    break;

  case IOCTL_SET_DECRYPT_KEY:

    /* This is the case when an application requests to get the transformed
     * key schedule from an encryption key 
     * 
     * e.g. encryption_key(128 bit) -> transformed key schedule (240 Bytes)    
     */
    //printk(KERN_INFO "AES_MOD: Read from user: %s\n", buffer);
    printk(KERN_INFO "AES_MOD: Inside set decrypt key \n");
    set_decrypt_key((ioctl_set_key_t *)ioctl_param);    
    break;


  case IOCTL_ENCRYPT_DATA:
    
    ret_val = copy_to_user((void *)(ioctl_param), (void *)(kernel_msg),
			   35);
    if (ret_val < 0) {
      printk(KERN_INFO "AES_MOD: Error in writing to user space.\n");
    }
    encrypt_buffer(0, NULL);
    break;

  case IOCTL_DECRYPT_DATA:
    break;

  default:
    return -ENOTTY;
  }

  return SUCCESS;
}

/* Helper function which expands the encrypt key,
// transforms the key and set the tranformed key
// in the user buffer, which will be returned to
   the user.
*/
static void set_encrypt_key(ioctl_set_key_t *ioctl_key) {

  //ioctl_set_key_t kern_key;
  key_schedule_t local_key_sched_buf;
  // we are using max key size to takein any key
  // we are not using dynamic size to avoid using malloc.
  char user_key[16];

  int ret_val = copy_from_user((void *)(ioctl_key->user_key), (void *)(user_key), 16);
  //sizeof(ioctl_set_key_t));
  if(ret_val != -1)
    printk(KERN_ALERT "ret_val = %d ioctl_key = 0x%p\n", ret_val,
	   ioctl_key);
  /*ret_val = copy_from_user((void *)(kern_key.user_key), (void *)user_key,
			   (kern_key.user_key_size) / BYTE);
  
  if(ret_val != -1)
    printk(KERN_ALERT "ret_val == -1\n");
  */

  /* Generate the key schedule for the key provided by the application   
     expand the aes key */
  AES_set_encrypt_key(user_key, ioctl_key->user_key_size, &local_key_sched_buf);

  /* Transform the key schedule */ 
  AES_transform_key(local_key_sched_buf.key, local_key_sched_buf.nr);

  //copy to user space
  copy_to_user((void *)(&(ioctl_key->key_schedule)), (void *)(&local_key_sched_buf),
	       sizeof(key_schedule_t));
}


/* Helper function which expands the decrypt key,
// transforms the key and set the tranformed key
// in the user buffer, which will be returned to
   the user.
*/
static void set_decrypt_key(ioctl_set_key_t *ioctl_key) {

  /* Generate the key schedule for the key provided by the application   
     expand the aes key */
  AES_set_decrypt_key(ioctl_key->user_key, ioctl_key->user_key_size, &(ioctl_key->key_schedule));

  /* Transform the key schedule */ 
  AES_transform_key((ioctl_key->key_schedule).key, (ioctl_key->key_schedule).nr);
}

/* Module Declarations */

/* 
 * This structure will hold the functions to be called
 * when a process does something to the device we
 * created. Since a pointer to this structure is kept in
 * the devices table, it can't be local to
 * init_module. NULL is for unimplemented functions. 
 */
struct file_operations Fops = {
	.ioctl = device_ioctl,
	.open = device_open,
	.release = device_release,	/* a.k.a. close */
};

int init_module(void)
{
  int ret_val;
  
  /* 
   * Register the character device (atleast try) 
   */
  ret_val = register_chrdev(MAJOR_NUM, DEVICE_NAME, &Fops);

  /* 
   * Negative values signify an error 
   */
  if (ret_val < 0) {
    printk(KERN_ALERT "%s failed with %d\n",
	   "Sorry, registering the character device ", ret_val);
    return ret_val;
  }
  
  printk(KERN_INFO "AES_MOD: Start of the kernel module.\n");

  
  /* 
   * A non 0 return means init_module failed; module can't be loaded. 
   */
  return 0;
}

void cleanup_module(void)
{
  printk(KERN_INFO "AES_MOD: Exit from aes module.\n");

  /* 
   * Unregister the device 
   */
  unregister_chrdev(MAJOR_NUM, DEVICE_NAME);
}

/* ================== Util functions =========== */

void print_m128i_with_string(char* string,__m128i data)
{
  unsigned char *pointer = (unsigned char*)&data;
  int i;
  printk(KERN_INFO "%-40s[0x",string);
  for (i=0; i<16; i++)
    printk(KERN_INFO "%02x",pointer[i]);
  //printk("]\n");
}


void print_m128i_with_string_short(char* string,__m128i data,int length)
{
  unsigned char *pointer = (unsigned char*)&data;
  int i;
  printk(KERN_INFO "%-40s[0x",string);
  for (i=0; i<length; i++)
    printk(KERN_INFO "%02x",pointer[i]);
  //printk("]\n");
}


void print_X(char *buf, char *comment) {
  int i;
  printk(KERN_INFO "\n%s=", comment);
  for(i = 0; i<16; i++) {
    /*if(i%4 == 0)
	printk("\n");
    */ 
      printk(KERN_INFO "0x%02X ", *(char *)((char *)buf + i));
  }
  //printk("\n");
}


/*void assert( int val ) {
  
  if val

  }*/

/* ========================== Obsolete Code ========== */

/* This function generates the encryption key schedule for the
 * application and stores it in the kernel modules map.
 * 
 * Note - This function is replaced by set_encrypt_key
 *  it should not be used. 
 */
int generate_key_schedule(unsigned char *KEY)
{
#ifdef DEBUG
  printk(KERN_INFO "AES_MOD: generate_key_schedule called.");
#endif

  /* Generate the key schedule for the key provided by the application */

  /* Transform the key schedule */

  /* Map the key in the map for key schedules -- currently only one key
  * is used.*/

  /* Return the "identifier" for this encryption key -- currently the
   * identifier is always 0
5456   */
  return 0;
}


    /* ret_val = copy_from_user((void *)(&user_key), (void *)(ioctl_param), */
    /* 			     sizeof(AES_BITKEY)); */
    /*ret_val = copy_from_user((void *)(buffer), (void *)(ioctl_param),
			     80);
    if (ret_val < 0) {
      printk(KERN_INFO "AES_MOD: Error in reading from user space.\n");
      return -EINVAL;
      }*/


