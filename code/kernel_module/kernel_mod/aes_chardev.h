/**@file aes_chardev.h
 *
 * This file contains the declaration of constants required for
 * the usage of the character device for AES encryption that is
 * protected from cold boot attacks.
 *
 */

#ifndef AES_CHARDEV_H_
#define AES_CHARDEV_H_

#include <linux/ioctl.h>

/* 
 * The major device number. We can't rely on dynamic 
 * registration any more, because ioctls need to know 
 * it. 
 */
#define MAJOR_NUM 100

/* 
 * Sets the key that the user passes into the kernel
 */
#define IOCTL_SET_ENCRYPT_KEY _IOR(MAJOR_NUM, 0, void *)

/* 
 * Sets the key that the user passes into the kernel
 */
#define IOCTL_SET_DECRYPT_KEY _IOR(MAJOR_NUM, 1, void *)

/* 
 * Encrypt data with the key that was provided earlier
 */
#define IOCTL_ENCRYPT_DATA _IOWR(MAJOR_NUM, 2, void *)

/* 
 * Decrypt data with the key that was provided earlier
 */
#define IOCTL_DECRYPT_DATA _IOWR(MAJOR_NUM, 3, void *)

/* 
 * The name of the device file 
 */
#define DEVICE_FILE_NAME "aes_chardev"

/*
 * The path to the device file
 */
#define DEVICE_PATH "/dev/aes_chardev"

#endif /* AES_CHARDEV_H_ */
