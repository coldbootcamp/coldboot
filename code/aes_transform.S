/* This file contains the implementation of AES_transform_key and
 * AES_hash functions.
 */

#AES_transform_key(unsigned char *key_sched, int key_nr)
#Steps in key transformation:
#1. Get the value of x.
#2. Initialize counter i
#3. Calculate the value of H(x + i)
#4. key_sched[i] ^ H(x + i)
#5. Overwrite key_sched[i] with value from 4

.globl AES_transform_key
.globl AES_hash


.globl X
.text
.globl AES128_HASH_KEY
.text
.globl CBC_HASH_IV
.text

#use cvtsis2ss to convert i to xmm register and then add to x
AES_transform_key:
#parameter 1: %rdi
#parameter 2: %rsi
	movq 	$0, %r8
	movdqu (X), %xmm7
	movdq	%rdi, %r10
	movdq	%rsi, %r11
LOOP:
	cvtsis2ss %r8, %xmm0
	addss	%xmm7, %xmm0
	call 	AES_hash	#now xmm0 contains hash(x+i)
	pxor 	(%r10), %xmm0	#now xmm0 has key[i] ^ hash(x+i)
	movdq	%xmm0, (%r10)	#save the value in xmm0 to same memory loc
	incq 	%r8		#increment round counter
	addq 	$16, %r10	#rdi now points to next round key
	cmpq 	%r8, %r11	#compare counter to number of rounds
	jl 	LOOP
	ret

#AES_hash(y)
#This function perform AES_encrypt(y) ^ (y)
#The AES encryption performed is using only a 128 bit key and
#produces a fixed output of 128 bits
#This uses global parameters for the hashing key schedule and IV
#This function modifies xmm3 and xmm0
AES_hash:
#parameter 1: xmm0 contains y
	movdqa	(CBC_HASH_IV), xmm3
	pxor	xmm0, xmm3
	pxor	(AES128_HASH_KEY), xmm3
	pxor	16(AES128_HASH_KEY), xmm3	#should have been aesenc
	pxor	32(AES128_HASH_KEY), xmm3
	pxor	48(AES128_HASH_KEY), xmm3
	pxor	64(AES128_HASH_KEY), xmm3
	pxor	80(AES128_HASH_KEY), xmm3
	pxor	96(AES128_HASH_KEY), xmm3
	pxor	112(AES128_HASH_KEY), xmm3
	pxor	128(AES128_HASH_KEY), xmm3
	pxor	144(AES128_HASH_KEY), xmm3
	pxor	160(AES128_HASH_KEY), xmm3	#should have been aesenclast
	#pxor	xmm3, xmm0
	#for now we are removing this operation - else all output
	#of this hash function would be (IV ^ KEY[0] ^ ... KEY[10])
	ret
