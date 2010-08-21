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
.globl AES_hash_check

ZERO_LONG:
	.long 0
	.text

#use cvtsi2ss to convert i to xmm register and then add to x
AES_transform_key:
#parameter 1: %rdi
#parameter 2: %rsi
	movq 	$0, %r8
	movq	$X, %r10
	movdqu 	(%r10), %xmm15
	movq	%rdi, %r10
LOOP:
	pxor	%xmm0, %xmm0
	cvtsi2ss %r8, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + i)
	pxor 	(%r10), %xmm0	#now xmm0 has key[i] ^ H(X + i)
	movdqu	%xmm0, (%r10)	#save the value in xmm0 to same memory loc
	incq 	%r8		#increment round counter
	addq 	$16, %r10	#rdi now points to next round key
	cmpq 	%rsi, %r8	#compare counter to number of rounds
	jg 	EXIT
	jmp	LOOP

EXIT:	
	/* Clean up XMM0 and XMM15 as it contains the secret value
	 * X and the computations to transform the key schedule
	*/
	pxor	%xmm15, %xmm15
	pxor	%xmm0, %xmm0
	ret

AES_hash_check:
	cvtsi2ss %rdi, %xmm0
	call	AES_hash
	movq	$test_var, %r11
	movdqu	%xmm0, (%r11)
	CVTSS2SI %xmm0, %rax
	ret
	
#AES_hash(y)
#This function perform AES_encrypt(y) ^ (y)
#The AES encryption performed is using only a 128 bit key and
#produces a fixed output of 128 bits
#This uses global parameters for the hashing key schedule and IV
#This function modifies r11, xmm14 and xmm0
AES_hash:
#parameter 1: xmm0 contains y
	#movq	$cbc_hash_iv, %r11
	#movq	(%r11), %r11
	#movdqa	(%r11), %xmm14
	#pxor	%xmm0, %xmm14
	#movq	(%r11), %r11

	movdqu	%xmm0,	%xmm14
	movq	$hash_key, %r11
	pxor	(%r11), %xmm0
	#movdqu	(%r11), %xmm0
	#cvtsi2ss %rax, %xmm0
	
	aesenc	16(%r11), %xmm0
	aesenc	32(%r11), %xmm0
	aesenc	48(%r11), %xmm0
	aesenc	64(%r11), %xmm0
	aesenc	80(%r11), %xmm0
	aesenc	96(%r11), %xmm0
	aesenc	112(%r11), %xmm0
	aesenc	128(%r11), %xmm0
	aesenc	144(%r11), %xmm0
	aesenclast 160(%r11), %xmm0
	pxor	%xmm14, %xmm0
	##for now we are removing this operation - else all output
	##of this hash function would be (IV ^ KEY[0] ^ ... KEY[10])
	pxor	%xmm14, %xmm14
	#pxor	%xmm0, %xmm0
	#mov	$3, %r11
	#cvtsi2ss %r11, %xmm0
	ret
