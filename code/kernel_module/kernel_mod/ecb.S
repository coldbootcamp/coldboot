//void AES_ECB_encrypt (const unsigned char *in,
//                      unsigned char *out,
//                      unsigned long length,
//                      const unsigned char *KS,
//                      int nr)
.globl AES_ECB_encrypt

ZERO_LONG:
	.long 00000000
	.text

AES_ECB_encrypt:
# parameter 1: %rdi	#input buffer
# parameter 2: %rsi	#output buffer
# parameter 3: %rdx	#length of buffer
# parameter 4: %rcx	#Key schedule pointer
# parameter 5: %r8d	#Number of keys
	movq	$X, %r10
	movdqu 	(%r10), %xmm15  # value of X from debug register

        movq    %rdx, %r10
        shrq    $4, %rdx
        shlq    $60, %r10
        je      NO_PARTS_4
        addq    $1, %rdx
NO_PARTS_4:
	movq	$0, %r9
        movq    %rdx, %r10
        shlq    $62, %r10
        shrq    $62, %r10
        shrq    $2, %rdx
        je      REMAINDER_4
        subq    $64, %rsi
LOOP_4:
	movq	$0, %r9
        movdqu  (%rdi), %xmm1
        movdqu  16(%rdi), %xmm2
        movdqu  32(%rdi), %xmm3
        movdqu  48(%rdi), %xmm4
        movdqa  (%rcx), %xmm9
        movdqa  16(%rcx), %xmm10
        movdqa  32(%rcx), %xmm11
	movdqa  48(%rcx), %xmm12

	#get the value of H(X)
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0	#move X into xmm0 to pass to AES_hash
	call	AES_hash	#after this xmm0 has H(X)
	pxor	%xmm0, %xmm9	#calculate R[0] ^ H(X)
	#get the value of H(X + 1)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0	#move X+1 into xmm0 to pass to AES_hash
	call 	AES_hash	#now xmm0 contains H(X + 1)
	pxor 	%xmm0, %xmm10	#calculate R[1] ^ H(X + 1) in %xmm10
	#get the value of H(X + 2)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0	#move X+2 into xmm0 to pass to AES_hash
	call 	AES_hash	#now xmm0 contains H(X + 2)
	pxor 	%xmm0, %xmm11	#calculate R[2] ^ H(X + 2) in %xmm11
	#get the value of H(X + 3)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0	#move X+3 into xmm0 to pass to AES_hash
	call 	AES_hash	#now xmm0 contains H(X + 3)
	pxor 	%xmm0, %xmm12	#calculate R[3] ^ H(X + 3) in %xmm12
        
        pxor    %xmm9, %xmm1
        pxor    %xmm9, %xmm2
        pxor    %xmm9, %xmm3
        pxor    %xmm9, %xmm4
	aesenc  %xmm10, %xmm1
        aesenc  %xmm10, %xmm2
        aesenc  %xmm10, %xmm3
        aesenc  %xmm10, %xmm4
        aesenc  %xmm11, %xmm1
        aesenc  %xmm11, %xmm2
        aesenc  %xmm11, %xmm3
        aesenc  %xmm11, %xmm4
        aesenc  %xmm12, %xmm1
        aesenc  %xmm12, %xmm2
        aesenc  %xmm12, %xmm3
        aesenc  %xmm12, %xmm4
	
        movdqa  64(%rcx), %xmm9
        movdqa  80(%rcx), %xmm10
        movdqa  96(%rcx), %xmm11
        movdqa  112(%rcx), %xmm12

	#get the value of H(X + 4)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0	#move X+4 into xmm0 to pass to AES_hash
	call 	AES_hash	#now xmm0 contains H(X + 4)
	pxor 	%xmm0, %xmm9	#calculate R[4] ^ H(X + 4)
	#get the value of H(X + 5)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 5)
	pxor 	%xmm0, %xmm10	#calculate R[5] ^ H(X + 5)
        #get the value of H(X + 6)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 6)
	pxor 	%xmm0, %xmm11	#calculate R[6] ^ H(X + 6)	
	#get the value of H(X + 7)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 7)
	pxor 	%xmm0, %xmm12	#calculate R[7] ^ H(X + 7)
	
	aesenc  %xmm9, %xmm1
        aesenc  %xmm9, %xmm2
        aesenc  %xmm9, %xmm3
        aesenc  %xmm9, %xmm4
	aesenc    %xmm10, %xmm1
        aesenc    %xmm10, %xmm2
        aesenc    %xmm10, %xmm3
        aesenc    %xmm10, %xmm4
        aesenc    %xmm11, %xmm1
        aesenc    %xmm11, %xmm2
        aesenc    %xmm11, %xmm3
        aesenc    %xmm11, %xmm4
	aesenc    %xmm12, %xmm1
        aesenc    %xmm12, %xmm2
        aesenc    %xmm12, %xmm3
        aesenc    %xmm12, %xmm4

        movdqa    128(%rcx), %xmm9
        movdqa    144(%rcx), %xmm10
        movdqa    160(%rcx), %xmm11

	#get the value of H(X + 8)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 8)
	pxor 	%xmm0, %xmm9	#calculate R[8] ^ H(X + 8)
	#get the value of H(X + 9)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 9)
	pxor 	%xmm0, %xmm10	#calculate R[9] ^ H(X + 9)
	#get the value of H(X + 10)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 10)
	pxor 	%xmm0, %xmm11	#calculate R[10] ^ H(X + 10)

	cmpl      $12, %r8d
	aesenc    %xmm9, %xmm1
        aesenc    %xmm9, %xmm2
        aesenc    %xmm9, %xmm3
        aesenc    %xmm9, %xmm4
        aesenc  %xmm10, %xmm1
        aesenc  %xmm10, %xmm2
        aesenc  %xmm10, %xmm3
        aesenc  %xmm10, %xmm4
	jb        LAST_4

        movdqa    160(%rcx), %xmm9
        movdqa    176(%rcx), %xmm10
        movdqa    192(%rcx), %xmm11

	#get the value of H(X + 10)
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 10)
	pxor 	%xmm0, %xmm9	#calculate R[10] ^ H(X + 10)
	#get the value of H(X + 11)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 11)
	pxor 	%xmm0, %xmm10	#calculate R[11] ^ H(X + 11)
	#get the value of H(X + 12)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 12)
	pxor 	%xmm0, %xmm11	#calculate R[12] ^ H(X + 12)
	
        aesenc  %xmm9, %xmm1
        aesenc  %xmm9, %xmm2
        aesenc  %xmm9, %xmm3
        aesenc  %xmm9, %xmm4
	aesenc    %xmm10, %xmm1
        aesenc    %xmm10, %xmm2
        aesenc    %xmm10, %xmm3
        aesenc    %xmm10, %xmm4

        cmpl      $14, %r8d
        jb        LAST_4
	
        movdqa    192(%rcx), %xmm9
        movdqa    208(%rcx), %xmm10
        movdqa    224(%rcx), %xmm11

	#get the value of H(X + 12)
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 12)
	pxor 	%xmm0, %xmm9	#calculate R[12] ^ H(X + 12)
	#get the value of H(X + 13)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 13)
	pxor 	%xmm0, %xmm10	#calculate R[13] ^ H(X + 13)
	#get the value of H(X + N)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + N)
	pxor 	%xmm0, %xmm11	#calculate R[N] ^ H(X + N)
	
	aesenc    %xmm9, %xmm1
        aesenc    %xmm9, %xmm2
        aesenc    %xmm9, %xmm3
        aesenc    %xmm9, %xmm4
	aesenc    %xmm10, %xmm1
        aesenc    %xmm10, %xmm2
        aesenc    %xmm10, %xmm3
        aesenc    %xmm10, %xmm4
LAST_4:
        addq      $64, %rdi
        addq      $64, %rsi
        decq      %rdx
	
        aesenclast %xmm11, %xmm1
        aesenclast %xmm11, %xmm2
        aesenclast %xmm11, %xmm3
        aesenclast %xmm11, %xmm4
        movdqu    %xmm1, (%rsi)
        movdqu    %xmm2, 16(%rsi)
        movdqu    %xmm3, 32(%rsi)
        movdqu    %xmm4, 48(%rsi)
        jne       LOOP_4
        addq      $64, %rsi
REMAINDER_4:
        cmpq      $0, %r10
        je        END_4
LOOP_4_2:
        movdqu    (%rdi), %xmm1
        addq      $16, %rdi

	#get the value of H(X)
	mov	$0, %r9 #0
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X)
	movdqa	(%rcx), %xmm11
	pxor 	%xmm0, %xmm11	#calculate R[0] ^ H(X)
        pxor      %xmm11, %xmm1
	
	#get the value of H(X + 1)
	incq	%r9 #1
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 1)
	movdqa	16(%rcx), %xmm11
	pxor 	%xmm0, %xmm11	#calculate R[1] ^ H(X + 1)
        aesenc    %xmm11, %xmm1

	#get the value of H(X + 2)
	incq	%r9 #2
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 2)
	movdqa	32(%rcx), %xmm11
	pxor 	%xmm0, %xmm11	#calculate R[2] ^ H(X + 2)
        aesenc    %xmm11, %xmm1


	#get the value of H(X + 3)
	incq	%r9 #3
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 3)
	movdqa	48(%rcx), %xmm11
	pxor 	%xmm0, %xmm11	#calculate R[3] ^ H(X + 3)
        aesenc    %xmm11, %xmm1

	#get the value of H(X + 4)
	incq	%r9 #4
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 4)
	movdqa	64(%rcx), %xmm11
	pxor 	%xmm0, %xmm11	#calculate R[4] ^ H(X + 4)
        aesenc    %xmm11, %xmm1

	#get the value of H(X + 5)
	incq	%r9 #5
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 5)
	movdqa	80(%rcx), %xmm11
	pxor 	%xmm0, %xmm11	#calculate R[5] ^ H(X + 5)
        aesenc    %xmm11, %xmm1

	#get the value of H(X + 6)
	incq	%r9 #6
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 6)
	movdqa	96(%rcx), %xmm11
	pxor 	%xmm0, %xmm11	#calculate R[6] ^ H(X + 6)
        aesenc    %xmm11, %xmm1

	#get the value of H(X + 7)
	incq	%r9 #7
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 7)
	movdqa	112(%rcx), %xmm11
	pxor 	%xmm0, %xmm11	#calculate R[7] ^ H(X + 7)
        aesenc    %xmm11, %xmm1

	#get the value of H(X + 8)
	incq	%r9 #8
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 8)
	movdqa	128(%rcx), %xmm11
	pxor 	%xmm0, %xmm11	#calculate R[8] ^ H(X + 8)
        aesenc    %xmm11, %xmm1

	#get the value of H(X + 9)
	incq	%r9 #9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 9)
	movdqa	144(%rcx), %xmm11
	pxor 	%xmm0, %xmm11	#calculate R[9] ^ H(X + 9)
        aesenc    %xmm11, %xmm1

	# move below instruction from top to here as it does not change anything and
	# the i value in %r9 is incremented to the value we need at this point
        movdqu    160(%rcx), %xmm2	
	#get the value of H(X + 10)
	incq	%r9 #10
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 10)
	pxor 	%xmm0, %xmm2	#calculate R[N] ^ H(X + 10)

        cmpl      $12, %r8d
        jb        LAST_4_2

	#get the value of H(X + 10)
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 10)
	movdqa	160(%rcx), %xmm11
	pxor 	%xmm0, %xmm11	#calculate R[10] ^ H(X + 10)
        aesenc    %xmm11, %xmm1

	#get the value of H(X + 11)
	incq	%r9 #11
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 11)
	movdqa	176(%rcx), %xmm11
	pxor 	%xmm0, %xmm11	#calculate R[11] ^ H(X + 11)
        aesenc  %xmm11, %xmm1

	# move below instruction from top to here as it does not change anything and
	# the i value in %r9 is incremented to the value we need at this point
	movdqu    192(%rcx), %xmm2
	#get the value of H(X + 12)
	incq	%r9 #12
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + N)
	pxor 	%xmm0, %xmm2	#calculate R[N] ^ H(X + N)
	
        cmpl    $14, %r8d
        jb      LAST_4_2

	#get the value of H(X + 12)
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 12)
	movdqa	192(%rcx), %xmm11
	pxor 	%xmm0, %xmm11	#calculate R[12] ^ H(X + 12)
        aesenc  %xmm11, %xmm1

	#get the value of H(X + 13)
	incq	%r9 #13
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 13)
	movdqa	208(%rcx), %xmm11
	pxor 	%xmm0, %xmm11	#calculate R[13] ^ H(X + 13)
        aesenc  %xmm11, %xmm1

	movdqu  224(%rcx), %xmm2
	#get the value of H(X + 14)
	incq	%r9 #14
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + N)
	pxor 	%xmm0, %xmm2	#calculate R[N] ^ H(X + N)

LAST_4_2:
        aesenclast %xmm2, %xmm1
        movdqu    %xmm1, (%rsi)
        addq      $16, %rsi
        decq      %r10
        jne       LOOP_4_2
END_4:
        ret


//void AES_ECB_decrypt (const unsigned char *in,
//                      unsigned char *out,
//                      unsigned long length,
//                      const unsigned char *KS,
//                      int nr)
.globl AES_ECB_decrypt
AES_ECB_decrypt:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %rdx
# parameter 4: %rcx
# parameter 5: %r8d
	movq	$X, %r10
	movdqu 	(%r10), %xmm15  # value of X from debug register
	
        movq      %rdx, %r10
        shrq   $4, %rdx
        shlq      $60, %r10
        je            DNO_PARTS_4
        addq      $1, %rdx
DNO_PARTS_4:
        movq      %rdx, %r10
        shlq      $62, %r10
        shrq      $62, %r10
        shrq      $2, %rdx
        je     DREMAINDER_4
        subq   $64, %rsi
DLOOP_4:
	movq	$0, %r9
        movdqu (%rdi), %xmm1
        movdqu 16(%rdi), %xmm2
        movdqu 32(%rdi), %xmm3
        movdqu 48(%rdi), %xmm4
        movdqa (%rcx), %xmm9
        movdqa 16(%rcx), %xmm10
        movdqa 32(%rcx), %xmm11
        movdqa 48(%rcx), %xmm12
	
	#get the value of H(X)
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0	#move X into xmm0 to pass to AES_hash
	call	AES_hash	#after this xmm0 has H(X)
	pxor	%xmm0, %xmm9	#calculate R[0] ^ H(X)
	#get the value of H(X + 1)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0	#move X+1 into xmm0 to pass to AES_hash
	call 	AES_hash	#now xmm0 contains H(X + 1)
	pxor 	%xmm0, %xmm10	#calculate R[1] ^ H(X + 1) in %xmm10
	#get the value of H(X + 2)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0	#move X+2 into xmm0 to pass to AES_hash
	call 	AES_hash	#now xmm0 contains H(X + 2)
	pxor 	%xmm0, %xmm11	#calculate R[2] ^ H(X + 2) in %xmm11
	#get the value of H(X + 3)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0	#move X+3 into xmm0 to pass to AES_hash
	call 	AES_hash	#now xmm0 contains H(X + 3)
	pxor 	%xmm0, %xmm12	#calculate R[3] ^ H(X + 3) in %xmm12      

	pxor   %xmm9, %xmm1
        pxor   %xmm9, %xmm2
        pxor   %xmm9, %xmm3
        pxor   %xmm9, %xmm4
        aesdec %xmm10, %xmm1
        aesdec %xmm10, %xmm2
        aesdec %xmm10, %xmm3
        aesdec %xmm10, %xmm4
        aesdec %xmm11, %xmm1
        aesdec %xmm11, %xmm2
        aesdec %xmm11, %xmm3
        aesdec %xmm11, %xmm4
        aesdec %xmm12, %xmm1
        aesdec %xmm12, %xmm2
        aesdec %xmm12, %xmm3
        aesdec %xmm12, %xmm4
        movdqa 64(%rcx), %xmm9
        movdqa 80(%rcx), %xmm10
        movdqa 96(%rcx), %xmm11
        movdqa 112(%rcx), %xmm12

	#get the value of H(X + 4)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0	#move X+4 into xmm0 to pass to AES_hash
	call 	AES_hash	#now xmm0 contains H(X + 4)
	pxor 	%xmm0, %xmm9	#calculate R[4] ^ H(X + 4)
	#get the value of H(X + 5)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 5)
	pxor 	%xmm0, %xmm10	#calculate R[5] ^ H(X + 5)
        #get the value of H(X + 6)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 6)
	pxor 	%xmm0, %xmm11	#calculate R[6] ^ H(X + 6)	
	#get the value of H(X + 7)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 7)
	pxor 	%xmm0, %xmm12	#calculate R[7] ^ H(X + 7)
	
        aesdec %xmm9, %xmm1
        aesdec %xmm9, %xmm2
        aesdec %xmm9, %xmm3
        aesdec %xmm9, %xmm4
        aesdec %xmm10, %xmm1
        aesdec %xmm10, %xmm2
        aesdec %xmm10, %xmm3
        aesdec %xmm10, %xmm4
        aesdec %xmm11, %xmm1
        aesdec %xmm11, %xmm2
        aesdec %xmm11, %xmm3
        aesdec %xmm11, %xmm4
        aesdec %xmm12, %xmm1
        aesdec %xmm12, %xmm2
        aesdec %xmm12, %xmm3
        aesdec %xmm12, %xmm4
        movdqa 128(%rcx), %xmm9
        movdqa 144(%rcx), %xmm10
        movdqa 160(%rcx), %xmm11

	#get the value of H(X + 8)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 8)
	pxor 	%xmm0, %xmm9	#calculate R[8] ^ H(X + 8)
	#get the value of H(X + 9)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 9)
	pxor 	%xmm0, %xmm10	#calculate R[9] ^ H(X + 9)
	#get the value of H(X + 10)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 10)
	pxor 	%xmm0, %xmm11	#calculate R[10] ^ H(X + 10)
	
        cmpl   $12, %r8d
        aesdec %xmm9, %xmm1
        aesdec %xmm9, %xmm2
        aesdec %xmm9, %xmm3
        aesdec %xmm9, %xmm4
        aesdec %xmm10, %xmm1
        aesdec %xmm10, %xmm2
        aesdec %xmm10, %xmm3
        aesdec %xmm10, %xmm4
        jb        DLAST_4
        movdqa    160(%rcx), %xmm9
        movdqa    176(%rcx), %xmm10
        movdqa    192(%rcx), %xmm11

	#get the value of H(X + 10)
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 10)
	pxor 	%xmm0, %xmm9	#calculate R[10] ^ H(X + 10)
	#get the value of H(X + 11)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 11)
	pxor 	%xmm0, %xmm10	#calculate R[11] ^ H(X + 11)
	#get the value of H(X + 12)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 12)
	pxor 	%xmm0, %xmm11	#calculate R[12] ^ H(X + 12)
	
        cmpl      $14, %r8d
        aesdec    %xmm9, %xmm1
        aesdec    %xmm9, %xmm2
        aesdec    %xmm9, %xmm3
        aesdec    %xmm9, %xmm4
        aesdec    %xmm10, %xmm1
        aesdec    %xmm10, %xmm2
        aesdec    %xmm10, %xmm3
        aesdec    %xmm10, %xmm4
        jb        DLAST_4
        movdqa    192(%rcx), %xmm9
        movdqa    208(%rcx), %xmm10
        movdqa    224(%rcx), %xmm11
	
	#get the value of H(X + 12)
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 12)
	pxor 	%xmm0, %xmm9	#calculate R[12] ^ H(X + 12)
	#get the value of H(X + 13)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + 13)
	pxor 	%xmm0, %xmm10	#calculate R[13] ^ H(X + 13)
	#get the value of H(X + N)
	incq	%r9
	pxor	%xmm0, %xmm0
	cvtsi2ss %r9, %xmm0
	addss	%xmm15, %xmm0
	call 	AES_hash	#now xmm0 contains H(X + N)
	pxor 	%xmm0, %xmm11	#calculate R[N] ^ H(X + N)
	
        aesdec    %xmm9, %xmm1
        aesdec    %xmm9, %xmm2
        aesdec    %xmm9, %xmm3
        aesdec    %xmm9, %xmm4
        aesdec    %xmm10, %xmm1
        aesdec    %xmm10, %xmm2
        aesdec    %xmm10, %xmm3
        aesdec    %xmm10, %xmm4
DLAST_4:
        addq      $64, %rdi
        addq      $64, %rsi
        decq      %rdx
        aesdeclast %xmm11, %xmm1
        aesdeclast %xmm11, %xmm2
        aesdeclast %xmm11, %xmm3
        aesdeclast %xmm11, %xmm4
        movdqu    %xmm1, (%rsi)
        movdqu    %xmm2, 16(%rsi)
        movdqu    %xmm3, 32(%rsi)
        movdqu    %xmm4, 48(%rsi)
        jne       DLOOP_4
        addq      $64, %rsi
DREMAINDER_4:
        cmpq      $0, %r10
        je        DEND_4
DLOOP_4_2:
        movdqu    (%rdi), %xmm1
        addq      $16, %rdi
        pxor      (%rcx), %xmm1
        movdqu    160(%rcx), %xmm2
        cmpl      $12, %r8d
        aesdec    16(%rcx), %xmm1
        aesdec    32(%rcx), %xmm1
        aesdec    48(%rcx), %xmm1
        aesdec    64(%rcx), %xmm1
        aesdec    80(%rcx), %xmm1
        aesdec    96(%rcx), %xmm1
        aesdec    112(%rcx), %xmm1
        aesdec    128(%rcx), %xmm1
        aesdec    144(%rcx), %xmm1
        jb        DLAST_4_2
        cmpl      $14, %r8d
        movdqu    192(%rcx), %xmm2
        aesdec    160(%rcx), %xmm1
        aesdec    176(%rcx), %xmm1
        jb        DLAST_4_2
        movdqu    224(%rcx), %xmm2
        aesdec    192(%rcx), %xmm1
        aesdec    208(%rcx), %xmm1
DLAST_4_2:
        aesdeclast %xmm2, %xmm1
        movdqu    %xmm1, (%rsi)
        addq      $16, %rsi
        decq      %r10
        jne       DLOOP_4_2
DEND_4:
        ret

