//AES_CBC_encrypt (const unsigned char *in,
//                 unsigned char *out,
//                 unsigned char ivec[16],
//                 unsigned long length,
//                 const unsigned char *KS,
//                 int nr)
.globl AES_CBC_encrypt
AES_CBC_encrypt:
# parameter 1: %rdi
# parameter 2: %rsi
# parameter 3: %rdx
# parameter 4: %rcx
# parameter 5: %r8
# parameter 6: %r9d

	movq    %rcx, %r10
	shrq    $4, %rcx
	shlq    $60, %r10
	je      NO_PARTS
	addq    $1, %rcx
	movq	$0, %r10	//initialize a counter i
	movdqu (X), %xmm7	//get the value of X from debug registers
				//memory for now
	
NO_PARTS:
	subq	$16, %rsi	//dec "out" by 16 - due to initial loop
	movdqa  (%rdx), %xmm1	//move IV into xmm1
LOOP:
	pxor    (%rdi), %xmm1 	//xor IV with block
	cvtsis2ss %r10, %xmm0	
	addss	%xmm7, %xmm0	//xmm0 contains (x+i)
	call	AES_hash	//now xmm0 has H(x+i)
	pxor	(%r8), %xmm0	//xor key from memory with H(x+i)
	pxor    %xmm0, %xmm1	//xor with block

	addq    $16,%rsi	//inc "out" by 16 - due to loop
	addq    $16,%rdi	//shift "in" by 16 bytes
	cmpl    $12, %r9d	//check how many rounds

	incq	%r10
	cvtsis2ss %r10, %xmm0	
	addss	%xmm7, %xmm0	//xmm0 contains (x+i)
	call	AES_hash	//now xmm0 has H(x+i)
	pxor	16(%r8), %xmm0	//xor key from memory with H(x+i)
	pxor    %xmm0, %xmm1	//should have been aesenc

	incq	%r10
	cvtsis2ss %r10, %xmm0	
	addss	%xmm7, %xmm0	//xmm0 contains (x+i)
	call	AES_hash	//now xmm0 has H(x+i)
	pxor	32(%r8), %xmm0	//xor key from memory with H(x+i)
	pxor    %xmm0, %xmm1	//should have been aesenc

	incq	%r10
	cvtsis2ss %r10, %xmm0	
	addss	%xmm7, %xmm0	//xmm0 contains (x+i)
	call	AES_hash	//now xmm0 has H(x+i)
	pxor	48(%r8), %xmm0	//xor key from memory with H(x+i)
	pxor    %xmm0, %xmm1	//should have been aesenc

	incq	%r10
	cvtsis2ss %r10, %xmm0	
	addss	%xmm7, %xmm0	//xmm0 contains (x+i)
	call	AES_hash	//now xmm0 has H(x+i)
	pxor	64(%r8), %xmm0	//xor key from memory with H(x+i)
	pxor    %xmm0, %xmm1	//should have been aesenc

	incq	%r10
	cvtsis2ss %r10, %xmm0	
	addss	%xmm7, %xmm0	//xmm0 contains (x+i)
	call	AES_hash	//now xmm0 has H(x+i)
	pxor	80(%r8), %xmm0	//xor key from memory with H(x+i)
	pxor    %xmm0, %xmm1	//should have been aesenc

	incq	%r10
	cvtsis2ss %r10, %xmm0	
	addss	%xmm7, %xmm0	//xmm0 contains (x+i)
	call	AES_hash	//now xmm0 has H(x+i)
	pxor	96(%r8), %xmm0	//xor key from memory with H(x+i)
	pxor    %xmm0, %xmm1	//should have been aesenc

		incq	%r10
	cvtsis2ss %r10, %xmm0	
	addss	%xmm7, %xmm0	//xmm0 contains (x+i)
	call	AES_hash	//now xmm0 has H(x+i)
	pxor	112(%r8), %xmm0	//xor key from memory with H(x+i)
	pxor    %xmm0, %xmm1	//should have been aesenc

	incq	%r10
	cvtsis2ss %r10, %xmm0	
	addss	%xmm7, %xmm0	//xmm0 contains (x+i)
	call	AES_hash	//now xmm0 has H(x+i)
	pxor	128(%r8), %xmm0	//xor key from memory with H(x+i)
	pxor    %xmm0, %xmm1	//should have been aesenc

	incq	%r10
	cvtsis2ss %r10, %xmm0	
	addss	%xmm7, %xmm0	//xmm0 contains (x+i)
	call	AES_hash	//now xmm0 has H(x+i)
	pxor	144(%r8), %xmm0	//xor key from memory with H(x+i)
	pxor    %xmm0, %xmm1	//should have been aesenc

	movdqa    160(%r8),%xmm2	//move 10th round key to xmm2
	jb        LAST		//if r9d < 12 jump to last round
	cmpl      $14, %r9d	//compare r9d (num rounds) with 14

	incq	%r10
	cvtsis2ss %r10, %xmm0	
	addss	%xmm7, %xmm0	//xmm0 contains (x+i)
	call	AES_hash	//now xmm0 has H(x+i)
	pxor	160(%r8), %xmm0	//xor key from memory with H(x+i)
	pxor    %xmm0, %xmm1	//should have been aesenc

	incq	%r10
	cvtsis2ss %r10, %xmm0	
	addss	%xmm7, %xmm0	//xmm0 contains (x+i)
	call	AES_hash	//now xmm0 has H(x+i)
	pxor	176(%r8), %xmm0	//xor key from memory with H(x+i)
	pxor    %xmm0, %xmm1	//should have been aesenc

	movdqa    192(%r8),%xmm2
	jb        LAST		//if r9d < 14 jump to last round

	incq	%r10
	cvtsis2ss %r10, %xmm0	
	addss	%xmm7, %xmm0	//xmm0 contains (x+i)
	call	AES_hash	//now xmm0 has H(x+i)
	pxor	192(%r8), %xmm0	//xor key from memory with H(x+i)
	pxor    %xmm0, %xmm1	//should have been aesenc

	incq	%r10
	cvtsis2ss %r10, %xmm0	
	addss	%xmm7, %xmm0	//xmm0 contains (x+i)
	call	AES_hash	//now xmm0 has H(x+i)
	pxor	208(%r8), %xmm0	//xor key from memory with H(x+i)
	pxor    %xmm0, %xmm1	//should have been aesenc

	movdqa    224(%r8),%xmm2
LAST:
	decq       %rcx		//dec num of bytes to encrypt by 16

	incq	%r10
	cvtsis2ss %r10, %xmm0	
	addss	%xmm7, %xmm0	//xmm0 contains (x+i)
	call	AES_hash	//now xmm0 has H(x+i)
	pxor %xmm0, %xmm2
	pxor %xmm2,%xmm1	//should have been aesenclast
	movdqu     %xmm1,(%rsi)	//store encrypted data into memory
	jne        LOOP		//loop if not done
	ret
