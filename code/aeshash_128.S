/* This function is called only from inside the aes encryption/decryption
 * function. It generates a hash of the secret value + round index at puts
 * it in xmm3.
 */
//aeshash_128 (int round_idx)
.globl aeshash_128

aeshash_128:
#parameter 1: %rdi
#parameter 2: $%rsi
