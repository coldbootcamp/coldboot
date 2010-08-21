/**@file Xfunctions.S
 *
 *  This file contains functions which provides functionality
 *  to save any 128 bit value to debug registers, and then
 *  retrieve from there.
 *
 *  @author Shishir Kumar Yadav	(skyadav)
 *  @author Vanshidhar Konda (vkonda)
 *  @author Chetan Anand (canand)
 *  @author Krishna Santosh Suravar (ksuravar)	
 */

.globl SAVE_X

#This function can only be executed at privilege level 0
SAVE_X:
# parameter 1: %rdi /* the bufer address containing X */
# parameter 2: %rsi /* Memory region to save debug register values */
#save current values in the debug registers
	mov %db0, %rax
	mov %eax, (%rsi)
	mov %db1, %rax
	mov %eax, 4(%rsi)
	mov %db2, %rax
	mov %eax, 8(%rsi)
	mov %db3, %rax
	mov %eax, 12(%rsi)
	mov (%rdi), %eax
	mov %rax, %DB0
	mov 4(%rdi), %eax
	mov %rax, %DB1
	mov 8(%rdi), %eax
	mov %rax, %DB2
	mov 12(%rdi), %eax
	mov %rax, %DB3
	ret
	
	
