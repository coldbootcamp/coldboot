#Makefile for the aes_mod kernel module

#EXTRA_CFLAGS += -enable-sse2 -maes -msse4.2 -g -mno-sse -mno-sse2 -mno-mmx
EXTRA_CFLAGS += -maes -msse2 -mmmx # -g -mno-mmx -mno-sse2
#obj-m += aes_mod.o
#obj-m += util.o
obj-m += aesni.o
aesni-objs := util.o Xfunctions.o aes_transform.o ecb.o key_expansion.o aes.o aes_mod.o
#ecb-objs := ecb.s

#all: first rest

#first: Xfunctions.o aes_transform.o key_expansion.o aes.o ecb.o

#Xfunctions.o: Xfunctions.S
#	gcc -c -o Xfunctions.o -msse2 -maes -g -mno-sse -mno-mmx -mno-sse2 Xfunctions.S

#aes_transfrom.o: aes_transform.S
#	gcc -c -o aes_transform.o -msse2 -maes -g -mno-sse -mno-mmx -mno-sse2 aes_transform.S

#key_expansion.o: key_expansion.S
#	gcc -c -o key_expansion.o -msse2 -maes -g -mno-sse -mno-mmx -mno-sse2 key_expansion.S

#aes.o: aes.c
#	gcc -c -o aes.o -msse2 -maes -g -mno-sse -mno-mmx -mno-sse2 aes.c

#ecb.o: ecb.c
#	gcc -c -o ecb.o -msse2 -maes -g -mno-sse -mno-mmx -mno-sse2 ecb.c

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean