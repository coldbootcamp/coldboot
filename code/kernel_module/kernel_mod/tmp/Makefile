#Makefile for the aes_mod kernel module

#EXTRA_CFLAGS += -enable-sse2 -maes -msse4.2 -g -mno-sse -mno-sse2 -mno-mmx
EXTRA_CFLAGS += -msse2 -maes -g -mno-sse -mno-mmx -mno-sse2
#obj-m += aes_mod.o
#obj-m += util.o
obj-m += aesni.o
aesni-objs := util.o Xfunctions.o aes_transform.o ecb.o key_expansion.o aes.o aes_mod.o
#ecb-objs := ecb.s

all: first rest

first: Xfunctions aes_transform

rest:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean